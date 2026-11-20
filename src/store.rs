// glues the wal, the memtable and the tables together. every write funnels through one
// mutex so the sequence numbers come out in a single agreed order.
//
// the ordering here is the whole durability story. a write is only visible after the wal
// has it on disk, so a reader can never see something a power cut would take away. on flush
// the sstable is fsynced before the wal is truncated, which means a crash in between just
// replays records that already made it into the table. same seq, same bytes, no harm.

use parking_lot::{Mutex, RwLock};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::config::Config;
use crate::lsm::SsTable;
use crate::mem::{Kind, MemTable};
use crate::wal::{Record, Wal};
use crate::Result;

struct WriteSide {
    wal: Wal,
    next_table_id: u64,
}

pub struct Store {
    dir: PathBuf,
    memtable_bytes: usize,
    write: Mutex<WriteSide>,
    mem: RwLock<Arc<MemTable>>,
    tables: RwLock<Vec<Arc<SsTable>>>,
    seq: AtomicU64,
}

impl Store {
    pub fn open(config: &Config) -> Result<Store> {
        fs::create_dir_all(&config.data_dir)?;

        let mut discovered: Vec<(u64, PathBuf)> = Vec::new();
        for entry in fs::read_dir(&config.data_dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("sst") {
                continue;
            }
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
            if let Ok(id) = stem.parse::<u64>() {
                discovered.push((id, path));
            }
        }
        discovered.sort_by_key(|(id, _)| *id);

        let mut tables = Vec::with_capacity(discovered.len());
        let mut next_table_id = 0u64;
        let mut max_seq = 0u64;

        for (id, path) in discovered {
            let table = SsTable::open(&path)?;
            max_seq = max_seq.max(table.max_seq());
            next_table_id = next_table_id.max(id + 1);
            tables.push(Arc::new(table));
        }

        let (wal, records) = Wal::open(&config.data_dir, config.fsync_on_write)?;

        let mem = MemTable::new();
        for record in records {
            max_seq = max_seq.max(record.seq);
            mem.insert(record.key, record.seq, record.kind, record.value);
        }

        Ok(Store {
            dir: config.data_dir.clone(),
            memtable_bytes: config.memtable_bytes,
            write: Mutex::new(WriteSide { wal, next_table_id }),
            mem: RwLock::new(Arc::new(mem)),
            tables: RwLock::new(tables),
            seq: AtomicU64::new(max_seq),
        })
    }

    pub fn set(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.append(Kind::Set, key, value)
    }

    pub fn delete(&self, key: &[u8]) -> Result<()> {
        self.append(Kind::Del, key, &[])
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let snapshot = self.seq.load(Ordering::SeqCst);

        let mem = Arc::clone(&self.mem.read());
        if let Some(found) = mem.get(key, snapshot) {
            return Ok(visible(found.kind, found.bytes));
        }

        let tables = self.tables.read().clone();
        for table in tables.iter().rev() {
            if let Some(found) = table.get(key, snapshot)? {
                return Ok(visible(found.kind, found.bytes));
            }
        }

        Ok(None)
    }

    pub fn flush(&self) -> Result<()> {
        let mut write = self.write.lock();
        self.flush_locked(&mut write)
    }

    pub fn sequence(&self) -> u64 {
        self.seq.load(Ordering::SeqCst)
    }

    pub fn table_count(&self) -> usize {
        self.tables.read().len()
    }

    fn append(&self, kind: Kind, key: &[u8], value: &[u8]) -> Result<()> {
        let mut write = self.write.lock();

        let seq = self
            .seq
            .load(Ordering::SeqCst)
            .checked_add(1)
            .ok_or_else(|| crate::Error::Config("sequence number space exhausted".into()))?;

        let record = Record {
            seq,
            kind,
            key: key.to_vec(),
            value: value.to_vec(),
        };
        write.wal.append(&record)?;
        self.seq.store(seq, Ordering::SeqCst);

        let full = {
            let mem = Arc::clone(&self.mem.read());
            mem.insert(record.key, seq, kind, record.value);
            mem.approx_bytes() >= self.memtable_bytes
        };

        if full {
            self.flush_locked(&mut write)?;
        }
        Ok(())
    }

    fn flush_locked(&self, write: &mut WriteSide) -> Result<()> {
        let current = Arc::clone(&self.mem.read());
        if current.is_empty() {
            return Ok(());
        }

        let entries = current.snapshot_sorted();
        let id = write.next_table_id;
        let path = self.dir.join(format!("{id:010}.sst"));

        SsTable::write(&path, &entries)?;
        let table = Arc::new(SsTable::open(&path)?);

        self.tables.write().push(table);
        *self.mem.write() = Arc::new(MemTable::new());
        write.next_table_id = id + 1;
        write.wal.truncate()?;

        Ok(())
    }
}

fn visible(kind: Kind, bytes: Vec<u8>) -> Option<Vec<u8>> {
    match kind {
        Kind::Set => Some(bytes),
        Kind::Del => None,
    }
}

#[cfg(test)]
mod tests {
    use super::Store;
    use crate::config::Config;

    fn config(dir: &std::path::Path) -> Config {
        Config {
            data_dir: dir.to_path_buf(),
            memtable_bytes: 1024 * 1024,
            ..Config::default()
        }
    }

    #[test]
    fn writes_survive_a_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = config(dir.path());

        {
            let store = Store::open(&cfg).expect("open");
            store.set(b"colour", b"blue").expect("set");
            store.set(b"colour", b"green").expect("overwrite");
            store.set(b"shape", b"round").expect("set");
        }

        let store = Store::open(&cfg).expect("reopen");
        assert_eq!(store.get(b"colour").unwrap().as_deref(), Some(&b"green"[..]));
        assert_eq!(store.get(b"shape").unwrap().as_deref(), Some(&b"round"[..]));
        assert!(store.get(b"missing").unwrap().is_none());
    }

    #[test]
    fn deletes_hide_older_versions_through_a_flush() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = config(dir.path());
        let store = Store::open(&cfg).expect("open");

        store.set(b"k", b"v").expect("set");
        store.flush().expect("flush");
        store.delete(b"k").expect("delete");
        store.flush().expect("flush");

        assert!(store.get(b"k").unwrap().is_none());

        drop(store);
        let reopened = Store::open(&cfg).expect("reopen");
        assert!(reopened.get(b"k").unwrap().is_none());
    }

    #[test]
    fn sequence_numbers_keep_climbing_across_a_flush_and_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = config(dir.path());

        let before = {
            let store = Store::open(&cfg).expect("open");
            store.set(b"a", b"1").expect("set");
            store.flush().expect("flush");
            store.sequence()
        };

        let store = Store::open(&cfg).expect("reopen");
        assert_eq!(store.sequence(), before);
        store.set(b"b", b"2").expect("set");
        assert!(store.sequence() > before);
    }
}
