// immutable sorted table on disk. layout is data, then index, then bloom, then a fixed
// footer at the tail pointing at the other two. you read the footer first and work backwards.
// nothing here trusts the file. every length gets bounds checked before it is used to
// allocate or seek, because a corrupt table and a malicious table look identical from here.

use parking_lot::Mutex;
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::config::{MAX_KEY_BYTES, MAX_VALUE_BYTES};
use crate::lsm::bloom::Bloom;
use crate::mem::{InternalKey, Kind, Value};
use crate::{Error, Result};

const MAGIC: u32 = 0x4d41_5231;
const FOOTER_BYTES: u64 = 20;
const MAX_INDEX_BYTES: u64 = 256 * 1024 * 1024;
const MAX_BLOOM_BYTES: u64 = 64 * 1024 * 1024;
const FP_RATE: f64 = 0.01;

pub struct SsTable {
    file: Mutex<File>,
    index: Vec<(InternalKey, u64)>,
    bloom: Bloom,
    path: PathBuf,
}

impl SsTable {
    pub fn write(path: &Path, entries: &[(InternalKey, Value)]) -> Result<()> {
        let file = File::create(path)?;
        let mut out = BufWriter::new(file);

        let mut index: Vec<(InternalKey, u64)> = Vec::with_capacity(entries.len());
        let mut bloom = Bloom::new(entries.len(), FP_RATE);
        let mut offset: u64 = 0;
        let mut scratch = Vec::new();

        for (key, value) in entries {
            index.push((key.clone(), offset));
            bloom.insert(&key.user);

            scratch.clear();
            scratch.extend_from_slice(&(key.user.len() as u32).to_be_bytes());
            scratch.extend_from_slice(&key.user);
            scratch.extend_from_slice(&key.seq.to_be_bytes());
            scratch.push(value.kind.as_byte());
            scratch.extend_from_slice(&(value.bytes.len() as u32).to_be_bytes());
            scratch.extend_from_slice(&value.bytes);

            out.write_all(&scratch)?;
            offset += scratch.len() as u64;
        }

        let index_offset = offset;
        scratch.clear();
        scratch.extend_from_slice(&(index.len() as u32).to_be_bytes());
        for (key, entry_offset) in &index {
            scratch.extend_from_slice(&(key.user.len() as u32).to_be_bytes());
            scratch.extend_from_slice(&key.user);
            scratch.extend_from_slice(&key.seq.to_be_bytes());
            scratch.extend_from_slice(&entry_offset.to_be_bytes());
        }
        out.write_all(&scratch)?;
        let bloom_offset = index_offset + scratch.len() as u64;

        let encoded_bloom = bloom.encode();
        out.write_all(&encoded_bloom)?;

        let mut footer = Vec::with_capacity(FOOTER_BYTES as usize);
        footer.extend_from_slice(&index_offset.to_be_bytes());
        footer.extend_from_slice(&bloom_offset.to_be_bytes());
        footer.extend_from_slice(&MAGIC.to_be_bytes());
        out.write_all(&footer)?;

        let file = out.into_inner().map_err(|e| Error::Io(e.into_error()))?;
        file.sync_all()?;

        if let Some(parent) = path.parent() {
            crate::wal::sync_dir(parent)?;
        }
        Ok(())
    }

    pub fn open(path: &Path) -> Result<SsTable> {
        let mut file = File::open(path)?;
        let size = file.metadata()?.len();
        if size < FOOTER_BYTES {
            return Err(Error::BadTable("file shorter than footer"));
        }

        file.seek(SeekFrom::Start(size - FOOTER_BYTES))?;
        let mut footer = [0u8; FOOTER_BYTES as usize];
        file.read_exact(&mut footer)?;

        if u32::from_be_bytes([footer[16], footer[17], footer[18], footer[19]]) != MAGIC {
            return Err(Error::BadTable("bad magic"));
        }

        let index_offset = be_u64(&footer[0..8]);
        let bloom_offset = be_u64(&footer[8..16]);
        let footer_offset = size - FOOTER_BYTES;

        if index_offset > bloom_offset || bloom_offset > footer_offset {
            return Err(Error::BadTable("footer offsets out of order"));
        }

        let index_len = bloom_offset - index_offset;
        let bloom_len = footer_offset - bloom_offset;
        if index_len > MAX_INDEX_BYTES || bloom_len > MAX_BLOOM_BYTES {
            return Err(Error::BadTable("index or bloom section too large"));
        }

        let index_raw = read_exact_at(&mut file, index_offset, index_len as usize)?;
        let bloom_raw = read_exact_at(&mut file, bloom_offset, bloom_len as usize)?;

        let index = decode_index(&index_raw, index_offset)?;
        let bloom = Bloom::decode(&bloom_raw).ok_or(Error::BadTable("bloom section"))?;

        Ok(SsTable {
            file: Mutex::new(file),
            index,
            bloom,
            path: path.to_path_buf(),
        })
    }

    pub fn get(&self, user: &[u8], snapshot: u64) -> Result<Option<Value>> {
        if !self.bloom.maybe_contains(user) {
            return Ok(None);
        }

        let probe = InternalKey {
            user: user.to_vec(),
            seq: snapshot,
        };
        let position = self.index.partition_point(|(key, _)| *key < probe);

        let (found, offset) = match self.index.get(position) {
            Some(entry) => entry,
            None => return Ok(None),
        };
        if found.user.as_slice() != user {
            return Ok(None);
        }

        self.read_value_at(*offset).map(Some)
    }

    fn read_value_at(&self, offset: u64) -> Result<Value> {
        let mut file = self.file.lock();
        file.seek(SeekFrom::Start(offset))?;

        let mut key_len_buf = [0u8; 4];
        file.read_exact(&mut key_len_buf)?;
        let key_len = u32::from_be_bytes(key_len_buf) as usize;
        if key_len > MAX_KEY_BYTES {
            return Err(Error::BadTable("key length out of range"));
        }

        file.seek(SeekFrom::Current(key_len as i64))?;

        let mut tail = [0u8; 13];
        file.read_exact(&mut tail)?;
        let kind = Kind::from_byte(tail[8]).ok_or(Error::BadTable("unknown record kind"))?;
        let value_len = u32::from_be_bytes([tail[9], tail[10], tail[11], tail[12]]) as usize;
        if value_len > MAX_VALUE_BYTES {
            return Err(Error::BadTable("value length out of range"));
        }

        let mut bytes = vec![0u8; value_len];
        file.read_exact(&mut bytes)?;

        Ok(Value { kind, bytes })
    }

    pub fn max_seq(&self) -> u64 {
        self.index.iter().map(|(key, _)| key.seq).max().unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn be_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    u64::from_be_bytes(buf)
}

fn read_exact_at(file: &mut File, offset: u64, len: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

fn decode_index(raw: &[u8], data_end: u64) -> Result<Vec<(InternalKey, u64)>> {
    if raw.len() < 4 {
        return Err(Error::BadTable("index header truncated"));
    }
    let count = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;

    let mut cursor = &raw[4..];
    let mut index = Vec::with_capacity(count.min(1 << 20));
    let mut previous: Option<InternalKey> = None;

    for _ in 0..count {
        if cursor.len() < 4 {
            return Err(Error::BadTable("index entry truncated"));
        }
        let key_len = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]) as usize;
        if key_len > MAX_KEY_BYTES {
            return Err(Error::BadTable("index key too long"));
        }
        cursor = &cursor[4..];

        if cursor.len() < key_len + 16 {
            return Err(Error::BadTable("index entry truncated"));
        }
        let user = cursor[..key_len].to_vec();
        cursor = &cursor[key_len..];

        let seq = be_u64(&cursor[..8]);
        let offset = be_u64(&cursor[8..16]);
        cursor = &cursor[16..];

        if offset >= data_end {
            return Err(Error::BadTable("index points past the data section"));
        }

        let key = InternalKey { user, seq };
        if let Some(prev) = &previous {
            if key <= *prev {
                return Err(Error::BadTable("index is not sorted"));
            }
        }
        previous = Some(key.clone());
        index.push((key, offset));
    }

    if !cursor.is_empty() {
        return Err(Error::BadTable("trailing bytes in index"));
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::SsTable;
    use crate::mem::{InternalKey, Kind, Value};

    fn entry(user: &str, seq: u64, value: &str) -> (InternalKey, Value) {
        (
            InternalKey {
                user: user.as_bytes().to_vec(),
                seq,
            },
            Value {
                kind: Kind::Set,
                bytes: value.as_bytes().to_vec(),
            },
        )
    }

    #[test]
    fn round_trips_and_respects_snapshots() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("000001.sst");

        let mut entries = vec![entry("a", 1, "first"), entry("a", 5, "second"), entry("b", 2, "bee")];
        entries.sort_by(|x, y| x.0.cmp(&y.0));
        SsTable::write(&path, &entries).expect("write");

        let table = SsTable::open(&path).expect("open");
        assert_eq!(table.get(b"a", 10).unwrap().unwrap().bytes, b"second");
        assert_eq!(table.get(b"a", 3).unwrap().unwrap().bytes, b"first");
        assert!(table.get(b"a", 0).unwrap().is_none());
        assert!(table.get(b"zzz", 10).unwrap().is_none());
    }

    #[test]
    fn rejects_a_truncated_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("000002.sst");
        SsTable::write(&path, &[entry("a", 1, "x")]).expect("write");

        let size = std::fs::metadata(&path).unwrap().len();
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(size - 4).unwrap();
        drop(file);

        assert!(SsTable::open(&path).is_err());
    }
}
