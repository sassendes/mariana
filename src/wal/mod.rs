// write ahead log. every write lands here and gets fsynced before we tell the client ok.
// each record is length + crc32c + payload. on restart we replay forwards and stop at the
// first record that does not check out, then truncate the file there. that is how a torn
// write from a power cut gets thrown away instead of being served back as real data.

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::mem::Kind;
use crate::{Error, Result};

const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;
const HEADER_BYTES: usize = 8;

#[derive(Debug, Clone)]
pub struct Record {
    pub seq: u64,
    pub kind: Kind,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

impl Record {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.clear();
        out.push(self.kind.as_byte());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&(self.key.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&(self.value.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.value);
    }

    fn decode(buf: &[u8]) -> Option<Record> {
        let (kind_byte, rest) = buf.split_first()?;
        let kind = Kind::from_byte(*kind_byte)?;

        let (seq_bytes, rest) = split_at_checked(rest, 8)?;
        let seq = u64::from_be_bytes(seq_bytes.try_into().ok()?);

        let (key, rest) = take_len_prefixed(rest)?;
        let (value, rest) = take_len_prefixed(rest)?;
        if !rest.is_empty() {
            return None;
        }

        Some(Record {
            seq,
            kind,
            key: key.to_vec(),
            value: value.to_vec(),
        })
    }
}

fn split_at_checked(buf: &[u8], n: usize) -> Option<(&[u8], &[u8])> {
    if buf.len() < n {
        return None;
    }
    Some(buf.split_at(n))
}

fn take_len_prefixed(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len_bytes, rest) = split_at_checked(buf, 4)?;
    let len = u32::from_be_bytes(len_bytes.try_into().ok()?) as usize;
    split_at_checked(rest, len)
}

pub struct Wal {
    file: File,
    path: PathBuf,
    fsync: bool,
    scratch: Vec<u8>,
}

impl Wal {
    pub fn open(dir: &Path, fsync: bool) -> Result<(Wal, Vec<Record>)> {
        fs::create_dir_all(dir)?;
        let path = dir.join("wal.log");

        let mut records = Vec::new();
        let mut valid_end: u64 = 0;

        if path.exists() {
            let mut reader = BufReader::new(File::open(&path)?);
            let mut header = [0u8; HEADER_BYTES];
            loop {
                if reader.read_exact(&mut header).is_err() {
                    break;
                }
                let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
                let crc = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);

                if len == 0 || len > MAX_RECORD_BYTES {
                    break;
                }

                let mut payload = vec![0u8; len];
                if reader.read_exact(&mut payload).is_err() {
                    break;
                }
                if crc32c::crc32c(&payload) != crc {
                    break;
                }

                match Record::decode(&payload) {
                    Some(record) => records.push(record),
                    None => break,
                }

                valid_end += (HEADER_BYTES + len) as u64;
            }
        }

        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)?;
        file.set_len(valid_end)?;
        file.sync_all()?;
        sync_dir(dir)?;

        let mut file = file;
        file.seek(SeekFrom::End(0))?;

        Ok((
            Wal {
                file,
                path,
                fsync,
                scratch: Vec::new(),
            },
            records,
        ))
    }

    pub fn append(&mut self, record: &Record) -> Result<()> {
        let mut payload = std::mem::take(&mut self.scratch);
        record.encode_into(&mut payload);

        if payload.len() > MAX_RECORD_BYTES {
            self.scratch = payload;
            return Err(Error::Malformed);
        }

        let mut header = [0u8; HEADER_BYTES];
        header[..4].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        header[4..].copy_from_slice(&crc32c::crc32c(&payload).to_be_bytes());

        let write_result = self
            .file
            .write_all(&header)
            .and_then(|_| self.file.write_all(&payload));

        self.scratch = payload;
        write_result?;

        if self.fsync {
            self.file.sync_data()?;
        }
        Ok(())
    }

    pub fn truncate(&mut self) -> Result<()> {
        self.file.set_len(0)?;
        self.file.seek(SeekFrom::Start(0))?;
        self.file.sync_all()?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub fn sync_dir(_dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(_dir)?.sync_all()?;
    }
    Ok(())
}
