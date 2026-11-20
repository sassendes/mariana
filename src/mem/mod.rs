// the memtable. lock free skiplist so readers never wait on writers.
// keys sort by user key ascending, then sequence descending, which means the newest
// version of a key is always the first thing you land on when you seek to it.

use crossbeam_skiplist::SkipMap;
use std::cmp::Ordering as CmpOrdering;
use std::ops::Bound;
use std::sync::atomic::{AtomicUsize, Ordering};

const ENTRY_OVERHEAD: usize = 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Set,
    Del,
}

impl Kind {
    pub fn as_byte(self) -> u8 {
        match self {
            Kind::Set => 0,
            Kind::Del => 1,
        }
    }

    pub fn from_byte(b: u8) -> Option<Kind> {
        match b {
            0 => Some(Kind::Set),
            1 => Some(Kind::Del),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalKey {
    pub user: Vec<u8>,
    pub seq: u64,
}

impl Ord for InternalKey {
    fn cmp(&self, other: &InternalKey) -> CmpOrdering {
        self.user
            .cmp(&other.user)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}

impl PartialOrd for InternalKey {
    fn partial_cmp(&self, other: &InternalKey) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone)]
pub struct Value {
    pub kind: Kind,
    pub bytes: Vec<u8>,
}

pub struct MemTable {
    map: SkipMap<InternalKey, Value>,
    charged: AtomicUsize,
}

impl MemTable {
    pub fn new() -> MemTable {
        MemTable {
            map: SkipMap::new(),
            charged: AtomicUsize::new(0),
        }
    }

    pub fn insert(&self, user: Vec<u8>, seq: u64, kind: Kind, bytes: Vec<u8>) {
        let charge = user.len() + bytes.len() + ENTRY_OVERHEAD;
        self.map.insert(InternalKey { user, seq }, Value { kind, bytes });
        self.charged.fetch_add(charge, Ordering::Relaxed);
    }

    pub fn get(&self, user: &[u8], snapshot: u64) -> Option<Value> {
        let probe = InternalKey {
            user: user.to_vec(),
            seq: snapshot,
        };
        let entry = self.map.lower_bound(Bound::Included(&probe))?;
        if entry.key().user.as_slice() != user {
            return None;
        }
        Some(entry.value().clone())
    }

    pub fn approx_bytes(&self) -> usize {
        self.charged.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn snapshot_sorted(&self) -> Vec<(InternalKey, Value)> {
        self.map
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect()
    }
}

impl Default for MemTable {
    fn default() -> MemTable {
        MemTable::new()
    }
}
