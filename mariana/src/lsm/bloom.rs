// bloom filter. answers "definitely not in this table" or "maybe", never a false no.
// that one sided error is the whole point, it lets a read skip opening tables it cannot
// possibly need. sizing comes straight from the standard formulas, m = -n ln p / (ln2)^2
// and k = (m/n) ln2. hash seeds are hardcoded on purpose because these get written to disk
// and a randomly seeded hasher would stop matching after a restart.

use ahash::RandomState;

const SEED_A: u64 = 0x243f_6a88_85a3_08d3;
const SEED_B: u64 = 0x1319_8a2e_0370_7344;
const SEED_C: u64 = 0xa409_3822_299f_31d0;
const SEED_D: u64 = 0x082e_fa98_ec4e_6c89;
const MIX: u64 = 0xff51_afd7_ed55_8ccd;

const MAX_BLOOM_WORDS: usize = 1 << 22;

pub struct Bloom {
    words: Vec<u64>,
    bits: u64,
    k: u32,
}

fn hash_pair(key: &[u8]) -> (u64, u64) {
    let state = RandomState::with_seeds(SEED_A, SEED_B, SEED_C, SEED_D);
    let h1 = state.hash_one(key);
    let h2 = (h1.rotate_left(32) ^ MIX) | 1;
    (h1, h2)
}

impl Bloom {
    pub fn new(expected: usize, fp_rate: f64) -> Bloom {
        let n = expected.max(1) as f64;
        let p = fp_rate.clamp(1e-6, 0.5);
        let ln2 = std::f64::consts::LN_2;

        let m = (-(n * p.ln()) / (ln2 * ln2)).ceil().max(64.0);
        let k = ((m / n) * ln2).round().clamp(1.0, 24.0) as u32;

        let words = (m as usize).div_ceil(64).min(MAX_BLOOM_WORDS);

        Bloom {
            words: vec![0u64; words],
            bits: (words as u64) * 64,
            k,
        }
    }

    pub fn insert(&mut self, key: &[u8]) {
        if self.bits == 0 {
            return;
        }
        let (h1, h2) = hash_pair(key);
        for i in 0..u64::from(self.k) {
            let bit = h1.wrapping_add(h2.wrapping_mul(i)) % self.bits;
            let idx = (bit >> 6) as usize;
            self.words[idx] |= 1u64 << (bit & 63);
        }
    }

    pub fn maybe_contains(&self, key: &[u8]) -> bool {
        if self.bits == 0 {
            return true;
        }
        let (h1, h2) = hash_pair(key);
        for i in 0..u64::from(self.k) {
            let bit = h1.wrapping_add(h2.wrapping_mul(i)) % self.bits;
            let idx = (bit >> 6) as usize;
            if self.words[idx] & (1u64 << (bit & 63)) == 0 {
                return false;
            }
        }
        true
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.words.len() * 8);
        out.extend_from_slice(&self.k.to_be_bytes());
        out.extend_from_slice(&(self.words.len() as u32).to_be_bytes());
        for word in &self.words {
            out.extend_from_slice(&word.to_be_bytes());
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Bloom> {
        if buf.len() < 8 {
            return None;
        }
        let k = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let count = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;

        if k == 0 || k > 24 || count > MAX_BLOOM_WORDS {
            return None;
        }
        let needed = count.checked_mul(8)?.checked_add(8)?;
        if buf.len() != needed {
            return None;
        }

        let mut words = Vec::with_capacity(count);
        for chunk in buf[8..].chunks_exact(8) {
            words.push(u64::from_be_bytes(chunk.try_into().ok()?));
        }

        Some(Bloom {
            bits: (words.len() as u64) * 64,
            words,
            k,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Bloom;

    #[test]
    fn no_false_negatives() {
        let mut bloom = Bloom::new(1000, 0.01);
        for i in 0..1000u32 {
            bloom.insert(&i.to_be_bytes());
        }
        for i in 0..1000u32 {
            assert!(bloom.maybe_contains(&i.to_be_bytes()));
        }
    }

    #[test]
    fn false_positive_rate_is_near_target() {
        let mut bloom = Bloom::new(10_000, 0.01);
        for i in 0..10_000u32 {
            bloom.insert(&i.to_be_bytes());
        }
        let misses = (10_000u32..110_000)
            .filter(|i| bloom.maybe_contains(&i.to_be_bytes()))
            .count();
        assert!(misses < 3_000, "false positive rate too high: {misses}/100000");
    }

    #[test]
    fn survives_a_round_trip() {
        let mut bloom = Bloom::new(500, 0.01);
        bloom.insert(b"hello");
        let decoded = Bloom::decode(&bloom.encode()).expect("decodes");
        assert!(decoded.maybe_contains(b"hello"));
    }

    #[test]
    fn rejects_garbage() {
        assert!(Bloom::decode(&[]).is_none());
        assert!(Bloom::decode(&[0, 0, 0, 3, 0xff, 0xff, 0xff, 0xff]).is_none());
    }
}
