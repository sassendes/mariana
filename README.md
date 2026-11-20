# mariana

A key-value store that speaks a small binary protocol over TCP. You set things, you get them back, and if the process dies mid-write it comes back up with your data intact.

It is a log-structured store: writes go to a write-ahead log and an in-memory table, and when that table fills up it gets flushed to an immutable sorted file on disk. Reads check memory first, then the files newest to oldest, using a bloom filter per file to skip the ones that cannot contain the key.

## Status

Single node. It works and the durability path is tested, but there is no replication yet, so this is not something to put real data in.

Working:

- write-ahead log with a CRC32C per record, replayed on startup, truncated at the first torn record
- lock-free skiplist memtable, readers never block writers
- MVCC sequence numbers, so a read sees a consistent snapshot and never a half-applied write
- SSTable flush with a per-table bloom filter sized from a target false-positive rate
- length-prefixed binary protocol with every length bounds-checked before allocation
- optional token auth, compared in constant time

Not there yet:

- Raft. Every write already funnels through one mutex in `store.rs`, which is where replication would hook in, but nothing is replicated today.
- Compaction. Tables accumulate and never get merged, so read latency grows with write volume.
- Range scans. Point lookups only.
- TLS. Bind it to loopback or put it behind something that terminates TLS for you.

## Running it

```bash
cargo run --release
```

Defaults to `127.0.0.1:7878` with data in `./data`. To listen anywhere other than loopback you have to set a token, or it refuses to start:

```bash
MARIANA_TOKEN=$(openssl rand -hex 32) cargo run --release -- --listen 0.0.0.0:7878
```

Config file is optional:

```toml
listen = "127.0.0.1:7878"
data_dir = "./data"
max_connections = 512
handshake_timeout_ms = 5000
idle_timeout_ms = 60000
memtable_bytes = 67108864
fsync_on_write = true
```

Turning off `fsync_on_write` makes writes considerably faster and means you can lose the last few of them on a power cut. It is off the durability path on purpose, so decide deliberately.

## Protocol

Every frame is a 4-byte big-endian length, then a 1-byte opcode, then the body. Lengths inside the body are 4-byte big-endian too.

| Opcode | Request | Body |
| --- | --- | --- |
| `0x01` | PING | empty |
| `0x02` | AUTH | token |
| `0x03` | GET | key |
| `0x04` | SET | key, value |
| `0x05` | DEL | key |

Responses use the same length prefix, then a status byte:

| Status | Meaning |
| --- | --- |
| `0x00` | ok |
| `0x01` | value follows |
| `0x02` | not found |
| `0x03` | denied |
| `0x04` | bad request |
| `0x05` | internal error |

Limits: keys up to 1 KiB, values up to 4 MiB, frames up to 8 MiB. Anything over those is rejected before a single byte is allocated.

## On-disk layout

```
data/
  wal.log        append-only, [len][crc32c][payload] per record
  0000000000.sst
  0000000001.sst
```

An SSTable is the data section, then the index, then the bloom filter, then a 20-byte footer pointing at the index and bloom offsets. You read the footer first and work backwards. Nothing in the file is trusted: every offset and length is range-checked against the file size before it is used, and the index is verified to be sorted on load.

## Why the ordering matters

The durability argument is short enough to state in full:

1. A write is appended to the WAL and fsynced before the sequence counter advances.
2. Reads take their snapshot from that counter, so a reader can never observe a write that a power cut would erase.
3. On flush, the SSTable is fsynced before the WAL is truncated. A crash in between just replays records that already made it into the table, and because they carry the same sequence numbers and the same bytes, replaying them is a no-op.

That third point is why recovery is idempotent and why you can kill the process at any point without a repair step.

## Tests

```bash
cargo test
```

23 tests. The unit tests cover WAL round trips, torn-record truncation, bloom false-positive rates, SSTable corruption handling, snapshot visibility across flushes, and protocol parsing against malformed and oversized frames.

`tests/roundtrip.rs` runs the real server on an ephemeral port and talks to it over a socket with hand-built frames, including the cases that matter: a 4 GiB length prefix, a truncated body, and an unauthenticated client trying to read.

## Security

See [SECURITY.md](SECURITY.md) for the attack surface walkthrough and what is and is not defended against.

## License

MIT
