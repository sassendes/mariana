# Security

This is a network service that accepts unauthenticated bytes from whoever can reach the port, and it parses a hand-rolled binary format. That is the two ingredients that produce most remote vulnerabilities, so the parsing and limit code is written defensively and this document explains what it is defending against.

## Threat model

Assumed hostile: anything arriving on the socket. Frame contents, frame lengths, connection timing, connection count.

Assumed trusted: the local filesystem and the config file. If an attacker can write to the data directory or the config, they have already won by an easier route than anything below.

Not defended against: an attacker with local disk access, a malicious operator, or side channels beyond the timing case handled below.

## Attack surface

### Length-prefix memory exhaustion

Reading a 4-byte length and passing it to `Vec::with_capacity` lets a 5-byte packet request a 4 GiB allocation. This is the single most common bug in hand-written binary protocols.

`read_frame` in `src/net/codec.rs` checks the length against `MAX_FRAME_BYTES` before touching the buffer. Zero-length frames are rejected too, since they carry no opcode and would otherwise fall into the parser. The buffer is reused across requests on the same connection, so a well-behaved client does not cause repeated allocation either.

Inner lengths get the same treatment. `take_len_prefixed` checks the claimed length against a per-field cap *and* against the bytes actually remaining, so a frame claiming a 1 KiB key inside a 12-byte body is refused rather than slicing out of range.

### Panics as a denial of service

With `panic = "abort"` in the release profile, a panic on a hostile frame takes down the whole process. The parser therefore contains no indexing that can panic: everything is `split_first`, `split_at` behind an explicit length check, or `try_into` with the error handled. There are no `unwrap` or `expect` calls on any path that touches network input.

The same reasoning applies to the on-disk parsers. A corrupt SSTable and a maliciously crafted one are indistinguishable at the point of reading, so `sstable.rs` range-checks every offset against the file size, verifies the footer magic, caps the index and bloom section sizes, and confirms the index is sorted before trusting a binary search over it.

### Connection exhaustion

Slow or idle connections tie up file descriptors and memory. Three limits apply:

- `max_connections` is enforced with a semaphore using `try_acquire_owned`. A connection arriving when the server is full is dropped immediately rather than queued, because queueing lets an attacker accumulate unbounded pending work.
- `handshake_timeout_ms` bounds how long a connection can sit before its first frame. This is the slowloris case.
- `idle_timeout_ms` bounds the gap between frames afterwards.

An unauthenticated connection stays on the shorter handshake budget until it authenticates, so an attacker without the token cannot hold a socket for the longer idle window.

### Token comparison timing

Comparing tokens with `==` returns on the first differing byte, and the time difference is measurable over a network given enough samples. It also leaks the length.

`src/net/auth.rs` hashes both the stored secret and the presented token with SHA-256 and compares the digests with `subtle::ConstantTimeEq`. Hashing first means the comparison is always over 32 bytes regardless of input length, so neither the token contents nor its length leak. A failed AUTH closes the connection rather than allowing repeated attempts on the same socket.

The token is read only from `MARIANA_TOKEN`, never from the config file, so it does not end up committed by accident. A minimum length is enforced. `Debug` is implemented by hand to print `Token(redacted)` so it cannot be logged by mistake.

### Unauthenticated public exposure

The most damaging real-world incidents involving key-value stores have overwhelmingly been unauthenticated instances reachable from the internet, not memory-safety bugs.

The default listen address is `127.0.0.1`. Binding a non-loopback address with no token configured is a startup error, not a warning. This is deliberately not overridable by a flag.

### Blocking the async runtime

`fsync` on a Tokio worker thread stalls every other connection scheduled on it, which is a denial of service reachable by any client that can issue a write. All store operations run through `spawn_blocking`.

### Integer overflow

The sequence counter uses `checked_add` and returns an error at the limit rather than wrapping, since a wrapped sequence number would silently corrupt snapshot visibility. Bloom filter sizing uses `checked_mul`/`checked_add` when validating an encoded filter's declared word count, so a hostile table cannot overflow into a small allocation followed by a large read.

### Torn writes and corruption

Every WAL record carries a CRC32C. Recovery replays forwards and stops at the first record with a bad checksum, a length outside the accepted range, or a body that does not decode, then truncates the file at the last known-good offset. A partially written record from a power cut is discarded rather than served back as data.

CRC32C detects accidental corruption. It is not a MAC and does not detect deliberate tampering by someone with write access to the data directory, which is outside the threat model.

## Known gaps

- **No TLS.** Traffic and the token itself are in plaintext. Bind to loopback or terminate TLS in front of it.
- **No rate limiting on AUTH.** Failed attempts close the connection, but nothing stops reconnection. A token of the enforced minimum length is not brute-forceable in practice, but a real deployment should limit this at the network edge.
- **No per-client quotas.** An authenticated client can fill the disk.
- **`fsync_on_write = false` breaks the durability guarantee.** It is documented and defaults to on.
- **No compaction** means unbounded disk growth under sustained writes. This is an availability issue, not a memory-safety one, but it is a real way to run a node out of space.

## Reporting

Open an issue.
