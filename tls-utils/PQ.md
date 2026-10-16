# Native PQ TLS and QUIC

`solana_tls_utils::pq` is a Quinn/rustls implementation over UDP. It does not
wrap classical TLS in an application handshake. Its authenticated TLS 1.3
profile is padded Falcon-512 for CertificateVerify, ML-KEM-768 for key exchange,
and `TLS_AES_256_GCM_SHA384` for traffic encryption and the TLS key schedule.
TLS 1.2, classical key exchanges and signature schemes, session resumption,
tickets and zero RTT are disabled.

RFC 9001 Initial packets retain publicly derivable AES-128-GCM/SHA256 protection.
That protection is part of QUIC framing and establishes no identity or secrecy;
authenticated Handshake and application traffic use the PQ profile above.

The Falcon TLS signature scheme is private-use `0xfefe`, with ALPN
`agave-pq-validator-v1`. Canonical X.509 credential containers bind the Agave
signature domain, the existing 32-byte identity address, and the Falcon public key.
The outer certificate signature is a placeholder. Authority comes from the
independently trusted identity/key registry and the real Falcon TLS
CertificateVerify signature. Both verifiers match the complete container
against that registry; outbound clients additionally pin the expected server
identity. No key supplied by a connecting peer can extend the registry.
The actual Agave genesis hash is pinned separately at startup, and the registry
is checked against its immutable genesis account. Separating that hash from the
signature domain avoids a self-referential genesis encoding.

The ML-KEM implementation checks encapsulation-key modulus encodings and fixed
key/ciphertext sizes before completing exchange. Falcon uses the shared fixed
profile with chain and network-role domain separation. Secret KEM results are
erased after transfer into rustls's zeroizing shared-secret container.

`PqQuicConfig::server_config()` and `client_config(expected_identity)` provide
native Quinn configurations for services that already own an endpoint.
`PqQuicTransport::spawn(config, exit)` provides the validator's ordered frame
service. It exposes `receiver.recv_timeout()` / `try_recv()`, `send(peer, frame)`,
`broadcast(frame)`, and `join()`. Each connection carries a persistent ordered
unidirectional stream; each frame has a four-byte length prefix.

Frames are limited to 4 MiB. Outbound queues are limited to 4,096 records and
16 MiB per destination; the aggregate application receive queue has the same
limits. Quinn flow-control windows and active handshakes are also bounded.
Payload reads have a five-second timeout. Queue overflow returns an explicit
error; the caller must retain the frame and apply its own bounded retry policy.
Dequeueing releases the application receive reservation. A successful send
means admission to the local queue, and does not constitute a finalized
transaction acknowledgement. Reconnection can duplicate a frame, so consumers
must authenticate its protocol contents and apply replay/idempotency checks.

The validator's strict PQ branch must use this service for all authoritative
traffic. Existing classical gossip, repair, TPU identity and BLS voting paths
cannot remain authoritative merely because another endpoint uses PQ TLS.

The unit suite exercises actual UDP QUIC endpoints: mutual PQ authentication
and ordered frames, wrong-signature-domain rejection, rejection of a classical
Ed25519/X25519 client, canonical pin substitutions, KEM modulus checks, and queue
bounds. Existing legacy TLS certificate tests continue to run.

Remaining transport design work includes an interoperable standardized Falcon
TLS profile, finalized registry/key rotation across epochs, admission fairness
between validator and client traffic under adversarial load, and sustained
backpressure integration. This private profile is an experimental Agave mode.
