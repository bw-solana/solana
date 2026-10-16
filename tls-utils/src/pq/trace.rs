//! Bounded diagnostic timing of public block-frame metadata, never admission.
use {
    super::PqQuicError,
    solana_pubkey::Pubkey,
    std::{
        collections::BTreeMap,
        fmt,
        sync::{
            Arc, Mutex, OnceLock,
            atomic::{AtomicU64, Ordering},
        },
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    },
};

const SHARDS: usize = 16;
const ENTRIES_PER_SHARD: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PqTraceConfig {
    pub first_slot: u64,
    pub slot_count: u64,
    pub window_size: u64,
}

impl PqTraceConfig {
    fn includes(self, slot: u64) -> bool {
        let Some(offset) = slot.checked_sub(self.first_slot) else {
            return false;
        };
        offset < self.slot_count
            && offset
                .checked_rem(self.window_size)
                .is_some_and(|position| {
                    position == 0 || position == self.window_size.saturating_sub(1)
                })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PqTraceLandmark {
    pub first_unix_us: u64,
    pub last_unix_us: u64,
    pub frames: u64,
    pub bytes: u64,
}

impl PqTraceLandmark {
    fn record(&mut self, timestamp: u64, bytes: usize) {
        if self.frames == 0 {
            self.first_unix_us = timestamp;
        } else {
            self.first_unix_us = self.first_unix_us.min(timestamp);
        }
        self.last_unix_us = self.last_unix_us.max(timestamp);
        self.frames = self.frames.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes as u64);
    }
}

/// Cumulative observed frames, including retransmissions. Prefix metadata is
/// unverified here; only Core's authenticated candidate can validate this join.
/// Write completion means Quinn accepted bytes, not peer receipt or QUIC ACK.
#[derive(Clone, Debug)]
pub struct PqBlockTrace {
    pub peer_index: u16,
    pub outbound: bool,
    pub leader_epoch: u64,
    pub slot: u64,
    pub candidate: [u8; 48],
    pub generation: u64,
    pub data: [PqTraceLandmark; 4],
    pub terminal: [PqTraceLandmark; 4],
}

impl fmt::Display for PqBlockTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "peer_index={} direction={} leader_epoch={} slot={} generation={} candidate=",
            self.peer_index,
            if self.outbound { "outbound" } else { "inbound" },
            self.leader_epoch,
            self.slot,
            self.generation
        )?;
        for byte in self.candidate {
            write!(f, "{byte:02x}")?;
        }
        for (kind, landmarks) in [("data", &self.data), ("terminal", &self.terminal)] {
            for (stage, landmark) in ["enqueue", "write", "read", "dequeue"]
                .into_iter()
                .zip(landmarks)
            {
                write!(
                    f,
                    " {kind}_{stage}_first_unix_us={} {kind}_{stage}_last_unix_us={} \
                     {kind}_{stage}_frames={} {kind}_{stage}_bytes={}",
                    landmark.first_unix_us, landmark.last_unix_us, landmark.frames, landmark.bytes
                )?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) enum Stage {
    Enqueue = 0,
    Write = 1,
    Read = 2,
    Dequeue = 3,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    peer_index: u16,
    outbound: bool,
    leader_epoch: u64,
    slot: u64,
    candidate: [u8; 48],
}

struct Entry {
    summary: PqBlockTrace,
    dirty: bool,
    last_observed: u64,
}

pub(super) struct BlockTracer {
    config: OnceLock<PqTraceConfig>,
    peers: BTreeMap<Pubkey, u16>,
    origin: Instant,
    unix_origin_us: u64,
    shards: [Mutex<BTreeMap<Key, Entry>>; SHARDS],
    last_drain: Mutex<Instant>,
    next_generation: AtomicU64,
    pub(super) evictions: AtomicU64,
}

impl Default for BlockTracer {
    fn default() -> Self {
        Self::new(std::iter::empty())
    }
}

impl BlockTracer {
    pub(super) fn new(peers: impl Iterator<Item = Pubkey>) -> Self {
        let origin = Instant::now();
        Self {
            config: OnceLock::new(),
            peers: peers
                .enumerate()
                .map(|(i, peer)| (peer, i as u16))
                .collect(),
            origin,
            unix_origin_us: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros()
                .min(u128::from(u64::MAX)) as u64,
            shards: std::array::from_fn(|_| Mutex::new(BTreeMap::new())),
            last_drain: Mutex::new(origin),
            next_generation: AtomicU64::new(1),
            evictions: AtomicU64::new(0),
        }
    }

    pub(super) fn configure(&self, config: PqTraceConfig) -> Result<(), PqQuicError> {
        if config.window_size == 0
            || config.slot_count == 0
            || config.first_slot.checked_add(config.slot_count).is_none()
        {
            return Err(PqQuicError::Configuration(
                "invalid block trace bounds".into(),
            ));
        }
        let actual = self.config.get_or_init(|| config);
        if *actual != config {
            return Err(PqQuicError::Configuration(
                "block trace configuration changed".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn now_us(&self) -> u64 {
        self.unix_origin_us
            .saturating_add(self.origin.elapsed().as_micros().min(u128::from(u64::MAX)) as u64)
    }

    pub(super) fn tag(
        self: &Arc<Self>,
        peer: Pubkey,
        frame: &[u8],
        outbound: bool,
    ) -> Option<FrameTrace> {
        let config = *self.config.get()?;
        // Existing public v1 prefixes only. Do not decode, authenticate or alter
        // the frame; malformed claimed metadata remains diagnostic/untrusted.
        let (offset, terminal) = match frame.first()? {
            1 => (1, false),
            2 if frame.get(1) == Some(&2) => (2, true),
            _ => return None,
        };
        let prefix = frame.get(offset..)?;
        if prefix.get(..2)? != [1, 0] {
            return None;
        }
        let leader_epoch = u64::from_le_bytes(prefix.get(2..10)?.try_into().ok()?);
        let slot = u64::from_le_bytes(prefix.get(10..18)?.try_into().ok()?);
        if !config.includes(slot) {
            return None;
        }
        let candidate = prefix.get(18..66)?.try_into().ok()?;
        Some(FrameTrace {
            tracer: Arc::clone(self),
            key: Key {
                peer_index: *self.peers.get(&peer)?,
                outbound,
                leader_epoch,
                slot,
                candidate,
            },
            terminal,
        })
    }

    pub(super) fn drain(&self) -> Vec<PqBlockTrace> {
        let Ok(mut last) = self.last_drain.lock() else {
            return Vec::new();
        };
        if last.elapsed() < Duration::from_secs(1) {
            return Vec::new();
        }
        *last = Instant::now();
        let mut snapshots = Vec::new();
        for shard in &self.shards {
            let Ok(mut rows) = shard.lock() else { continue };
            for entry in rows.values_mut().filter(|entry| entry.dirty) {
                snapshots.push(entry.summary.clone());
                entry.dirty = false;
            }
        }
        snapshots
    }
}

#[derive(Clone)]
pub(super) struct FrameTrace {
    tracer: Arc<BlockTracer>,
    key: Key,
    terminal: bool,
}

impl FrameTrace {
    pub(super) fn observe(&self, stage: Stage, bytes: usize) {
        self.observe_at(stage, bytes, self.tracer.now_us());
    }

    pub(super) fn observe_at(&self, stage: Stage, bytes: usize, timestamp: u64) {
        let shard = (usize::from(self.key.peer_index)
            ^ self.key.slot as usize
            ^ usize::from(self.key.outbound))
            % SHARDS;
        let Ok(mut rows) = self.tracer.shards[shard].lock() else {
            return;
        };
        if !rows.contains_key(&self.key)
            && rows.len() >= ENTRIES_PER_SHARD
            && let Some(oldest) = rows
                .iter()
                .min_by_key(|(_, entry)| entry.last_observed)
                .map(|(key, _)| *key)
        {
            rows.remove(&oldest);
            self.tracer.evictions.fetch_add(1, Ordering::Relaxed);
        }
        let entry = rows.entry(self.key).or_insert_with(|| Entry {
            summary: PqBlockTrace {
                peer_index: self.key.peer_index,
                outbound: self.key.outbound,
                leader_epoch: self.key.leader_epoch,
                slot: self.key.slot,
                candidate: self.key.candidate,
                generation: self.tracer.next_generation.fetch_add(1, Ordering::Relaxed),
                data: [PqTraceLandmark::default(); 4],
                terminal: [PqTraceLandmark::default(); 4],
            },
            dirty: false,
            last_observed: timestamp,
        });
        let landmarks = if self.terminal {
            &mut entry.summary.terminal
        } else {
            &mut entry.summary.data
        };
        landmarks[stage as usize].record(timestamp, bytes);
        entry.last_observed = entry.last_observed.max(timestamp);
        entry.dirty = true;
    }
}

#[cfg(test)]
pub(super) mod tests {
    use {
        super::*,
        agave_pq_crypto::{
            crypto::FalconKeypair,
            network::{BatchContext, FinalMarker, SignedBatch},
        },
    };

    pub(crate) fn signed_frames(key: &FalconKeypair, slot: u64) -> (Vec<Vec<u8>>, Vec<u8>) {
        let payload = b"transport timing retains real signed frame bytes";
        let batch = SignedBatch::build(
            &[0x37; 32],
            key,
            BatchContext {
                leader_epoch: 7,
                slot,
                candidate: [0x29; 48],
                parent: [0x18; 48],
                batch_index: 0,
                previous: [0; 48],
            },
            payload,
            2,
            2,
        )
        .unwrap();
        let marker =
            FinalMarker::build(&[0x37; 32], key, std::slice::from_ref(&batch), payload).unwrap();
        let frames = batch
            .shreds
            .iter()
            .map(|shred| {
                let mut bytes = vec![1];
                bytes.extend(shred.encode().unwrap());
                bytes
            })
            .collect();
        let mut terminal = vec![2];
        terminal.extend(marker.encode());
        (frames, terminal)
    }

    fn force_drain(tracer: &BlockTracer) -> Vec<PqBlockTrace> {
        *tracer.last_drain.lock().unwrap() =
            Instant::now().checked_sub(Duration::from_secs(2)).unwrap();
        tracer.drain()
    }

    #[test]
    fn boundary_trace_joins_real_signed_prefixes_and_late_data_without_authorizing_them() {
        let peer = Pubkey::new_unique();
        let tracer = Arc::new(BlockTracer::new(std::iter::once(peer)));
        let key = FalconKeypair::generate();
        let (data, terminal) = signed_frames(&key, 4);
        assert!(tracer.tag(peer, &data[0], true).is_none());
        assert!(
            tracer
                .configure(PqTraceConfig {
                    first_slot: 1,
                    slot_count: 8,
                    window_size: 0
                })
                .is_err()
        );
        let config = PqTraceConfig {
            first_slot: 1,
            slot_count: 8,
            window_size: 4,
        };
        tracer.configure(config).unwrap();
        tracer.configure(config).unwrap();
        assert!(
            tracer
                .configure(PqTraceConfig {
                    first_slot: 2,
                    ..config
                })
                .is_err()
        );
        for slot in 0u64..=9 {
            let mut frame = data[0].clone();
            frame[11..19].copy_from_slice(&slot.to_le_bytes());
            assert_eq!(
                tracer.tag(peer, &frame, false).is_some(),
                matches!(slot, 1 | 4 | 5 | 8)
            );
        }
        let first = tracer.tag(peer, &data[0], true).unwrap();
        // The writer may run before the producer records successful enqueue.
        first.observe_at(Stage::Write, data[0].len(), 200);
        first.observe_at(Stage::Enqueue, data[0].len(), 100);
        let term = tracer.tag(peer, &terminal, false).unwrap();
        term.observe_at(Stage::Read, terminal.len(), 300);
        term.observe_at(Stage::Dequeue, terminal.len(), 400);
        for (index, frame) in data.iter().enumerate() {
            let trace = tracer.tag(peer, frame, false).unwrap();
            trace.observe_at(Stage::Read, frame.len(), 500 + index as u64);
            trace.observe_at(Stage::Dequeue, frame.len(), 600 + index as u64);
        }
        let snapshots = force_drain(&tracer);
        assert_eq!(snapshots.len(), 2);
        let sent = snapshots.iter().find(|row| row.outbound).unwrap();
        assert_eq!(sent.data[0].first_unix_us, 100);
        assert_eq!(sent.data[1].last_unix_us, 200);
        let received = snapshots.iter().find(|row| !row.outbound).unwrap();
        assert_eq!(received.candidate, [0x29; 48]);
        assert_eq!(received.terminal[2].first_unix_us, 300);
        assert_eq!(received.data[2].frames, 4);
        assert_eq!(received.data[2].last_unix_us, 503);
        assert_eq!(received.data[3].last_unix_us, 603);
        assert!(tracer.drain().is_empty(), "one-second emission bound");
        assert!(
            force_drain(&tracer).is_empty(),
            "unchanged cumulative rows are quiet"
        );
        assert!(tracer.tag(Pubkey::new_unique(), &data[0], true).is_none());
        for prefix in 0..67 {
            assert!(tracer.tag(peer, &data[0][..prefix], true).is_none());
        }
        let mut wrong_version = data[0].clone();
        wrong_version[1] = 2;
        assert!(tracer.tag(peer, &wrong_version, true).is_none());
    }

    #[test]
    fn trace_concurrent_retention_is_bounded_and_eviction_generations_are_explicit() {
        let peers: Vec<_> = (0..8).map(|_| Pubkey::new_unique()).collect();
        let tracer = Arc::new(BlockTracer::new(peers.iter().copied()));
        tracer
            .configure(PqTraceConfig {
                first_slot: 1,
                slot_count: 10000,
                window_size: 4,
            })
            .unwrap();
        let (data, _) = signed_frames(&FalconKeypair::generate(), 4);
        std::thread::scope(|scope| {
            for peer in peers {
                let tracer = Arc::clone(&tracer);
                let original = &data[0];
                scope.spawn(move || {
                    for ordinal in 0..100u64 {
                        let mut bytes = original.clone();
                        bytes[19..27].copy_from_slice(&ordinal.to_le_bytes());
                        let trace = tracer.tag(peer, &bytes, true).unwrap();
                        trace.observe_at(Stage::Enqueue, bytes.len(), ordinal + 1);
                        trace.observe_at(Stage::Write, bytes.len(), ordinal + 2);
                    }
                });
            }
        });
        assert!(tracer.evictions.load(Ordering::Relaxed) > 0);
        let rows = force_drain(&tracer);
        assert!(rows.len() <= SHARDS * ENTRIES_PER_SHARD);
        let generations: std::collections::BTreeSet<_> =
            rows.iter().map(|row| row.generation).collect();
        assert_eq!(generations.len(), rows.len());
        assert!(
            rows.iter()
                .all(|row| row.data[0].frames == 1 && row.data[1].frames == 1)
        );
    }
}
