//! Deterministic event-driven network scenarios, with real signature verification.
use {
    crate::{
        consensus::{
            ConsensusKeypair, ConsensusMessage, ConsensusPool, MessageKind, SignedEvidence,
            Validator,
        },
        crypto::FalconKeypair,
        network::{AuthenticatedShred, BatchContext, CandidateAssembler, FinalMarker, SignedBatch},
        quantumglow::{
            Action, BlockRef, Config, Error, ExecutionState, Quantumglow, RecoveryJournal,
            epoch_configuration_commitment,
        },
    },
    std::{
        collections::{BTreeMap, BTreeSet},
        sync::Arc,
    },
};

#[derive(Clone)]
struct Candidate {
    marker: FinalMarker,
    shreds: Vec<AuthenticatedShred>,
}
#[derive(Clone)]
enum Packet {
    Evidence(SignedEvidence),
    Block(Box<Candidate>),
}
struct Delivery {
    at: u64,
    to: usize,
    packet: Packet,
}

/// The scheduler controls directed delays, transient loss, partition GST,
/// offline nodes and restart. It retransmits original signed evidence rather
/// than asking the one-time signer to allocate another key for a retry.
type DeliveryId = (usize, usize, u64, MessageKind, Option<[u8; 48]>);
struct Network {
    keys: Vec<Arc<ConsensusKeypair>>,
    leaders: Vec<FalconKeypair>,
    validators: Vec<Validator>,
    config: Config,
    nodes: Vec<Option<Quantumglow>>,
    deliveries: Vec<Delivery>,
    retransmit: Vec<(usize, SignedEvidence)>,
    candidates: BTreeMap<[u8; 48], Candidate>,
    produced: BTreeSet<u64>,
    disabled: BTreeSet<usize>,
    partition_until: u64,
    lose_first: bool,
    lost: BTreeSet<DeliveryId>,
    broadcasts: usize,
    repairs: usize,
}
impl Network {
    fn new(slots: u64, window: u64, schedule: Vec<usize>) -> Self {
        let keys: Vec<_> = (0..7)
            .map(|i| {
                Arc::new(
                    ConsensusKeypair::generate_for([0x42; 32], [i; 32], 1, 1, slots as u32)
                        .unwrap(),
                )
            })
            .collect();
        let leaders: Vec<_> = (0..7).map(|_| FalconKeypair::generate()).collect();
        let validators: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| Validator {
                id: [i as u8; 32],
                stake: 1,
                key: k.public_key(),
            })
            .collect();
        let config = Config {
            chain: [0x42; 32],
            epoch: 1,
            first_slot: 1,
            slot_count: slots,
            window_size: window,
            network_delay_ms: 10,
            block_time_ms: 5,
            leaders: schedule.iter().map(|i| [*i as u8; 32]).collect(),
            leader_keys: leaders
                .iter()
                .enumerate()
                .map(|(i, k)| ([i as u8; 32], k.public_key()))
                .collect(),
            finalized_anchor: BlockRef {
                slot: 0,
                hash: [0x91; 48],
            },
            finalized_state_root: [0x55; 48],
            execution_rules: [0x22; 48],
            validate_execution: Arc::new(|candidate| {
                (candidate.payload != b"invalid execution").then_some(ExecutionState {
                    parent_state_root: [0x55; 48],
                    state_root: [0x55; 48],
                })
            }),
        };
        let nodes = (0..7)
            .map(|i| Some(Quantumglow::new(config.clone(), [i; 32], validators.clone()).unwrap()))
            .collect();
        Self {
            keys,
            leaders,
            validators,
            config,
            nodes,
            deliveries: vec![],
            retransmit: vec![],
            candidates: BTreeMap::new(),
            produced: BTreeSet::new(),
            disabled: BTreeSet::new(),
            partition_until: 0,
            lose_first: false,
            lost: BTreeSet::new(),
            broadcasts: 0,
            repairs: 0,
        }
    }
    fn candidate(&self, slot: u64, parent: [u8; 48], tag: u8, payload: &[u8]) -> Candidate {
        let leader = self.config.leaders[(slot - 1) as usize][0] as usize;
        let batch = SignedBatch::build(
            &self.config.chain,
            &self.leaders[leader],
            BatchContext {
                leader_epoch: self.config.epoch,
                slot,
                candidate: [tag; 48],
                parent,
                batch_index: 0,
                previous: [0; 48],
            },
            payload,
            2,
            2,
        )
        .unwrap();
        let marker = FinalMarker::build(
            &self.config.chain,
            &self.leaders[leader],
            std::slice::from_ref(&batch),
            payload,
        )
        .unwrap();
        // Only parity and one data shred: every received candidate exercises repair decoding.
        Candidate {
            marker,
            shreds: vec![batch.shreds[1].clone(), batch.shreds[2].clone()],
        }
    }
    fn queue(&mut self, from: usize, to: usize, packet: Packet, now: u64, retry: bool) {
        if self.disabled.contains(&to) {
            return;
        }
        if let Packet::Evidence(e) = &packet {
            let key = (from, to, e.message.slot, e.message.kind, e.message.block);
            if self.lose_first && !retry && self.lost.insert(key) {
                return;
            }
        }
        let split = (from < 3) != (to < 3);
        let at = if split && now < self.partition_until {
            self.partition_until + 1 + (from + to) as u64 % 5
        } else {
            now + 1 + (from * 7 + to * 3) as u64 % 5
        };
        self.deliveries.push(Delivery { at, to, packet });
    }
    fn actions(&mut self, index: usize, actions: Vec<Action>, now: u64) {
        for action in actions {
            match action {
                Action::Broadcast(message) => {
                    self.broadcasts += 1;
                    let e = self.keys[index]
                        .sign(&self.config.chain, [index as u8; 32], message)
                        .unwrap();
                    self.retransmit.push((index, e.clone()));
                    for to in 0..7 {
                        self.queue(index, to, Packet::Evidence(e.clone()), now, false);
                    }
                }
                Action::ParentReady { slot, parent } => {
                    if self.config.leaders[(slot - 1) as usize][0] as usize != index
                        || !self.produced.insert(slot)
                        || self.disabled.contains(&index)
                    {
                        continue;
                    }
                    let mut parent = parent;
                    for s in slot..slot + self.config.window_size {
                        let candidate = self.candidate(s, parent, s as u8, &[s as u8; 19]);
                        parent = candidate.marker.block_commitment;
                        self.candidates.insert(parent, candidate.clone());
                        for to in 0..7 {
                            self.queue(
                                index,
                                to,
                                Packet::Block(Box::new(candidate.clone())),
                                now + (s - slot + 1) * self.config.block_time_ms,
                                false,
                            );
                        }
                    }
                }
                Action::Repair { block, .. } => {
                    self.repairs += 1;
                    if let Some(candidate) = self.candidates.get(&block).cloned() {
                        self.queue(index, index, Packet::Block(Box::new(candidate)), now, true);
                    }
                }
                _ => {}
            }
        }
    }
    fn run(&mut self, until: u64, restart_at: Option<(u64, usize)>) {
        for now in 0..=until {
            if restart_at.is_some_and(|(t, _)| t == now) {
                let index = restart_at.unwrap().1;
                let journal = self.nodes[index]
                    .as_ref()
                    .unwrap()
                    .recovery_journal()
                    .encode()
                    .unwrap();
                self.nodes[index] = Some(
                    Quantumglow::restore(
                        self.config.clone(),
                        [index as u8; 32],
                        self.validators.clone(),
                        RecoveryJournal::decode(&journal).unwrap(),
                    )
                    .unwrap(),
                );
            }
            for index in 0..7 {
                if self.disabled.contains(&index) {
                    continue;
                }
                let actions = self.nodes[index].as_mut().unwrap().tick(now).unwrap();
                self.actions(index, actions, now);
            }
            while let Some(position) = self.deliveries.iter().position(|d| d.at <= now) {
                let delivery = self.deliveries.swap_remove(position);
                if self.disabled.contains(&delivery.to) {
                    continue;
                }
                let node = self.nodes[delivery.to].as_mut().unwrap();
                let actions = match delivery.packet {
                    Packet::Evidence(e) => node.receive(e, now),
                    Packet::Block(c) => node.observe_block(c.marker, c.shreds, now),
                }
                .unwrap();
                self.actions(delivery.to, actions, now);
            }
            if now % 25 == 0 {
                for (from, e) in self.retransmit.clone() {
                    for to in 0..7 {
                        self.queue(from, to, Packet::Evidence(e.clone()), now, true);
                    }
                }
            }
        }
    }
    fn assert_agreement(&self, minimum_finalized: usize) {
        let chains: Vec<_> = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(i, _)| !self.disabled.contains(i))
            .map(|(_, n)| n.as_ref().unwrap().finalized_chain())
            .collect();
        for a in &chains {
            for b in &chains {
                let common = a.len().min(b.len());
                assert_eq!(a[..common], b[..common]);
            }
        }
        for chain in chains {
            assert!(
                chain.len() > minimum_finalized,
                "finalized only {} blocks",
                chain.len() - 1
            );
        }
    }
}

#[test]
fn live_authenticated_candidates_bind_leader_roles_and_replay_raw_witnesses() {
    let network = Network::new(4, 2, vec![0, 0, 1, 1]);
    let candidate = network.candidate(
        1,
        network.config.finalized_anchor.hash,
        31,
        b"verified payload",
    );
    let mut assembler = CandidateAssembler::new(
        network.config.chain,
        network.leaders[0].public_key(),
        1,
        1,
        [31; 48],
        network.config.finalized_anchor.hash,
    );
    for shred in &candidate.shreds {
        assembler.insert(shred.clone()).unwrap();
    }
    let verified = assembler.finish_verified(candidate.marker.clone()).unwrap();
    let mut machine =
        Quantumglow::new(network.config.clone(), [0; 32], network.validators.clone()).unwrap();
    machine.tick(0).unwrap();
    let actions = machine.observe_verified(verified.clone(), 1).unwrap();
    assert!(actions.iter().any(
        |action| matches!(action,Action::Broadcast(message) if message.kind==MessageKind::NotarVote)
    ));
    let encoded = machine.recovery_journal().encode().unwrap();
    let restored = Quantumglow::restore(
        network.config.clone(),
        [0; 32],
        network.validators.clone(),
        RecoveryJournal::decode(&encoded).unwrap(),
    )
    .unwrap();
    assert_eq!(
        restored.payload(&candidate.marker.block_commitment),
        Some(b"verified payload".as_slice())
    );
    let mut corrupt = encoded;
    *corrupt.last_mut().unwrap() ^= 1;
    let journal = RecoveryJournal::decode(&corrupt).unwrap();
    assert!(matches!(
        Quantumglow::restore(
            network.config.clone(),
            [0; 32],
            network.validators.clone(),
            journal
        ),
        Err(Error::BlockAuthentication)
    ));
    let mut changed = network.config.clone();
    changed
        .leader_keys
        .insert([0; 32], network.leaders[1].public_key());
    let mut wrong_role = Quantumglow::new(changed, [0; 32], network.validators.clone()).unwrap();
    assert!(matches!(
        wrong_role.observe_verified(verified, 1),
        Err(Error::BlockAuthentication)
    ));
    let invalid = network.candidate(
        1,
        network.config.finalized_anchor.hash,
        32,
        b"invalid execution",
    );
    let mut assembler = CandidateAssembler::new(
        network.config.chain,
        network.leaders[0].public_key(),
        1,
        1,
        [32; 48],
        network.config.finalized_anchor.hash,
    );
    for shred in invalid.shreds {
        assembler.insert(shred).unwrap();
    }
    let verified = assembler.finish_verified(invalid.marker).unwrap();
    let mut invalid_machine =
        Quantumglow::new(network.config, [0; 32], network.validators).unwrap();
    assert!(matches!(
        invalid_machine.observe_verified(verified, 1),
        Err(Error::InvalidExecution)
    ));
}

#[test]
fn fast_and_slow_network_finality_with_restart_and_transient_loss() {
    let mut fast = Network::new(6, 2, vec![0, 0, 1, 1, 2, 2]);
    fast.run(120, Some((20, 3)));
    fast.assert_agreement(6);
    assert!(fast.broadcasts > 42);
    let mut slow = Network::new(6, 2, vec![0, 0, 1, 1, 2, 2]);
    // One Byzantine withholding validator and one crash: each 1/7 < 20%.
    slow.disabled.extend([5, 6]);
    slow.lose_first = true;
    slow.run(350, Some((90, 3)));
    slow.assert_agreement(2); // eventual synchrony, with possible early skipped windows
    assert!(slow.nodes[0].as_ref().unwrap().pool().has_certificate(
        1,
        crate::consensus::CertificateKind::Finalization,
        None,
        false
    ));
}

#[test]
fn partition_and_withholding_leader_recover_in_a_later_correct_window() {
    let mut net = Network::new(8, 2, vec![6, 6, 0, 0, 1, 1, 2, 2]);
    net.disabled.insert(6);
    net.partition_until = 65;
    net.run(300, Some((80, 4)));
    net.assert_agreement(2);
    assert!(net.nodes[0].as_ref().unwrap().pool().has_certificate(
        1,
        crate::consensus::CertificateKind::Skip,
        None,
        true
    ));
    assert!(net.nodes[0].as_ref().unwrap().pool().has_certificate(
        2,
        crate::consensus::CertificateKind::Skip,
        None,
        true
    ));
}

#[test]
fn equivocated_leader_blocks_use_fallbacks_and_repair_before_advancing() {
    let mut net = Network::new(4, 2, vec![6, 6, 0, 0]);
    // The Byzantine leader signs two valid candidates, delivered to 3 + 3 correct nodes.
    net.disabled.insert(6);
    net.produced.insert(1);
    let a = net.candidate(1, net.config.finalized_anchor.hash, 77, b"fork a");
    let b = net.candidate(1, net.config.finalized_anchor.hash, 78, b"fork b");
    net.candidates.insert(a.marker.block_commitment, a.clone());
    net.candidates.insert(b.marker.block_commitment, b.clone());
    for to in 0..6 {
        net.queue(
            6,
            to,
            Packet::Block(Box::new(if to < 3 { a.clone() } else { b.clone() })),
            0,
            false,
        );
    }
    net.run(250, Some((30, 1)));
    net.assert_agreement(1);
    assert!(net.repairs > 0);
    for node in net.nodes.iter().take(6) {
        assert!(
            node.as_ref()
                .unwrap()
                .pool()
                .retained_evidence(1)
                .iter()
                .any(|e| e.message.kind == MessageKind::NotarFallbackVote)
        );
        assert!(
            node.as_ref()
                .unwrap()
                .pool()
                .retained_evidence(1)
                .iter()
                .any(|e| e.message.kind == MessageKind::SkipFallbackVote)
        );
        assert_eq!(node.as_ref().unwrap().pool().finalized(1), None);
    }
}

#[test]
fn malformed_blocks_forged_evidence_clock_rollback_and_stale_epoch_are_rejected() {
    let mut net = Network::new(2, 2, vec![0, 0]);
    let invalid = net.candidate(
        1,
        net.config.finalized_anchor.hash,
        22,
        b"invalid execution",
    );
    assert_eq!(
        net.nodes[0]
            .as_mut()
            .unwrap()
            .observe_block(invalid.marker, invalid.shreds, 0),
        Err(Error::InvalidExecution)
    );
    assert!(
        net.nodes[0]
            .as_ref()
            .unwrap()
            .pool()
            .retained_evidence(1)
            .is_empty()
    );
    let c = net.candidate(1, net.config.finalized_anchor.hash, 1, b"valid");
    let mut malformed = c.clone();
    malformed.shreds[0].payload[0] ^= 1;
    assert_eq!(
        net.nodes[0]
            .as_mut()
            .unwrap()
            .observe_block(malformed.marker, malformed.shreds, 0),
        Err(Error::BlockAuthentication)
    );
    let actions = net.nodes[0]
        .as_mut()
        .unwrap()
        .observe_block(c.marker, c.shreds, 0)
        .unwrap();
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::Broadcast(m) if m.kind == MessageKind::NotarVote))
    );
    let mut evidence = net.keys[1]
        .sign(
            &net.config.chain,
            [1; 32],
            ConsensusMessage {
                epoch: 1,
                slot: 1,
                kind: MessageKind::SkipVote,
                block: None,
            },
        )
        .unwrap();
    evidence.signature[0] ^= 1;
    assert!(net.nodes[0].as_mut().unwrap().receive(evidence, 1).is_err());
    net.nodes[0].as_mut().unwrap().tick(5).unwrap();
    assert_eq!(net.nodes[0].as_mut().unwrap().tick(4), Err(Error::Clock));
    let mut stale = net.keys[2]
        .sign(
            &net.config.chain,
            [2; 32],
            ConsensusMessage {
                epoch: 1,
                slot: 1,
                kind: MessageKind::SkipVote,
                block: None,
            },
        )
        .unwrap();
    stale.message.epoch = 0;
    assert!(net.nodes[0].as_mut().unwrap().receive(stale, 5).is_err());
    let journal = net.nodes[0]
        .as_ref()
        .unwrap()
        .recovery_journal()
        .encode()
        .unwrap();
    let mut wrong = net.config.clone();
    wrong.block_time_ms += 1;
    assert!(matches!(
        Quantumglow::restore(
            wrong,
            [0; 32],
            net.validators.clone(),
            RecoveryJournal::decode(&journal).unwrap()
        ),
        Err(Error::Journal)
    ));
    let mut trailing = journal;
    trailing.push(0);
    assert!(RecoveryJournal::decode(&trailing).is_err());
}

#[test]
fn strong_parent_and_initial_vote_legality_are_required() {
    let mut net = Network::new(4, 2, vec![0, 0, 1, 1]);
    let a = net.candidate(1, net.config.finalized_anchor.hash, 1, b"first");
    let b = net.candidate(2, a.marker.block_commitment, 2, b"second");
    // Out-of-order block stays pending, then notarizes only after its parent vote.
    let acts = net.nodes[0]
        .as_mut()
        .unwrap()
        .observe_block(b.marker.clone(), b.shreds.clone(), 0)
        .unwrap();
    assert!(!acts.iter().any(|a| matches!(a, Action::Broadcast(_))));
    let acts = net.nodes[0]
        .as_mut()
        .unwrap()
        .observe_block(a.marker.clone(), a.shreds.clone(), 1)
        .unwrap();
    let votes: Vec<_> = acts
        .iter()
        .filter_map(|a| {
            if let Action::Broadcast(m) = a {
                Some(m.slot)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(votes, vec![1, 2]);
    // A weak certificate must not authorize ParentReady for the next window.
    for i in 0..5 {
        let e = net.keys[i]
            .sign(
                &net.config.chain,
                [i as u8; 32],
                ConsensusMessage {
                    epoch: 1,
                    slot: 2,
                    kind: MessageKind::NotarVote,
                    block: Some(b.marker.block_commitment),
                },
            )
            .unwrap();
        let acts = net.nodes[0].as_mut().unwrap().receive(e, 2).unwrap();
        assert!(
            !acts
                .iter()
                .any(|a| matches!(a, Action::ParentReady { slot: 3, .. }))
        );
    }
    for i in 0..5 {
        let e = net.keys[i]
            .sign(
                &net.config.chain,
                [i as u8; 32],
                ConsensusMessage {
                    epoch: 1,
                    slot: 2,
                    kind: MessageKind::NotarApproval,
                    block: Some(b.marker.block_commitment),
                },
            )
            .unwrap();
        let acts = net.nodes[0].as_mut().unwrap().receive(e, 3).unwrap();
        if i == 4 {
            assert!(
                acts.iter()
                    .any(|a| matches!(a, Action::ParentReady { slot: 3, .. }))
            );
        }
    }
}

#[test]
fn epoch_transition_requires_finalized_exact_next_configuration() {
    let mut net = Network::new(2, 2, vec![0, 0]);
    let mut next = net.config.clone();
    next.epoch = 2;
    next.first_slot = 3;
    let next_keys: Vec<_> = (0..7)
        .map(|i| ConsensusKeypair::generate_for(next.chain, [i; 32], 2, 3, 2).unwrap())
        .collect();
    let next_validators: Vec<_> = next_keys
        .iter()
        .enumerate()
        .map(|(i, k)| Validator {
            id: [i as u8; 32],
            stake: 1,
            key: k.public_key(),
        })
        .collect();
    let next_pool =
        ConsensusPool::new(next.chain, next.epoch, next_validators.clone(), 3, 2).unwrap();
    let commitment = epoch_configuration_commitment(&next, &next_pool.validator_set_commitment());
    let a = net.candidate(1, net.config.finalized_anchor.hash, 1, b"parent");
    let b = net.candidate(2, a.marker.block_commitment, 2, &commitment);
    net.produced.insert(1);
    net.candidates.insert(a.marker.block_commitment, a.clone());
    net.candidates.insert(b.marker.block_commitment, b.clone());
    for to in 0..7 {
        net.queue(0, to, Packet::Block(Box::new(a.clone())), 0, false);
        net.queue(0, to, Packet::Block(Box::new(b.clone())), 6, false);
    }
    net.run(100, None);
    net.assert_agreement(2);
    next.finalized_anchor = BlockRef {
        slot: 2,
        hash: b.marker.block_commitment,
    };
    let old = net.nodes[0].take().unwrap();
    let (mut fresh, startup) = old.transition(next, next_validators, 101).unwrap();
    assert!(
        startup
            .iter()
            .any(|a| matches!(a, Action::ParentReady { slot: 3, .. }))
    );
    let stale = net.keys[0]
        .sign(
            &net.config.chain,
            [0; 32],
            ConsensusMessage {
                epoch: 1,
                slot: 2,
                kind: MessageKind::FinalVote,
                block: None,
            },
        )
        .unwrap();
    assert!(fresh.receive(stale, 102).is_err());
    assert_eq!(
        fresh.finalized_chain(),
        &[BlockRef {
            slot: 2,
            hash: b.marker.block_commitment
        }]
    );
}

#[test]
fn minority_notar_fallback_waits_for_repaired_block_and_parent_certificate() {
    let mut net = Network::new(2, 2, vec![0, 0]);
    net.nodes[0].as_mut().unwrap().tick(0).unwrap();
    net.nodes[0].as_mut().unwrap().tick(45).unwrap(); // skips the complete window
    let a = net.candidate(1, net.config.finalized_anchor.hash, 11, b"parent");
    let b = net.candidate(2, a.marker.block_commitment, 12, b"child");
    for i in 0..3 {
        let e = net.keys[i]
            .sign(
                &net.config.chain,
                [i as u8; 32],
                ConsensusMessage {
                    epoch: 1,
                    slot: 2,
                    kind: MessageKind::SkipVote,
                    block: None,
                },
            )
            .unwrap();
        net.nodes[0].as_mut().unwrap().receive(e, 46).unwrap();
    }
    for i in 3..5 {
        let e = net.keys[i]
            .sign(
                &net.config.chain,
                [i as u8; 32],
                ConsensusMessage {
                    epoch: 1,
                    slot: 2,
                    kind: MessageKind::NotarVote,
                    block: Some(b.marker.block_commitment),
                },
            )
            .unwrap();
        let actions = net.nodes[0].as_mut().unwrap().receive(e, 47).unwrap();
        assert!(!actions.iter().any(
            |a| matches!(a, Action::Broadcast(m) if m.kind == MessageKind::NotarFallbackVote)
        ));
    }
    // 2/7 notar <40%, but notar >=20% and 3/7 skip + 2/7 notar >=60%.
    // Neither the threshold alone nor authenticated child data is sufficient.
    let actions = net.nodes[0]
        .as_mut()
        .unwrap()
        .observe_block(b.marker.clone(), b.shreds, 48)
        .unwrap();
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::Broadcast(m) if m.kind == MessageKind::NotarFallbackVote))
    );
    net.nodes[0]
        .as_mut()
        .unwrap()
        .observe_block(a.marker.clone(), a.shreds, 49)
        .unwrap();
    for i in 0..5 {
        let e = net.keys[i]
            .sign(
                &net.config.chain,
                [i as u8; 32],
                ConsensusMessage {
                    epoch: 1,
                    slot: 1,
                    kind: MessageKind::NotarFallbackVote,
                    block: Some(a.marker.block_commitment),
                },
            )
            .unwrap();
        let actions = net.nodes[0].as_mut().unwrap().receive(e, 50).unwrap();
        assert_eq!(actions.iter().any(|a| matches!(a, Action::Broadcast(m) if m.kind == MessageKind::NotarFallbackVote && m.slot == 2)), i == 4);
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::Broadcast(m) if m.kind == MessageKind::FinalVote))
        );
    }
}

#[test]
fn epoch_transition_with_a_skipped_suffix_starts_from_the_finalized_ancestor() {
    let mut net = Network::new(4, 2, vec![0, 0, 6, 6]);
    net.disabled.insert(6);
    let mut next = net.config.clone();
    next.epoch = 2;
    next.first_slot = 5;
    next.slot_count = 2;
    next.leaders = vec![[0; 32]; 2];
    let keys: Vec<_> = (0..7)
        .map(|i| ConsensusKeypair::generate_for(next.chain, [i; 32], 2, 5, 2).unwrap())
        .collect();
    let validators: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| Validator {
            id: [i as u8; 32],
            stake: 1,
            key: k.public_key(),
        })
        .collect();
    let pool = ConsensusPool::new(next.chain, 2, validators.clone(), 5, 2).unwrap();
    let payload = epoch_configuration_commitment(&next, &pool.validator_set_commitment());
    let a = net.candidate(1, net.config.finalized_anchor.hash, 1, b"first");
    let b = net.candidate(2, a.marker.block_commitment, 2, &payload);
    net.produced.insert(1);
    net.candidates.insert(a.marker.block_commitment, a.clone());
    net.candidates.insert(b.marker.block_commitment, b.clone());
    for to in 0..6 {
        net.queue(0, to, Packet::Block(Box::new(a.clone())), 0, false);
        net.queue(0, to, Packet::Block(Box::new(b.clone())), 6, false);
    }
    net.run(150, None);
    net.assert_agreement(2);
    next.finalized_anchor = BlockRef {
        slot: 2,
        hash: b.marker.block_commitment,
    };
    let old = net.nodes[0].take().unwrap();
    let (mut fresh, startup) = old.transition(next, validators, 151).unwrap();
    assert!(
        startup
            .iter()
            .any(|a| matches!(a, Action::ParentReady { slot: 5, .. }))
    );
    let first = net.candidate(1, b.marker.block_commitment, 99, b"next epoch placeholder");
    // A wrong epoch candidate cannot reinterpret the skipped old slots.
    assert_eq!(
        fresh.observe_block(first.marker, first.shreds, 152),
        Err(Error::BlockAuthentication)
    );
    assert_eq!(fresh.config().first_slot, 5);
    let actions = fresh.tick(196).unwrap();
    assert!(actions.iter().any(
        |a| matches!(a, Action::Broadcast(m) if m.kind == MessageKind::SkipVote && m.slot == 5)
    ));
}
