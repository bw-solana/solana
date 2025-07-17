//! The `sigverify` module provides digital signature verification functions.
//! By default, signatures are verified in parallel using all available CPU
//! cores.  When perf-libs are available signature verification is offloaded
//! to the GPU.
//!

pub use solana_perf::sigverify::{
    count_packets_in_batches, ed25519_verify_cpu, ed25519_verify_disabled, init, TxOffset,
};
use {
    crate::{
        banking_stage::{consumer::Consumer, transaction_scheduler::receive_and_buffer::TransactionViewReceiveAndBuffer},
        banking_trace::BankingPacketSender,
        sigverify_stage::{SigVerifier, SigVerifier2, SigVerifyServiceError},
    },
    agave_banking_stage_ingress_types::BankingPacketBatch,
    crossbeam_channel::Sender,
    rayon::{prelude::*, ThreadPool},
    solana_perf::{cuda_runtime::PinnedVec, packet::PacketBatch, recycler::Recycler, sigverify::verify_packet},
    solana_rayon_threadlimit::get_thread_count,
    solana_runtime::bank_forks::BankForks,
    solana_runtime_transaction::runtime_transaction::RuntimeTransaction,
    solana_svm::transaction_error_metrics::TransactionErrorMetrics,
    std::sync::{Arc, RwLock},
};

static PAR_THREAD_POOL: std::sync::LazyLock<ThreadPool> = std::sync::LazyLock::new(|| {
    rayon::ThreadPoolBuilder::new()
        .num_threads(get_thread_count())
        .thread_name(|i| format!("solSigVerif2{i:02}"))
        .build()
        .unwrap()
});

pub struct TransactionSigVerifier {
    banking_stage_sender: BankingPacketSender,
    forward_stage_sender: Option<Sender<(BankingPacketBatch, bool)>>,
    #[allow(dead_code)]
    recycler: Recycler<TxOffset>,
    #[allow(dead_code)]
    recycler_out: Recycler<PinnedVec<u8>>,
    reject_non_vote: bool,
}

impl TransactionSigVerifier {
    pub fn new_reject_non_vote(
        packet_sender: BankingPacketSender,
        forward_stage_sender: Option<Sender<(BankingPacketBatch, bool)>>,
    ) -> Self {
        let mut new_self = Self::new(packet_sender, forward_stage_sender);
        new_self.reject_non_vote = true;
        new_self
    }

    pub fn new(
        banking_stage_sender: BankingPacketSender,
        forward_stage_sender: Option<Sender<(BankingPacketBatch, bool)>>,
    ) -> Self {
        init();
        Self {
            banking_stage_sender,
            forward_stage_sender,
            recycler: Recycler::warmed(50, 4096),
            recycler_out: Recycler::warmed(50, 4096),
            reject_non_vote: false,
        }
    }
}

pub fn ed25519_verify_cpu_4(batches: &mut [PacketBatch], reject_non_vote: bool) {
    PAR_THREAD_POOL.install(|| {
        batches.par_iter_mut().flatten().for_each(|mut packet| {
            if !packet.meta().discard() && !verify_packet(&mut packet, reject_non_vote) {
                packet.meta_mut().set_discard(true);
            }
        });
    });
}

pub fn ed25519_verify_cpu_3(batches: &mut [PacketBatch], reject_non_vote: bool, bank_forks: Arc<RwLock<BankForks>>) {
    let (working_bank, root_bank) = {
        let bank_forks = bank_forks.read().unwrap();
        (bank_forks.working_bank(), bank_forks.root_bank())
    };
    // Sanitize packets, generate IDs, and insert into the container.
    let alt_resolved_slot = root_bank.slot();
    let sanitized_epoch = root_bank.epoch();
    let transaction_account_lock_limit = working_bank.get_transaction_account_lock_limit();
    let mut txs = vec![];

    PAR_THREAD_POOL.install(|| {
        txs = batches.par_iter_mut().flatten().filter_map(|mut packet| {
            // Check if already marked for discard.
            if packet.meta().discard() {
                return None;
            }

            // Signature verification.
            if !verify_packet(&mut packet, reject_non_vote) {
                return None;
            }

            // Make sure we can grab the data region.
            let Some(packet_data) = packet.data(..) else {
                return None;
            };

            // Convert to Transaction View and sanitize.
            let bytes = Arc::new(packet_data.to_vec());
            let Ok(mut tx_view_state) = TransactionViewReceiveAndBuffer::try_handle_packet(
                bytes,
                &root_bank,
                &working_bank,
                alt_resolved_slot,
                sanitized_epoch,
                transaction_account_lock_limit,
            ) else {
                return None;
            };

            // Check age, status cache, and compute budgets.
            let lock_results: [_; 1] = core::array::from_fn(|_| Ok(()));
            let mut error_counters = TransactionErrorMetrics::default();
            let (transaction, _max_age) = tx_view_state.take_transaction_for_scheduling();
            let sanitized_txs = vec![transaction.clone()];
            let check_results = working_bank.check_transactions::<RuntimeTransaction<_>>(
                &sanitized_txs,
                &lock_results[..1],
                150,
                &mut error_counters,
            );
            if let Err(_err) = check_results.first().unwrap() {
                return None;
            }

            // Check for valid fee payer.
            if let Err(_err) = Consumer::check_fee_payer_unlocked(
                working_bank.as_ref(),
                &transaction,
                &mut error_counters,
            ) {
                return None;
            }

            Some(transaction)
        }).collect();
    });
}

impl SigVerifier for TransactionSigVerifier {
    type SendType = BankingPacketBatch;

    fn send_packets(
        &mut self,
        packet_batches: Vec<PacketBatch>,
    ) -> Result<(), SigVerifyServiceError<Self::SendType>> {
        let banking_packet_batch = BankingPacketBatch::new(packet_batches);
        if let Some(forward_stage_sender) = &self.forward_stage_sender {
            self.banking_stage_sender
                .send(banking_packet_batch.clone())?;
            let _ = forward_stage_sender.try_send((banking_packet_batch, self.reject_non_vote));
        } else {
            self.banking_stage_sender.send(banking_packet_batch)?;
        }

        Ok(())
    }

    fn verify_batches(
        &self,
        mut batches: Vec<PacketBatch>,
        _valid_packets: usize,
    ) -> Vec<PacketBatch> {
        ed25519_verify_cpu_4(
            &mut batches,
            self.reject_non_vote,
        );
        batches
    }
}

impl SigVerifier2 for TransactionSigVerifier {
    type SendType = BankingPacketBatch;

    fn send_packets(
        &mut self,
        packet_batches: Vec<PacketBatch>,
    ) -> Result<(), SigVerifyServiceError<Self::SendType>> {
        let banking_packet_batch = BankingPacketBatch::new(packet_batches);
        if let Some(forward_stage_sender) = &self.forward_stage_sender {
            self.banking_stage_sender
                .send(banking_packet_batch.clone())?;
            let _ = forward_stage_sender.try_send((banking_packet_batch, self.reject_non_vote));
        } else {
            self.banking_stage_sender.send(banking_packet_batch)?;
        }

        Ok(())
    }

    fn verify_batches(
        &self,
        mut batches: Vec<PacketBatch>,
        _valid_packets: usize,
        bank_forks: Arc<RwLock<BankForks>>,
    ) -> Vec<PacketBatch> {
        ed25519_verify_cpu_3(
            &mut batches,
            self.reject_non_vote,
            bank_forks,
        );
        batches
    }
}
