//! Genuine SBF application used by native migration and continuous-load tests.

use {
    solana_account::Account,
    solana_instruction::{AccountMeta, Instruction},
    solana_loader_v3_interface::state::UpgradeableLoaderState,
    solana_pubkey::Pubkey,
    solana_rent::Rent,
    solana_sdk_ids::{bpf_loader_upgradeable, system_program},
};

pub const PROGRAM_ID: Pubkey = Pubkey::new_from_array([0x55; 32]);
pub const STATE_BYTES: usize = 128;
pub const BAD_STATE: u32 = 7001;
pub const BAD_AUTHORITY: u32 = 7002;
pub const BAD_ESCROW: u32 = 7003;
pub const BAD_SEQUENCE: u32 = 7004;
pub const EXPECTED_ROLLBACK: u32 = 7005;
pub const BAD_OWNER: u32 = 7006;

pub fn program_elf() -> &'static [u8] {
    include_bytes!("../tests/fixtures/pq-svm/workload.so")
}

pub fn program_account(rent: &Rent) -> Account {
    let data = wincode::serialize(&UpgradeableLoaderState::Program {
        programdata_address: programdata_address(),
    })
    .unwrap();
    Account {
        lamports: rent.minimum_balance(data.len()),
        data,
        owner: bpf_loader_upgradeable::id(),
        executable: true,
        rent_epoch: u64::MAX,
    }
}

pub fn programdata_address() -> Pubkey {
    Pubkey::find_program_address(&[PROGRAM_ID.as_ref()], &bpf_loader_upgradeable::id()).0
}

/// Install both genuine immutable UpgradeableLoader accounts in genesis.
pub fn program_accounts(rent: &Rent) -> [(Pubkey, Account); 2] {
    let mut data = wincode::serialize(&UpgradeableLoaderState::ProgramData {
        slot: 0,
        upgrade_authority_address: None,
    })
    .unwrap();
    data.resize(UpgradeableLoaderState::size_of_programdata_metadata(), 0);
    data.extend_from_slice(program_elf());
    [
        (PROGRAM_ID, program_account(rent)),
        (
            programdata_address(),
            Account {
                lamports: rent.minimum_balance(data.len()),
                data,
                owner: bpf_loader_upgradeable::id(),
                executable: false,
                rent_epoch: u64::MAX,
            },
        ),
    ]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub primary: Pubkey,
    pub secondary: Pubkey,
    pub last_sequence: u64,
    pub operations: u64,
    pub deposited: u64,
    pub withdrawn: u64,
    pub rotations: u64,
    pub initialized: bool,
}

impl State {
    pub fn new(primary: Pubkey, secondary: Pubkey) -> Self {
        Self {
            primary,
            secondary,
            last_sequence: 0,
            operations: 0,
            deposited: 0,
            withdrawn: 0,
            rotations: 0,
            initialized: false,
        }
    }

    pub fn encode(&self, data_bytes: usize) -> Vec<u8> {
        assert!(data_bytes >= STATE_BYTES);
        let mut data = vec![0; data_bytes];
        data[..8].copy_from_slice(b"PQVAULT1");
        data[8..40].copy_from_slice(self.primary.as_ref());
        data[40..72].copy_from_slice(self.secondary.as_ref());
        for (offset, value) in [
            (72, self.last_sequence),
            (80, self.operations),
            (88, self.deposited),
            (96, self.withdrawn),
            (104, self.rotations),
            (120, u64::from(self.initialized)),
        ] {
            data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        data
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < STATE_BYTES || &data[..8] != b"PQVAULT1" {
            return None;
        }
        let read = |offset| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        let initialized = read(120);
        if initialized > 1 {
            return None;
        }
        Some(Self {
            primary: Pubkey::new_from_array(data[8..40].try_into().unwrap()),
            secondary: Pubkey::new_from_array(data[40..72].try_into().unwrap()),
            last_sequence: read(72),
            operations: read(80),
            deposited: read(88),
            withdrawn: read(96),
            rotations: read(104),
            initialized: initialized == 1,
        })
    }
}

pub fn escrow_address(state: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"escrow", state.as_ref()], &PROGRAM_ID).0
}

/// Genuine VM execution with no account writes; gives load transactions a
/// canonical source/counter nonce without changing fees or compute limits.
pub fn nonce_instruction(source: u64, counter: u64) -> Instruction {
    let mut data = vec![0];
    data.extend_from_slice(&source.to_le_bytes());
    data.extend_from_slice(&counter.to_le_bytes());
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![],
        data,
    }
}

#[derive(Clone, Copy)]
pub struct Accounts {
    pub state: Pubkey,
    pub primary: Pubkey,
    pub secondary: Pubkey,
    pub sponsor: Pubkey,
    pub recipient: Pubkey,
}

impl Accounts {
    fn instruction(self, operation: u8, amount: u64, sequence: u64) -> Instruction {
        let mut data = vec![operation];
        data.extend_from_slice(&amount.to_le_bytes());
        data.extend_from_slice(&sequence.to_le_bytes());
        Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(self.state, false),
                AccountMeta::new_readonly(self.primary, true),
                AccountMeta::new_readonly(self.secondary, operation >= 3),
                AccountMeta::new(escrow_address(&self.state), false),
                AccountMeta::new(self.recipient, false),
                AccountMeta::new(self.sponsor, true),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        }
    }

    pub fn initialize(self, rent_lamports: u64, sequence: u64) -> Instruction {
        self.instruction(1, rent_lamports, sequence)
    }

    pub fn deposit(self, amount: u64, sequence: u64) -> Instruction {
        self.instruction(2, amount, sequence)
    }

    pub fn withdraw(self, amount: u64, sequence: u64) -> Instruction {
        self.instruction(3, amount, sequence)
    }

    pub fn failed_withdraw(self, amount: u64, sequence: u64) -> Instruction {
        self.instruction(4, amount, sequence)
    }

    pub fn rotate(self, primary: Pubkey, secondary: Pubkey, sequence: u64) -> Instruction {
        let mut instruction = self.instruction(5, 0, sequence);
        instruction.data.extend_from_slice(primary.as_ref());
        instruction.data.extend_from_slice(secondary.as_ref());
        instruction
    }
}
