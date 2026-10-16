/* Real SBPF workload: program state, multisig authorities and PDA/System CPI. */
#include <solana_sdk.h>

#define STATE_BYTES 128
#define BAD_STATE 7001
#define BAD_AUTHORITY 7002
#define BAD_ESCROW 7003
#define BAD_SEQUENCE 7004
#define EXPECTED_ROLLBACK 7005
#define BAD_OWNER 7006

static uint64_t read_u64(const uint8_t *bytes) {
  uint64_t result = 0;
  for (uint64_t i = 0; i < 8; i++) result |= ((uint64_t)bytes[i]) << (8 * i);
  return result;
}

static void write_u64(uint8_t *bytes, uint64_t value) {
  for (uint64_t i = 0; i < 8; i++) bytes[i] = (uint8_t)(value >> (8 * i));
}

extern uint64_t entrypoint(const uint8_t *input) {
  SolAccountInfo accounts[7];
  SolParameters params = {.ka = accounts};
  if (!sol_deserialize(input, &params, SOL_ARRAY_SIZE(accounts)))
    return ERROR_INVALID_ARGUMENT;
  if (params.data_len == 17 && params.data[0] == 0 && params.ka_num == 0)
    return SUCCESS; /* Signed source/counter nonce, genuine VM execution. */
  if (params.ka_num != 7 || params.data_len < 17) return ERROR_INVALID_ARGUMENT;
  const uint8_t operation = params.data[0];
  const uint64_t amount = read_u64(params.data + 1);
  const uint64_t sequence = read_u64(params.data + 9);
  SolAccountInfo *state = &accounts[0];
  const SolPubkey system = {{0}};
  if (!SolPubkey_same(state->owner, params.program_id)) return BAD_OWNER;
  if (state->data_len < STATE_BYTES || !state->is_writable ||
      sol_memcmp(state->data, "PQVAULT1", 8) != 0) return BAD_STATE;
  if (!accounts[1].is_signer ||
      !SolPubkey_same(accounts[1].key, (const SolPubkey *)(state->data + 8)))
    return BAD_AUTHORITY;
  if ((operation == 3 || operation == 4 || operation == 5) &&
      (!accounts[2].is_signer ||
       !SolPubkey_same(accounts[2].key, (const SolPubkey *)(state->data + 40))))
    return BAD_AUTHORITY;
  if (!accounts[5].is_signer || !SolPubkey_same(accounts[6].key, &system))
    return BAD_AUTHORITY;
  if (sequence <= read_u64(state->data + 72) ||
      read_u64(state->data + 80) == UINT64_MAX) return BAD_SEQUENCE;
  if (operation == 5) {
    if (params.data_len != 81) return ERROR_INVALID_ARGUMENT;
    sol_memcpy(state->data + 8, params.data + 17, 64);
    write_u64(state->data + 72, sequence);
    write_u64(state->data + 80, read_u64(state->data + 80) + 1);
    write_u64(state->data + 104, read_u64(state->data + 104) + 1);
    return SUCCESS;
  }
  if (params.data_len != 17 || operation < 1 || operation > 4)
    return ERROR_INVALID_ARGUMENT;

  SolPubkey expected_escrow;
  uint8_t bump = 0;
  SolSignerSeed seeds[3] = {
    {(const uint8_t *)"escrow", 6}, {state->key->x, 32}, {&bump, 1}
  };
  if (sol_try_find_program_address(seeds, 2, params.program_id,
                                  &expected_escrow, &bump) != SUCCESS ||
      !SolPubkey_same(accounts[3].key, &expected_escrow)) return BAD_ESCROW;
  if (!SolPubkey_same(accounts[3].owner, &system) || accounts[3].data_len != 0)
    return BAD_OWNER;
  const SolSignerSeeds signer = {seeds, 3};
  uint8_t cpi_data[52] = {0};
  SolAccountMeta metas[2];
  SolInstruction cpi = {
    .program_id = accounts[6].key, .accounts = metas,
    .account_len = 2, .data = cpi_data, .data_len = 12
  };
  if (operation == 1) {
    if (read_u64(state->data + 120) != 0) return BAD_STATE;
    write_u64(cpi_data + 4, amount); /* System CreateAccount, enum zero. */
    cpi.data_len = 52;
    metas[0] = (SolAccountMeta){accounts[5].key, true, true};
    metas[1] = (SolAccountMeta){accounts[3].key, true, true};
  } else {
    if (read_u64(state->data + 120) != 1) return BAD_STATE;
    cpi_data[0] = 2; /* System Transfer. */
    write_u64(cpi_data + 4, amount);
    metas[0] = (SolAccountMeta){accounts[operation == 2 ? 5 : 3].key, true, true};
    metas[1] = (SolAccountMeta){accounts[operation == 2 ? 3 : 4].key, true, false};
  }
  /* Mutate before CPI: failures must roll this back along with any inner writes. */
  write_u64(state->data + 72, sequence);
  write_u64(state->data + 80, read_u64(state->data + 80) + 1);
  uint64_t result = sol_invoke_signed(&cpi, accounts, 7, &signer, 1);
  if (result != SUCCESS) return result;
  if (operation == 1) write_u64(state->data + 120, 1);
  if (operation == 2) {
    if (amount > UINT64_MAX - read_u64(state->data + 88)) return BAD_STATE;
    write_u64(state->data + 88, read_u64(state->data + 88) + amount);
  }
  if (operation == 3 || operation == 4) {
    if (amount > UINT64_MAX - read_u64(state->data + 96)) return BAD_STATE;
    write_u64(state->data + 96, read_u64(state->data + 96) + amount);
  }
  if (operation == 4) return EXPECTED_ROLLBACK;
  return SUCCESS;
}
