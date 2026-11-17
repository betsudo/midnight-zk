use crate::types::AssignedNative;
use ff::PrimeField;
use midnight_proofs::circuit::Region;
use midnight_proofs::plonk::Error;
use crate::types::blake2b_word::AssignedBlake2bWord;
use crate::types::row::AssignedRow;

/// Enforces the output and key sizes.
/// Output size must be between 1 and 64 bytes.
/// Key size must be between 0 and 64 bytes.
pub(crate) fn enforce_input_sizes(output_size: usize, key_size: usize) {
    assert!(output_size <= 64, "Output size must be between 1 and 64 bytes");
    assert!(output_size > 0, "Output size must be between 1 and 64 bytes");
    assert!(key_size <= 64, "Key size must be between 1 and 64 bytes");
}

/// Extracts the full number cell of each of the state rows
pub(crate) fn full_number_of_each_state_row<F: PrimeField>(
    current_block_rows: [AssignedRow<F>; 16],
) -> [AssignedBlake2bWord<F>; 16] {
    current_block_rows
        .iter()
        .map(|row| row.full_number.clone())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// The 'processed_bytes_count' is a variable in the algorithm that changes with every iteration,
/// in each iteration we compute the new value for it.
pub(crate) fn compute_processed_bytes_count_value_for_iteration(
    iteration: usize,
    is_last_block: bool,
    input_size: usize,
    empty_key: bool,
) -> u64 {
    let processed_bytes_count = if is_last_block {
        input_size + if empty_key { 0 } else { 128 }
    } else {
        128 * (iteration + 1)
    };

    processed_bytes_count as u64
}

/// This function will return 0 in most cases, except in 3 opportunities:
/// 1 - In the "key block": the first block (if there's a key)
/// 2 - In the last block, if the input length in bytes isn't a multiple of 128
/// 3 - If the input and key are empty, the algorithm will compute a single block of 128 zeros
pub(crate) fn zeros_to_pad_in_current_block<F: PrimeField>(
    key: &[AssignedNative<F>],
    input_size: usize,
    is_last_block: bool,
    is_key_block: bool,
) -> usize {
    if is_last_block && !is_key_block {
        if input_size == 0 {
            // Border case, the input and the key are empty
            128
        } else {
            // Last block, need to complete the block with zeroes
            (BLAKE2B_BLOCK_SIZE - input_size % BLAKE2B_BLOCK_SIZE) % BLAKE2B_BLOCK_SIZE
        }
    } else if is_key_block {
        // First block when there's a key, need to complete the block with zeroes
        BLAKE2B_BLOCK_SIZE - key.len()
    } else {
        // Middle block, no need to pad anything
        0
    }
}

/// Computes the edge cases in the amount of blocks to process.
pub(crate) fn get_total_blocks_count(
    input_blocks: usize,
    is_input_empty: bool,
    is_key_empty: bool,
) -> usize {
    if is_key_empty {
        if is_input_empty {
            // If there's no input and no key, we still need to process one block of zeroes.
            1
        } else {
            input_blocks
        }
    } else if is_input_empty {
        // If there's no input but there's key, key is processed in the first and only block.
        1
    } else {
        // Key needs to be processed in a block alone, then come the input blocks.
        input_blocks + 1
    }
}

/// This method constrains the padding cells to equal zero. The amount of constraints
/// depends on the input size and the key size, which makes sense since those values are known
/// at circuit building time.
/// The idea is that since we decompose the state into 8 limbs, we already have the input
/// bytes in the trace. It's just a matter of iterating the cells in the correct order and knowing
/// which ones should equal zero. In Blake2b the padding is allways 0.
pub(crate) fn constrain_padding_cells_to_equal_zero<F: PrimeField>(
    region: &mut Region<'_, F>,
    zeros_amount: usize,
    current_block_rows: &[AssignedRow<F>; 16],
    zero_constant_cell: &AssignedNative<F>,
) -> Result<(), Error> {
    let mut constrained_padding_cells = 0;
    for row in (0..16).rev() {
        for limb in (0..8).rev() {
            if constrained_padding_cells < zeros_amount {
                region.constrain_equal(
                    current_block_rows[row].limbs[limb].cell(),
                    zero_constant_cell.cell(),
                )?;
                constrained_padding_cells += 1;
            }
        }
    }
    Ok(())
}

// ----- Blake2b constants -----

pub const BLAKE2B_BLOCK_SIZE: usize = 128;

pub const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// These are constants used for the mixing rounds:
/// In each round, Blake2b algorithm modifies 4 fixed components of the state.
/// The first round, these components are
/// state[0], state[4], state[8], state[12], the second round, they're
/// state[1], state[5], state[9], state[13], and so on.
pub const ABCD: [[usize; 4]; 8] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
];

pub const IV_CONSTANTS: [u64; 8] = [
    0x6A09E667F3BCC908u64,
    0xBB67AE8584CAA73Bu64,
    0x3C6EF372FE94F82Bu64,
    0xA54FF53A5F1D36F1u64,
    0x510E527FADE682D1u64,
    0x9B05688C2B3E6C1Fu64,
    0x1F83D9ABFB41BD6Bu64,
    0x5BE0CD19137E2179u64,
];
