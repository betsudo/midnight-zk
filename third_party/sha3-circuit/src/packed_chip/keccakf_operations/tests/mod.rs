use ff::PrimeField;
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
};

use crate::{
    constants::{KECCAK_NUM_LANES, KECCAK_NUM_ROUNDS, KECCAK_WIDTH, RHO_ROTATAIONS, ROUND_CST},
    packed_chip::{keccakf_operations::types::AssignedKeccakState, PackedChip},
};

mod compute_keccak_step;
mod compute_keccakf;

impl<F: PrimeField> PackedChip<F> {
    /// Helper function to assign multiple keccak states.
    /// The inputs *are not rangechecked*.
    fn assign_states(
        &self,
        layouter: &mut impl Layouter<F>,
        inputs: &[KeccakState],
    ) -> Result<Vec<AssignedKeccakState<F>>, Error> {
        layouter.assign_region(
            || "assign keccak states",
            |mut region| {
                // for easy assignement get a vector of all lanes of all inputs
                let lanes = inputs.iter().flat_map(|state| state.inner).collect::<Vec<_>>();

                // assign state by assigning the spread bits
                let assigned_lanes = lanes
                    .iter()
                    .enumerate()
                    .map(|(i, &lane)| {
                        self.assign_spread_decomposition(&mut region, i, &Value::known(lane), 0)
                            .map(|x| x.assigned_result)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                // create the assigned keccack states
                Ok(assigned_lanes
                    .chunks(KECCAK_NUM_LANES)
                    .map(|lanes| AssignedKeccakState::from_lanes(lanes.try_into().unwrap()))
                    .collect::<Vec<_>>())
            },
        )
    }
}

// helper struct to represent (off-circuit) a keccak lane
#[derive(Clone, Debug, Default)]
struct KeccakState {
    inner: [u64; KECCAK_NUM_LANES],
}

impl KeccakState {
    pub(super) fn from_lanes(lanes: &[[u64; KECCAK_WIDTH]; KECCAK_WIDTH]) -> Self {
        let lanes = lanes.iter().flat_map(|&d| d).collect::<Vec<_>>();
        KeccakState {
            inner: lanes.try_into().unwrap(),
        }
    }
}
// helper functions to compute expected results. The results are returned as
// vectors

/// a[0][0] = a[0][0] ^ rc
fn compute_iota(state: &mut KeccakState, round: usize) {
    let rc = ROUND_CST[round];
    state.inner[0] ^= rc;
}

/// c[i] = xor_j [a[i][j]
fn compute_cs(state: &KeccakState) -> Vec<u64> {
    state
        .inner
        .chunks(KECCAK_WIDTH)
        .map(|row| row.iter().fold(0, |acc, x| acc ^ x))
        .collect()
}

/// rotc[i] = rotl(c[i], 1)
fn compute_rotcs(state: &KeccakState) -> Vec<u64> {
    compute_cs(state).iter().map(|x| x.rotate_left(1)).collect()
}

/// d[i] = c[i-1] xor rotc[i+1]
fn compute_ds(state: &KeccakState) -> Vec<u64> {
    let mut cs = compute_cs(state);
    let mut rot_cs = compute_rotcs(state);
    cs.rotate_right(1);
    rot_cs.rotate_left(1);
    cs.iter().zip(rot_cs.iter()).map(|(c, rotc)| c ^ rotc).collect()
}

/// theta: a[i][j] -> {a[i][j] ^ d[i]}_i,j
fn compute_theta(state: &mut KeccakState) {
    let ds = compute_ds(state);
    (0..KECCAK_NUM_LANES).for_each(|k| state.inner[k] ^= ds[k / KECCAK_WIDTH]);
}

/// rho: a[i][j] -> rotl(a[i][j], rot[i][j])
fn compute_rho(state: &mut KeccakState) {
    (0..KECCAK_NUM_LANES).for_each(|k| {
        let (i, j) = (k / KECCAK_WIDTH, k % KECCAK_WIDTH);
        let tmp = state.inner[k].rotate_left(RHO_ROTATAIONS[i][j] as u32);
        state.inner[k] = tmp;
    });
}

/// rho: a[j][2i+3j] -> a[i][j]
fn compute_pi(state: &mut KeccakState) {
    let old_state = state.clone();

    #[allow(clippy::needless_range_loop)]
    for j in 0..KECCAK_WIDTH {
        for i in 0..KECCAK_WIDTH {
            state.inner[j * KECCAK_WIDTH + ((2 * i + 3 * j) % KECCAK_WIDTH)] =
                old_state.inner[i * KECCAK_WIDTH + j];
        }
    }
}

/// chi: a[i][j] -> a[i][j] xor (not a[i+1][j] and a[i+2][j])
fn compute_chi(state: &mut KeccakState) {
    let old_state = state.clone();

    #[allow(clippy::needless_range_loop)]
    for i in 0..KECCAK_WIDTH {
        for j in 0..KECCAK_WIDTH {
            state.inner[KECCAK_WIDTH * i + j] = old_state.inner[i * KECCAK_WIDTH + j]
                ^ (!old_state.inner[((i + 1) % KECCAK_WIDTH) * KECCAK_WIDTH + j]
                    & old_state.inner[((i + 2) % KECCAK_WIDTH) * KECCAK_WIDTH + j]);
        }
    }
}

/// a full keccak round
fn compute_round(state: &mut KeccakState, round: usize) {
    compute_theta(state);
    compute_rho(state);
    compute_pi(state);
    compute_chi(state);
    compute_iota(state, round);
}

/// a full keccak permutation
fn compute_keccakf(state: &mut KeccakState) {
    (0..KECCAK_NUM_ROUNDS).for_each(|r| compute_round(state, r))
}
