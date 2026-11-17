//! Types and operation that are usefull for computing in-circuit the Keccak-f
//! permutation

use ff::PrimeField;
use midnight_proofs::circuit::Value;

use crate::{
    constants::{KECCAK_ABSORB_LANES, KECCAK_NUM_LANES, KECCAK_WIDTH},
    packed_chip::utils::{AssignedSpreadBits, SpreadBits},
};

/// Struct representing the state of the Keccak permutation in spread form
#[derive(Clone, Debug, Default)]
pub(super) struct KeccakState {
    pub(super) inner: [[Value<SpreadBits>; KECCAK_WIDTH]; KECCAK_WIDTH],
}

impl KeccakState {
    /// Creates a state from a reference of an array slice of spread bits.
    /// The (i,j)-th element is created as lanes[5 * i + j].
    fn from_lanes(lanes: &[Value<SpreadBits>; KECCAK_NUM_LANES]) -> Self {
        let inner: [[Value<SpreadBits>; KECCAK_WIDTH]; KECCAK_WIDTH] = lanes
            .chunks(KECCAK_WIDTH)
            .map(|lane| {
                // Covert the slice to an array.
                // Does not panic since we take KECCAK_WIDTH-sized lanes
                let res: [Value<SpreadBits>; KECCAK_WIDTH] = lane.to_vec().try_into().unwrap();
                res
            })
            // Convert the outer vector to an array.
            // Does not panic since we take KECCAK_WIDTH-sized lanes
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        KeccakState { inner }
    }
}

/// Struct representing an assigned Keccak state. This is the assigned variant
/// of [`KeccakState`].
#[derive(Clone, Debug)]
pub struct AssignedKeccakState<F: PrimeField> {
    pub(crate) inner: [[AssignedSpreadBits<F>; KECCAK_WIDTH]; KECCAK_WIDTH],
}

impl<F: PrimeField> AssignedKeccakState<F> {
    /// Access the inner value of the assigned state if it exists
    pub(super) fn value(&self) -> KeccakState {
        let lanes = self.inner.concat().iter().map(|x| x.value().cloned()).collect::<Vec<_>>();

        // never panics since we start from a KeccakState
        KeccakState::from_lanes(&lanes.try_into().unwrap())
    }

    /// Creates a state from a reference to an array of spread bits. The
    /// (i,j)-th element is created as lanes[5 * i + j].
    /// This is the same as the `from_lanes` for [`KeccakState`] but for
    /// assigned values.
    pub(super) fn from_lanes(lanes: &[AssignedSpreadBits<F>; KECCAK_NUM_LANES]) -> Self {
        let inner: [[AssignedSpreadBits<F>; KECCAK_WIDTH]; KECCAK_WIDTH] = lanes
            .chunks(KECCAK_WIDTH)
            .map(|lane| {
                let lane_vec = lane.to_vec();
                let res: [AssignedSpreadBits<F>; KECCAK_WIDTH] = lane_vec.try_into().unwrap();
                res
            })
            .collect::<Vec<_>>()
            // never panics due to the type system
            .try_into()
            .unwrap();

        AssignedKeccakState { inner }
    }
}

impl<F: PrimeField> AssignedKeccakState<F> {
    /// This operation is simply a permutation of the lanes. No in-circuit
    /// operations are needed. The permutation is given by the formula:
    /// new_state[j][2i + 3j] = state[i][j]
    pub(super) fn compute_pi(&self) -> AssignedKeccakState<F> {
        // this is done only to initialize the array
        let mut new_state = self.inner.clone();

        // it is cleaner in this case to use a double for loop
        #[allow(clippy::needless_range_loop)]
        for j in 0..KECCAK_WIDTH {
            for i in 0..KECCAK_WIDTH {
                new_state[j][(2 * i + 3 * j) % KECCAK_WIDTH] = self.inner[i][j].clone();
            }
        }
        AssignedKeccakState { inner: new_state }
    }
}

/// Struct representing the c values. The values are computed as
/// c[i] = a[i][0] + ... + a[i][4]. We also keep the left rotation of
/// cs for computing the D values later.
#[derive(Clone, Debug)]
pub(super) struct Cs {
    cs: [Value<SpreadBits>; KECCAK_WIDTH],
    rot_cs: [Value<SpreadBits>; KECCAK_WIDTH],
}

/// Assigned Variant of [`Cs`]
#[derive(Clone, Debug)]
pub(super) struct AssignedCs<F: PrimeField> {
    pub(super) cs: [AssignedSpreadBits<F>; KECCAK_WIDTH],
    pub(super) rot_cs: [AssignedSpreadBits<F>; KECCAK_WIDTH],
}

impl<F: PrimeField> AssignedCs<F> {
    /// Access the inner value of the [`AssignedCs`] if it exists
    pub(super) fn value(&self) -> Cs {
        let cs = self.cs.clone().map(|x| x.value().cloned());
        let rot_cs = self.rot_cs.clone().map(|x| x.value().cloned());
        Cs { cs, rot_cs }
    }
}

impl KeccakState {
    /// Adds the values a[i][0] + ... + a[i][4] to compute the spread
    /// form of c[i] *with error*.
    ///
    /// # NOTES
    ///
    /// This *does not* add the term from the IV of the previous round which is
    /// handled independently.
    pub(super) fn compute_cs_with_error(&self) -> [Value<SpreadBits>; KECCAK_WIDTH] {
        // add the spread values a[i][0]..a[i][5]
        self.inner
            .iter()
            .map(|row| {
                // instantiate with c[i] = a[i][0]
                let c0 = row[0].clone();
                // spread-add all the other values to c to get the result
                row.iter().skip(1).fold(c0, |acc, ci| {
                    acc.zip(ci.clone()).map(|(acc, ci)| acc.try_add(&ci).unwrap())
                })
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    /// Computes the new values a[i][j] = a[i][j] + c[x-1] + rotc[x+1].
    ///
    /// # NOTES
    ///
    /// This *does not* add the term from the IV of the previous round which is
    /// handled independently
    pub(super) fn compute_theta_with_error(&self, cs: Cs) -> KeccakState {
        // instantiate the state
        let mut new_state = KeccakState::default();
        for i in 0..KECCAK_WIDTH {
            // get the corresponding c and its rotation for i
            let c = &cs.cs[(i + KECCAK_WIDTH - 1) % KECCAK_WIDTH];
            let rotc = &cs.rot_cs[(i + 1) % KECCAK_WIDTH].clone();
            // update the (i,j)-th element by adding c, rotc
            for j in 0..KECCAK_WIDTH {
                let new_value = self.inner[i][j]
                    .clone()
                    .zip(c.clone())
                    .zip(rotc.clone())
                    // never panics since we always add full length spread bits
                    .map(|((a, c), rotc)| a.try_add(&c).unwrap().try_add(&rotc).unwrap());
                new_state.inner[i][j] = new_value;
            }
        }
        new_state
    }

    /// computing the value for the chi step which computes
    /// a[i][j] = a[i][j] xor (not a[i+1][j] and a[i+2][j])
    ///
    /// Computes the new values:
    /// a[i][j] = 2*a[i][j] + (ones - a[i+1][j] + a[i+2][j]).
    pub(super) fn compute_chi_with_error(&self) -> KeccakState {
        // instantiate the state
        let mut new_state = KeccakState::default();
        for i in 0..KECCAK_WIDTH {
            for j in 0..KECCAK_WIDTH {
                // ones - a[i+1][j]
                let a_next = self.inner[(i + 1) % KECCAK_WIDTH][j].clone();
                let neg_a_next = a_next.map(|a_next| a_next.negate().unwrap());

                // a[i+2][j]
                let a_next_next = self.inner[(i + 2) % KECCAK_WIDTH][j].clone();

                let new_value = self.inner[i][j].clone().zip(neg_a_next).zip(a_next_next).map(
                    |((a, neg_a_next), a_next_next)| {
                        // right summand
                        let r_sum = neg_a_next.try_add(&a_next_next).unwrap();
                        // result
                        a.mul2().unwrap().try_add(&r_sum).unwrap()
                    },
                );
                new_state.inner[i][j] = new_value;
            }
        }
        new_state
    }

    /// Absorbs new message blocks to the state.
    ///
    /// Concretely, given a [`KECCAK_ABSORB_LANES`]-length message, it modifies
    /// the state as: if i+5j < 17 then a[i][j] = a[i][j] + M[i + 5j]
    ///
    /// We "shift" the absorbed message via mul2 because this happens during the
    /// chi step. In this steps the result is in the middle bits so we shift
    /// to xor-with-error with the middle bits.
    pub(super) fn absorb_with_error(
        &self,
        ms: &[Value<SpreadBits>; KECCAK_ABSORB_LANES],
    ) -> KeccakState {
        // instantiate the state
        let mut new_state = self.inner.clone();
        ms.iter().enumerate().for_each(|(k, m)| {
            let (i, j) = (k % KECCAK_WIDTH, k / KECCAK_WIDTH);
            new_state[i][j] = self.inner[i][j]
                .clone()
                .zip(m.clone())
                // we double the message to shift it by one bit and align in the
                // constraint computation
                .map(|(a, m)| a.try_add(&m.mul2().unwrap()).unwrap())
        });

        KeccakState { inner: new_state }
    }
}
