use std::{
    collections::HashMap,
    fmt::Debug,
    io,
    sync::{Arc, OnceLock, RwLock},
};

use ff::{Field, PrimeField};
use group::{Curve, Group, GroupEncoding, prime::PrimeCurveAffine};
use midnight_curves::{
    pairing::{Engine, MultiMillerLoop},
    serde::SerdeObject,
};
use rand_core::RngCore;

use crate::{
    poly::{
        Coeff, LagrangeCoeff, LagrangeDeltaCoeff, PolynomialBasis, PolynomialRepresentation,
        kzg::bases::BasesStorage,
    },
    utils::{
        SerdeFormat,
        arithmetic::{CurveAffine, g_to_lagrange, parallelize},
        helpers::ProcessedSerdeObject,
    },
};

/// These are the public parameters for the polynomial commitment scheme.
#[derive(Debug, Clone)]
pub struct ParamsKZG<E: Engine> {
    pub(crate) g: BasesStorage<E::G1Affine>,
    /// May be absent after a lazy read; derive it from `g` on first use.
    pub(crate) g_lagrange: OnceLock<BasesStorage<E::G1Affine>>,
    /// Suffix-sum of `g_lagrange`:
    /// `g_lagrange_delta[i] = sum_{j=i}^{n-1} g_lagrange[j]`.
    pub(crate) g_lagrange_delta: OnceLock<Vec<E::G1Affine>>,
    /// Suffix-sum of `g_lagrange_delta`:
    /// `g_lagrange_double_delta[i] = sum_{j=i}^{n-1} g_lagrange_delta[j]`.
    /// Used as the SRS for the `LagrangeDoubleDelta` basis. Same derivation
    /// as `g_lagrange_delta`, applied a second time:
    /// `sum_j a_j · L_j = sum_i c_i · g_lagrange_double_delta[i]`,
    /// where `c_i = b_i - b_{i-1}` and `b_i = a_i - a_{i-1}`.
    pub(crate) g_lagrange_double_delta: OnceLock<Vec<E::G1Affine>>,
    pub(crate) g2: E::G2,
    pub(crate) s_g2: E::G2,
    /// The bases of every [`Residue`] committed to so far.
    residue_bases: ResidueBases<E::G1Affine>,
}

/// Residue `i` modulo `t`, identifying the bases for committing to `X^i f(X^t)`
/// from the `n` values of `f`, the `i`-th part of `g(X) = Σ_i X^i f_i(X^t)`.
/// These bases depend heavily on the representation `basis` of the values, as
/// detailed below. The name comes from `X^i f(X^t)` being made of the monomials
/// `X^e` with `e ≡ i (mod t)`.
///
/// - `Coeff`: the strided monomials `[s^(i + t·j)]`. For `f = Σ_j c_j X^j`,
///   `X^i f(X^t) = Σ_j c_j X^(i + t·j)`.
///
/// - `Lagrange`: `[s^i L_j(s^t)]`, for `L_j` the Lagrange basis of the domain
///   of size `n`: the Lagrange basis built from the strided monomials.
///
/// - `LagrangeDelta`: `[s^i Σ_{k ≥ j} L_k(s^t)]`, the suffix sums of the
///   `Lagrange` bases, as `g_lagrange_delta` is of `g_lagrange`.
///
/// - `LagrangeDoubleDelta`: `[s^i Σ_{k ≥ j} (k - j + 1) L_k(s^t)]`, the suffix
///   sums of the `LagrangeDelta` bases.
///
/// Committing to every `f_i` on its own bases keeps the zeros of its values
/// free. The bases are computed on first use, as the `Lagrange` ones take a
/// group FFT of size `n`, and cached in `ParamsKZG`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Residue {
    /// The representation of the values of `f_i`.
    basis: PolynomialBasis,
    /// The modulus, a power of two.
    t: usize,
    /// The number of values of `f_i`.
    n: usize,
    /// The residue, smaller than `t`.
    i: usize,
}

/// The bases of every [`Residue`] committed to so far.
type ResidueBases<C> = Arc<RwLock<HashMap<Residue, Arc<[C]>>>>;

/// Builds the suffix-sum of an affine SRS: `out[i] = sum_{j=i}^{n-1} input[j]`.
///
/// Accumulate in projective coordinates (one curve add per step) and
/// batch-normalise to affine at the end. n-1 projective adds + one O(n)
/// batch_normalise.
///
/// # Panics
/// If input is empty
fn suffix_sum<C: CurveAffine>(input: &[C]) -> Vec<C> {
    let n = input.len();
    let mut acc_proj: Vec<C::Curve> = vec![C::Curve::identity(); n];
    acc_proj[n - 1] = input[n - 1].into();
    for i in (0..n - 1).rev() {
        acc_proj[i] = acc_proj[i + 1] + input[i];
    }
    let mut acc_affine = vec![C::identity(); n];
    C::Curve::batch_normalize(&acc_proj, &mut acc_affine);
    acc_affine
}

impl<E: Engine + Debug> ParamsKZG<E>
where
    E::G1Affine: CurveAffine,
{
    fn g_lagrange_slice(&self) -> &[E::G1Affine] {
        self.g_lagrange
            .get_or_init(|| BasesStorage::owned(g_to_lagrange(&self.g, self.max_k())))
    }

    /// Return the SRS bases corresponding to the polynomial representation `B`.
    pub fn bases<B: PolynomialRepresentation>(&self) -> &[E::G1Affine] {
        match B::BASIS {
            PolynomialBasis::Coeff => &self.g,
            PolynomialBasis::Lagrange => self.g_lagrange_slice(),
            PolynomialBasis::LagrangeDelta => {
                self.g_lagrange_delta.get_or_init(|| suffix_sum(self.g_lagrange_slice()))
            }
            PolynomialBasis::LagrangeDoubleDelta => {
                self.g_lagrange_double_delta.get_or_init(|| {
                    suffix_sum(
                        self.g_lagrange_delta.get_or_init(|| suffix_sum(self.g_lagrange_slice())),
                    )
                })
            }
            PolynomialBasis::ExtendedLagrange => {
                unimplemented!("KZG does not support extended Lagrange bases")
            }
        }
    }

    /// The bases of the [`Residue`] `i` modulo `t`, for committing to
    /// `X^i f(X^t)` from the `n` values of `f` in the representation `B`.
    ///
    /// # Panics
    ///
    /// If `B` is the extended Lagrange basis, if `t·n` is larger than the SRS,
    /// or if `B` is Lagrange or one of its delta forms and `n` is not a power
    /// of two.
    pub(crate) fn residue_bases<B: PolynomialRepresentation>(
        &self,
        t: usize,
        n: usize,
        i: usize,
    ) -> Arc<[E::G1Affine]> {
        let residue = Residue {
            basis: B::BASIS,
            t,
            n,
            i,
        };
        if let Some(bases) =
            self.residue_bases.read().expect("residue bases lock poisoned").get(&residue)
        {
            return bases.clone();
        }
        let bases: Arc<[_]> = match B::BASIS {
            PolynomialBasis::Coeff => {
                assert!(
                    t * n <= self.g.len(),
                    "no residue bases of size {n} modulo {t}"
                );
                self.g[i..].iter().step_by(t).take(n).copied().collect()
            }
            PolynomialBasis::Lagrange => {
                assert!(n.is_power_of_two(), "no Lagrange residue bases of size {n}");
                g_to_lagrange(&self.residue_bases::<Coeff>(t, n, i), n.ilog2()).into()
            }
            PolynomialBasis::LagrangeDelta => {
                suffix_sum(&self.residue_bases::<LagrangeCoeff>(t, n, i)).into()
            }
            PolynomialBasis::LagrangeDoubleDelta => {
                suffix_sum(&self.residue_bases::<LagrangeDeltaCoeff>(t, n, i)).into()
            }
            basis => panic!("no residue bases in the {basis:?} basis"),
        };
        let mut cache = self.residue_bases.write().expect("residue bases lock poisoned");
        cache.entry(residue).or_insert(bases).clone()
    }

    /// Returns the size of the SRS, expressed as the exponent `k` such that it
    /// has `2^k` elements.
    pub fn max_k(&self) -> u32 {
        if let Some(lagrange) = self.g_lagrange.get() {
            assert_eq!(self.g.len(), lagrange.len());
        }
        self.g.len().ilog2()
    }

    /// Downsize the current parameters to match a smaller `k`.
    pub fn downsize(&mut self, new_k: u32) {
        if self.max_k() == new_k {
            return;
        }

        let n = 1 << new_k;
        assert!(n < self.g.len());
        self.g.truncate_into_owned(n);
        self.g_lagrange = OnceLock::new();
        self.g_lagrange_delta = OnceLock::new();
        self.g_lagrange_double_delta = OnceLock::new();
        self.residue_bases = Default::default();
    }

    /// Initializes parameters for the curve, draws toxic secret from given rng.
    /// MUST NOT be used in production.
    pub fn unsafe_setup<R: RngCore>(k: u32, rng: R) -> Self {
        // Largest root of unity exponent of the Engine is `2^E::Fr::S`, so we can
        // only support FFTs of polynomials below degree `2^E::Fr::S`.
        assert!(k <= E::Fr::S);
        let n: u64 = 1 << k;

        // Calculate g = [G1, [s] G1, [s^2] G1, ..., [s^(n-1)] G1] in parallel.
        let g1 = E::G1::generator();
        let s = <E::Fr>::random(rng);

        let mut g = vec![E::G1::identity(); n as usize];
        parallelize(&mut g, |g, start| {
            let mut current_g: E::G1 = g1;
            current_g *= s.pow_vartime([start as u64]);
            for g in g.iter_mut() {
                *g = current_g;
                current_g *= s;
            }
        });

        let mut g_lagrange = vec![E::G1::identity(); n as usize];
        let mut root = E::Fr::ROOT_OF_UNITY;
        for _ in k..E::Fr::S {
            root = root.square();
        }
        let n_inv = E::Fr::from(n).invert().expect("inversion should be ok for n = 1<<k");
        let multiplier = (s.pow_vartime([n]) - E::Fr::ONE) * n_inv;
        parallelize(&mut g_lagrange, |g, start| {
            for (idx, g) in g.iter_mut().enumerate() {
                let offset = start + idx;
                let root_pow = root.pow_vartime([offset as u64]);
                let scalar = multiplier * root_pow * (s - root_pow).invert().unwrap();
                *g = g1 * scalar;
            }
        });

        let mut g_affine = vec![E::G1Affine::identity(); n as usize];
        E::G1::batch_normalize(&g, &mut g_affine);

        let mut g_lagrange_affine = vec![E::G1Affine::identity(); n as usize];
        E::G1::batch_normalize(&g_lagrange, &mut g_lagrange_affine);

        let g2 = E::G2::generator();
        let s_g2 = g2 * s;

        Self {
            g: BasesStorage::owned(g_affine),
            g_lagrange: OnceLock::from(BasesStorage::owned(g_lagrange_affine)),
            g_lagrange_delta: OnceLock::new(),
            g_lagrange_double_delta: OnceLock::new(),
            g2,
            s_g2,
            residue_bases: Default::default(),
        }
    }

    /// Initializes parameters for the curve through existing parameters
    /// k, g, g_lagrange (optional), g2, s_g2
    pub fn from_parts(
        k: u32,
        g: Vec<E::G1>,
        g_lagrange: Option<Vec<E::G1>>,
        g2: E::G2,
        s_g2: E::G2,
    ) -> Self {
        let n = g.len();
        let mut g_affine = vec![E::G1Affine::identity(); n];
        E::G1::batch_normalize(&g, &mut g_affine);
        let g_lagrange_affine = match g_lagrange {
            Some(g_l) => {
                let mut aff = vec![E::G1Affine::identity(); g_l.len()];
                E::G1::batch_normalize(&g_l, &mut aff);
                aff
            }
            None => g_to_lagrange(&g_affine, k),
        };
        Self {
            g: BasesStorage::owned(g_affine),
            g_lagrange: OnceLock::from(BasesStorage::owned(g_lagrange_affine)),
            g_lagrange_delta: OnceLock::new(),
            g_lagrange_double_delta: OnceLock::new(),
            g2,
            s_g2,
            residue_bases: Default::default(),
        }
    }

    /// Returns the committed lagrange polynomials of these KZG params.
    pub fn g_lagrange(&self) -> &[E::G1Affine] {
        self.g_lagrange_slice()
    }

    /// Returns generator on G2
    pub fn g2(&self) -> E::G2 {
        self.g2
    }

    /// Returns \[τ\]₂, a commitment to τ in G2.
    pub fn s_g2(&self) -> E::G2 {
        self.s_g2
    }

    /// Writes parameters to buffer
    pub fn write_custom<W: io::Write>(&self, writer: &mut W, format: SerdeFormat) -> io::Result<()>
    where
        E::G1Affine: SerdeObject,
        E::G2: ProcessedSerdeObject,
    {
        writer.write_all(&self.g.len().ilog2().to_le_bytes())?;
        for el in self.g.iter() {
            match format {
                SerdeFormat::Processed => writer.write_all(el.to_bytes().as_ref())?,
                _ => el.write_raw(writer)?,
            }
        }
        for el in self.g_lagrange_slice().iter() {
            match format {
                SerdeFormat::Processed => writer.write_all(el.to_bytes().as_ref())?,
                _ => el.write_raw(writer)?,
            }
        }
        self.g2.write(writer, format)?;
        self.s_g2.write(writer, format)?;
        Ok(())
    }

    /// Reads params from a buffer.
    pub fn read_custom<R: io::Read>(reader: &mut R, format: SerdeFormat) -> io::Result<Self>
    where
        E::G1Affine: SerdeObject,
        E::G2: ProcessedSerdeObject,
    {
        let mut k = [0u8; 4];
        reader.read_exact(&mut k[..])?;
        let k = u32::from_le_bytes(k);
        if k > E::Fr::S {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("k = {k} exceeds the maximum supported value {}", E::Fr::S),
            ));
        }
        let n = 1usize
            .checked_shl(k)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SRS size overflows"))?;
        const POINT_CHUNK: usize = 4096;

        let reserve_points = |points: &mut Vec<E::G1Affine>, remaining: usize| {
            points
                .try_reserve(remaining.min(POINT_CHUNK))
                .map_err(|err| io::Error::other(format!("SRS allocation failed: {err}")))
        };

        let (g, g_lagrange) =
            match format {
                SerdeFormat::Processed => {
                    let load_points_from_file_parallelly =
                        |reader: &mut R| -> io::Result<Vec<E::G1Affine>> {
                            let mut result = Vec::new();
                            while result.len() < n {
                                let count = (n - result.len()).min(POINT_CHUNK);
                                let mut compressed =
                                    vec![<E::G1Affine as GroupEncoding>::Repr::default(); count];
                                for repr in &mut compressed {
                                    reader.read_exact(repr.as_mut())?;
                                }
                                let mut points = vec![Option::<E::G1Affine>::None; count];
                                parallelize(&mut points, |points, start| {
                                    for (i, point) in points.iter_mut().enumerate() {
                                        *point = Option::from(E::G1Affine::from_bytes(
                                            &compressed[start + i],
                                        ));
                                    }
                                });
                                reserve_points(&mut result, count)?;
                                for point in points {
                                    result.push(point.ok_or_else(|| {
                                        io::Error::other("invalid point encoding")
                                    })?);
                                }
                            }
                            Ok(result)
                        };

                    let g = load_points_from_file_parallelly(reader)?;
                    let g_lagrange = load_points_from_file_parallelly(reader)?;
                    (g, g_lagrange)
                }
                SerdeFormat::RawBytes => {
                    let read_points = |reader: &mut R| -> io::Result<Vec<E::G1Affine>> {
                        let mut points = Vec::new();
                        for i in 0..n {
                            if i % POINT_CHUNK == 0 {
                                reserve_points(&mut points, n - i)?;
                            }
                            points.push(E::G1Affine::read_raw(reader)?);
                        }
                        Ok(points)
                    };
                    let g = read_points(reader)?;
                    let g_lagrange = read_points(reader)?;
                    (g, g_lagrange)
                }
                SerdeFormat::RawBytesUnchecked => {
                    let read_points = |reader: &mut R| -> io::Result<Vec<E::G1Affine>> {
                        let mut points = Vec::new();
                        let mut raw = vec![0u8; E::G1Affine::identity().to_raw_bytes().len()];
                        for i in 0..n {
                            if i % POINT_CHUNK == 0 {
                                reserve_points(&mut points, n - i)?;
                            }
                            reader.read_exact(&mut raw)?;
                            points.push(E::G1Affine::read_raw_unchecked(&mut &raw[..]));
                        }
                        Ok(points)
                    };
                    let g = read_points(reader)?;
                    let g_lagrange = read_points(reader)?;
                    (g, g_lagrange)
                }
            };

        let read_g2 = |reader: &mut R| -> io::Result<E::G2> {
            if matches!(format, SerdeFormat::RawBytesUnchecked) {
                let mut raw = vec![0u8; E::G2::identity().byte_length(format)];
                reader.read_exact(&mut raw)?;
                E::G2::read(&mut &raw[..], format)
            } else {
                E::G2::read(reader, format)
            }
        };
        let g2 = read_g2(reader)?;
        let s_g2 = read_g2(reader)?;

        Ok(Self {
            g: BasesStorage::owned(g),
            g_lagrange: OnceLock::from(BasesStorage::owned(g_lagrange)),
            g_lagrange_delta: OnceLock::new(),
            g_lagrange_double_delta: OnceLock::new(),
            g2,
            s_g2,
            residue_bases: Default::default(),
        })
    }

    /// Read a seekable parameter stream without materialising its on-disk
    /// Lagrange basis. The basis is derived from `g` when first requested.
    /// The serialized format is identical to [`Self::read_custom`].
    pub fn read_custom_lazy<R: io::Read + io::Seek>(
        reader: &mut R,
        format: SerdeFormat,
    ) -> io::Result<Self>
    where
        E::G1Affine: SerdeObject,
        E::G2: ProcessedSerdeObject,
    {
        let mut k = [0u8; 4];
        reader.read_exact(&mut k)?;
        let k = u32::from_le_bytes(k);
        if k > E::Fr::S {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SRS k"));
        }
        let n = 1usize
            .checked_shl(k)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SRS size overflows"))?;
        let before_g = reader.stream_position()?;
        // Check the complete wire length before materialising any basis. In
        // particular, an otherwise valid k=32 header must not allocate a
        // multi-gigabyte vector from a truncated stream.
        let point_bytes = match format {
            SerdeFormat::Processed => {
                <E::G1Affine as GroupEncoding>::Repr::default().as_ref().len()
            }
            _ => E::G1Affine::identity().to_raw_bytes().len(),
        };
        let primary_bytes = n
            .checked_mul(point_bytes)
            .and_then(|size| size.checked_mul(2))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SRS too large"))?;
        let required = primary_bytes
            .checked_add(
                E::G2::identity()
                    .byte_length(format)
                    .checked_mul(2)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SRS too large"))?,
            )
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SRS too large"))?;
        let required = u64::try_from(required)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SRS too large"))?;
        let end = reader.seek(io::SeekFrom::End(0))?;
        reader.seek(io::SeekFrom::Start(before_g))?;
        if end.saturating_sub(before_g) < required {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated SRS",
            ));
        }
        let g = match format {
            SerdeFormat::Processed => {
                let mut encoded = vec![<E::G1Affine as GroupEncoding>::Repr::default(); n];
                for point in &mut encoded {
                    reader.read_exact(point.as_mut())?;
                }
                let mut points = vec![Option::<E::G1Affine>::None; n];
                parallelize(&mut points, |points, start| {
                    for (i, point) in points.iter_mut().enumerate() {
                        *point = Option::from(E::G1Affine::from_bytes(&encoded[start + i]));
                    }
                });
                points
                    .into_iter()
                    .map(|point| point.ok_or_else(|| io::Error::other("invalid point encoding")))
                    .collect::<io::Result<Vec<_>>>()?
            }
            SerdeFormat::RawBytes => {
                (0..n).map(|_| E::G1Affine::read_raw(reader)).collect::<io::Result<Vec<_>>>()?
            }
            SerdeFormat::RawBytesUnchecked => {
                (0..n).map(|_| E::G1Affine::read_raw_unchecked(reader)).collect()
            }
        };

        // Both primary bases have the same point count and encoding. Seek
        // past the second block before reading the two G2 elements.
        let g_bytes = reader.stream_position()?.checked_sub(before_g).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "SRS reader position moved backwards",
            )
        })?;
        let skip = i64::try_from(g_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SRS block too large"))?;
        reader.seek(io::SeekFrom::Current(skip))?;
        let g2 = E::G2::read(reader, format)?;
        let s_g2 = E::G2::read(reader, format)?;

        Ok(Self {
            g: BasesStorage::owned(g),
            g_lagrange: OnceLock::new(),
            g_lagrange_delta: OnceLock::new(),
            g_lagrange_double_delta: OnceLock::new(),
            g2,
            s_g2,
            residue_bases: Default::default(),
        })
    }

    /// Identifies the private 0.8.3 affine companion layout for this curve and k.
    /// It is a cache compatibility check, not a digest of the SRS contents.
    #[cfg(feature = "mmap")]
    fn companion_identity(k: u32) -> u64 {
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for part in [
            b"MDNGHTV3".as_slice(),
            env!("CARGO_PKG_VERSION").as_bytes(),
            std::any::type_name::<E::G1Affine>().as_bytes(),
            &std::mem::size_of::<E::G1Affine>().to_le_bytes(),
            &std::mem::align_of::<E::G1Affine>().to_le_bytes(),
            &k.to_le_bytes(),
        ] {
            for &byte in part {
                hash ^= u64::from(byte);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        hash
    }

    /// Writes the private, host-layout affine SRS companion format.
    /// This is a local cache format, not a network or cross-device format.
    /// Publish the completed file without replacing an existing inode, and
    /// keep it in a private directory that other processes cannot modify.
    #[cfg(feature = "mmap")]
    #[allow(unsafe_code)]
    pub fn write_mmap_companion<W: io::Write>(&self, writer: &mut W) -> io::Result<()>
    where
        E::G1Affine: crate::poly::kzg::bases::PlainBytes,
        E::G2: ProcessedSerdeObject,
    {
        const HEADER_LEN: usize = 96;
        const G_OFFSET: usize = 128;
        let k = self.max_k();
        let n = self.g.len();
        let point_size = std::mem::size_of::<E::G1Affine>();
        let block_bytes =
            n.checked_mul(point_size).ok_or_else(|| io::Error::other("SRS too large"))?;
        let gl_offset = G_OFFSET
            .checked_add(block_bytes)
            .ok_or_else(|| io::Error::other("SRS too large"))?;
        let g2_offset = gl_offset
            .checked_add(block_bytes)
            .ok_or_else(|| io::Error::other("SRS too large"))?;
        let mut g2_buf = Vec::new();
        let mut s_g2_buf = Vec::new();
        self.g2.write(&mut g2_buf, SerdeFormat::RawBytesUnchecked)?;
        self.s_g2.write(&mut s_g2_buf, SerdeFormat::RawBytesUnchecked)?;
        let s_g2_offset = g2_offset
            .checked_add(g2_buf.len())
            .ok_or_else(|| io::Error::other("SRS too large"))?;

        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(b"MDNGHTV3");
        header.extend_from_slice(&3u32.to_le_bytes());
        header.extend_from_slice(&k.to_le_bytes());
        header
            .extend_from_slice(&u32::try_from(point_size).map_err(io::Error::other)?.to_le_bytes());
        header.extend_from_slice(&1u32.to_le_bytes()); // both primary bases present
        header.extend_from_slice(&Self::companion_identity(k).to_le_bytes());
        for value in [
            G_OFFSET,
            n,
            gl_offset,
            n,
            g2_offset,
            g2_buf.len(),
            s_g2_offset,
            s_g2_buf.len(),
        ] {
            header
                .extend_from_slice(&u64::try_from(value).map_err(io::Error::other)?.to_le_bytes());
        }
        debug_assert_eq!(header.len(), HEADER_LEN);
        writer.write_all(&header)?;
        writer.write_all(&[0u8; G_OFFSET - HEADER_LEN])?;
        for points in [&self.g[..], self.g_lagrange_slice()] {
            // SAFETY: PlainBytes guarantees no padding or invalid Rust bit
            // patterns; these are live, initialized affine points.
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    points.as_ptr().cast::<u8>(),
                    std::mem::size_of_val(points),
                )
            };
            writer.write_all(bytes)?;
        }
        writer.write_all(&g2_buf)?;
        writer.write_all(&s_g2_buf)?;
        Ok(())
    }

    /// Publishes a complete companion at `path` without replacing an existing
    /// file. The caller must choose a private directory and keep the published
    /// inode immutable while any process maps it.
    #[cfg(feature = "mmap")]
    pub fn publish_mmap_companion(&self, path: &std::path::Path) -> io::Result<()>
    where
        E::G1Affine: crate::poly::kzg::bases::PlainBytes,
        E::G2: ProcessedSerdeObject,
    {
        let parent =
            path.parent().ok_or_else(|| io::Error::other("companion path has no parent"))?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        self.write_mmap_companion(&mut temporary)?;
        temporary.as_file().sync_all()?;
        temporary.persist_noclobber(path).map_err(|error| error.error)?;
        Ok(())
    }

    /// Reads the private affine companion produced by `write_mmap_companion`.
    /// Header, ranges, alignment, and format identity are checked before any
    /// mapped point slice is exposed. Point *values* are not validated.
    ///
    /// # Safety
    /// The caller must own the backing file and keep it immutable for every
    /// clone and borrow of the returned parameters. Do not map downloaded or
    /// attacker-writable files. A malicious or modified file can change proof
    /// results despite a valid header.
    #[cfg(feature = "mmap")]
    #[allow(unsafe_code)]
    pub unsafe fn read_mmap_arc(mmap: Arc<memmap2::Mmap>) -> io::Result<Self>
    where
        E::G1Affine: crate::poly::kzg::bases::PlainBytes,
        E::G2: ProcessedSerdeObject,
    {
        const HEADER_LEN: usize = 96;
        const G_OFFSET: usize = 128;
        fn bad(message: &'static str) -> io::Error {
            io::Error::new(io::ErrorKind::InvalidData, message)
        }
        let bytes = &mmap[..];
        if bytes.len() < HEADER_LEN || &bytes[0..8] != b"MDNGHTV3" {
            return Err(bad("not a v3 affine companion"));
        }
        let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let usize_at = |at: usize| -> io::Result<usize> {
            usize::try_from(u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap()))
                .map_err(|_| bad("companion field overflows usize"))
        };
        if u32_at(8) != 3 || u32_at(20) != 1 {
            return Err(bad("unsupported companion version or flags"));
        }
        let k = u32_at(12);
        let expected = 1usize.checked_shl(k).ok_or_else(|| bad("invalid k"))?;
        let point_size = std::mem::size_of::<E::G1Affine>();
        if usize::try_from(u32_at(16)).ok() != Some(point_size) {
            return Err(bad("affine point layout mismatch"));
        }
        if u64::from_le_bytes(bytes[24..32].try_into().unwrap()) != Self::companion_identity(k) {
            return Err(bad("companion identity mismatch"));
        }
        let fields: Vec<usize> = (32..96).step_by(8).map(usize_at).collect::<io::Result<_>>()?;
        let [
            g_offset,
            g_count,
            gl_offset,
            gl_count,
            g2_offset,
            g2_size,
            s_g2_offset,
            s_g2_size,
        ]: [usize; 8] = fields.try_into().unwrap();
        if g_offset != G_OFFSET || g_count != expected || gl_count != expected {
            return Err(bad("companion base count or offset mismatch"));
        }
        let block_bytes =
            expected.checked_mul(point_size).ok_or_else(|| bad("base length overflow"))?;
        if gl_offset
            != g_offset.checked_add(block_bytes).ok_or_else(|| bad("base range overflow"))?
            || g2_offset
                != gl_offset.checked_add(block_bytes).ok_or_else(|| bad("base range overflow"))?
            || s_g2_offset
                != g2_offset.checked_add(g2_size).ok_or_else(|| bad("g2 range overflow"))?
            || bytes.len()
                != s_g2_offset.checked_add(s_g2_size).ok_or_else(|| bad("s_g2 range overflow"))?
        {
            return Err(bad("companion blocks are truncated or not canonical"));
        }
        let base_addr = bytes.as_ptr() as usize;
        let align = std::mem::align_of::<E::G1Affine>();
        if base_addr.checked_add(g_offset).ok_or_else(|| bad("address overflow"))? % align != 0
            || base_addr.checked_add(gl_offset).ok_or_else(|| bad("address overflow"))? % align != 0
        {
            return Err(bad("affine base block misaligned"));
        }
        let mut g2_bytes = &bytes[g2_offset..s_g2_offset];
        let mut s_g2_bytes = &bytes[s_g2_offset..];
        let g2 = E::G2::read(&mut g2_bytes, SerdeFormat::RawBytesUnchecked)?;
        let s_g2 = E::G2::read(&mut s_g2_bytes, SerdeFormat::RawBytesUnchecked)?;
        if !g2_bytes.is_empty() || !s_g2_bytes.is_empty() {
            return Err(bad("trailing G2 bytes"));
        }
        // SAFETY: all ranges, lengths and alignment were checked above.
        // PlainBytes covers point representation; the caller owns immutability.
        let g = unsafe { BasesStorage::mapped(mmap.clone(), g_offset, expected) };
        let g_lagrange = unsafe { BasesStorage::mapped(mmap, gl_offset, expected) };
        Ok(Self {
            g,
            g_lagrange: OnceLock::from(g_lagrange),
            g_lagrange_delta: OnceLock::new(),
            g_lagrange_double_delta: OnceLock::new(),
            g2,
            s_g2,
            residue_bases: Default::default(),
        })
    }
}

// TODO: see the issue at https://github.com/appliedzkp/halo2/issues/45
// So we probably need much smaller verifier key. However for new bases in g1
// should be in verifier keys.
/// KZG multi-open verification parameters
#[derive(Clone, Debug)]
pub struct ParamsVerifierKZG<E: MultiMillerLoop> {
    pub(crate) s_g2: E::G2,
    pub(crate) n_g2_prepared: E::G2Prepared,
    pub(crate) s_g2_prepared: E::G2Prepared,
}

impl<E: MultiMillerLoop + Debug> ParamsVerifierKZG<E>
where
    E::G2: Curve + ProcessedSerdeObject,
{
    /// Returns \[τ\]₂, a commitment to τ in G2.
    pub fn s_g2(&self) -> E::G2 {
        self.s_g2
    }

    /// Writes parameters to buffer
    pub fn write<W: io::Write>(&self, writer: &mut W, format: SerdeFormat) -> io::Result<()> {
        self.s_g2.write(writer, format)?;
        Ok(())
    }

    /// Reads params from a buffer.
    pub fn read<R: io::Read>(reader: &mut R, format: SerdeFormat) -> io::Result<Self> {
        let s_g2 = E::G2::read(reader, format)?;
        let s_g2_prepared = E::G2Prepared::from(s_g2.into());
        let n_g2_prepared = E::G2Prepared::from(-E::G2Affine::generator());

        Ok(Self {
            s_g2,
            n_g2_prepared,
            s_g2_prepared,
        })
    }
}

impl<E: MultiMillerLoop + Debug> ParamsKZG<E> {
    /// Consume the prover parameters into verifier parameters. Need to specify
    /// the size of public inputs.
    pub fn verifier_params(&self) -> ParamsVerifierKZG<E> {
        let n_g2_prepared = E::G2Prepared::from((-self.g2).into());
        let s_g2_prepared = E::G2Prepared::from(self.s_g2.into());
        ParamsVerifierKZG {
            s_g2: self.s_g2,
            n_g2_prepared,
            s_g2_prepared,
        }
    }
}

#[cfg(test)]
mod test {
    use rand_core::OsRng;

    use crate::{
        poly::{
            LagrangeDeltaCoeff, LagrangeDoubleDeltaCoeff, PolynomialLabel,
            commitment::PolynomialCommitmentScheme,
            kzg::{KZGCommitmentScheme, params::ParamsKZG},
        },
        utils::SerdeFormat,
    };

    #[test]
    fn test_read_custom_rejects_oversized_k() {
        use ff::PrimeField;
        use midnight_curves::{Bls12, Fq};

        let data = (Fq::S + 1).to_le_bytes();
        for format in [
            SerdeFormat::Processed,
            SerdeFormat::RawBytes,
            SerdeFormat::RawBytesUnchecked,
        ] {
            let err = ParamsKZG::<Bls12>::read_custom(&mut &data[..], format)
                .err()
                .expect("oversized k must be rejected");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

            let boundary = Fq::S.to_le_bytes();
            assert!(
                ParamsKZG::<Bls12>::read_custom(&mut &boundary[..], format).is_err(),
                "k at the field limit must not allocate from a truncated stream"
            );
            assert!(
                ParamsKZG::<Bls12>::read_custom_lazy(&mut std::io::Cursor::new(boundary), format,)
                    .is_err(),
                "lazy k at the field limit must not allocate from a truncated stream"
            );
        }
    }

    #[test]
    fn test_read_custom_unchecked_truncation_is_an_io_error() {
        use midnight_curves::Bls12;

        let params: ParamsKZG<Bls12> = ParamsKZG::unsafe_setup(2, OsRng);
        let mut bytes = Vec::new();
        params.write_custom(&mut bytes, SerdeFormat::RawBytesUnchecked).unwrap();
        bytes.truncate(bytes.len() - 1);
        let err = ParamsKZG::<Bls12>::read_custom(&mut &bytes[..], SerdeFormat::RawBytesUnchecked)
            .err()
            .expect("truncated raw SRS must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_commit_lagrange() {
        const K: u32 = 6;

        use midnight_curves::{Bls12, Fq};

        use crate::poly::EvaluationDomain;

        let params: ParamsKZG<Bls12> = ParamsKZG::unsafe_setup(K, OsRng);
        let domain = EvaluationDomain::new(1, K);

        let mut a = domain.empty_lagrange();

        for (i, a) in a.iter_mut().enumerate() {
            *a = Fq::from(i as u64);
        }

        let b = domain.lagrange_to_coeff(a.clone());

        let tmp = KZGCommitmentScheme::commit(&params, &a, PolynomialLabel::NoLabel);
        let com = KZGCommitmentScheme::commit(&params, &b, PolynomialLabel::NoLabel);

        assert_eq!(tmp, com);
    }

    #[test]
    fn test_commit_in_delta_basis_matches_lagrange() {
        const K: u32 = 6;

        use ff::Field;
        use midnight_curves::{Bls12, Fq};

        use crate::poly::EvaluationDomain;

        let params: ParamsKZG<Bls12> = ParamsKZG::unsafe_setup(K, OsRng);
        let domain = EvaluationDomain::new(1, K);

        // A polynomial with long constant runs and a few isolated transitions —
        // exercises the structure the optimization is designed for.
        let mut a = domain.empty_lagrange();
        for (i, slot) in a.iter_mut().enumerate() {
            *slot = match i {
                0..16 => Fq::ZERO,
                16..40 => Fq::from(7),
                40..50 => Fq::from(7) + Fq::from(i as u64),
                _ => Fq::from(42),
            };
        }

        let c_lagrange = KZGCommitmentScheme::commit(&params, &a, PolynomialLabel::NoLabel);
        let c_delta = KZGCommitmentScheme::commit(&params, &a.to_delta(), PolynomialLabel::NoLabel);
        assert_eq!(c_lagrange, c_delta);

        // Round-trip identity: to_delta then into_lagrange recovers the original.
        let restored = a.to_delta().into_lagrange();
        assert_eq!(restored.values, a.values);
    }

    #[test]
    fn test_commit_in_double_delta_basis_matches_lagrange() {
        const K: u32 = 6;

        use midnight_curves::{Bls12, Fq};

        use crate::poly::EvaluationDomain;

        let params: ParamsKZG<Bls12> = ParamsKZG::unsafe_setup(K, OsRng);
        let domain = EvaluationDomain::new(1, K);

        // A polynomial with linear runs (constant first differences) and a
        // few transitions — exercises the structure the double-delta basis
        // is designed for: linear segments collapse to zeros after two
        // delta applications.
        let mut a = domain.empty_lagrange();
        for (i, slot) in a.iter_mut().enumerate() {
            *slot = match i {
                0..16 => Fq::from(i as u64),
                16..40 => Fq::from(16) + Fq::from(2u64) * Fq::from((i - 16) as u64),
                40..50 => Fq::from(99),
                _ => Fq::from(i as u64) - Fq::from(50),
            };
        }

        let c_lagrange = KZGCommitmentScheme::commit(&params, &a, PolynomialLabel::NoLabel);

        // Fused single-pass conversion matches the two-step path.
        let c_double_delta_fused =
            KZGCommitmentScheme::commit(&params, &a.to_double_delta(), PolynomialLabel::NoLabel);
        let c_double_delta_two_step = KZGCommitmentScheme::commit(
            &params,
            &a.to_delta().into_double_delta(),
            PolynomialLabel::NoLabel,
        );
        assert_eq!(c_lagrange, c_double_delta_fused);
        assert_eq!(c_lagrange, c_double_delta_two_step);

        // Both fused and two-step transforms produce the same scalar vector.
        let fused = a.to_double_delta();
        let two_step = a.to_delta().into_double_delta();
        assert_eq!(fused.values, two_step.values);

        // Round-trip identity, both inverse paths.
        let restored_fused = a.to_double_delta().into_lagrange();
        let restored_stepwise = a.to_double_delta().into_lagrange_delta().into_lagrange();
        assert_eq!(restored_fused.values, a.values);
        assert_eq!(restored_stepwise.values, a.values);
    }

    #[test]
    fn test_parameter_serialisation_roundtrip() {
        const K: u32 = 4;

        use midnight_curves::Bls12;

        let params0: ParamsKZG<Bls12> = ParamsKZG::unsafe_setup(K, OsRng);
        assert!(params0.g_lagrange_delta.get().is_none());
        assert!(params0.g_lagrange_double_delta.get().is_none());
        let mut data = vec![];
        ParamsKZG::write_custom(&params0, &mut data, SerdeFormat::RawBytesUnchecked).unwrap();
        let params1 =
            ParamsKZG::<Bls12>::read_custom::<_>(&mut &data[..], SerdeFormat::RawBytesUnchecked)
                .unwrap();
        assert!(params1.g_lagrange_delta.get().is_none());
        assert!(params1.g_lagrange_double_delta.get().is_none());

        assert_eq!(params0.g.len(), params1.g.len());
        assert_eq!(params0.g_lagrange().len(), params1.g_lagrange().len());

        assert_eq!(params0.g, params1.g);
        assert_eq!(params0.g_lagrange(), params1.g_lagrange());
        assert_eq!(params0.g2, params1.g2);
        assert_eq!(params0.s_g2, params1.s_g2);
        assert_eq!(
            params0.bases::<LagrangeDeltaCoeff>(),
            params1.bases::<LagrangeDeltaCoeff>()
        );
        assert_eq!(
            params0.bases::<LagrangeDoubleDeltaCoeff>(),
            params1.bases::<LagrangeDoubleDeltaCoeff>()
        );
    }

    #[test]
    fn test_lazy_parameter_read_preserves_wire_and_derives_lagrange_on_use() {
        use midnight_curves::Bls12;
        use std::io::Cursor;

        let original: ParamsKZG<Bls12> = ParamsKZG::unsafe_setup(4, OsRng);
        for format in [
            SerdeFormat::Processed,
            SerdeFormat::RawBytes,
            SerdeFormat::RawBytesUnchecked,
        ] {
            let mut bytes = Vec::new();
            original.write_custom(&mut bytes, format).unwrap();
            let mut reader = Cursor::new(&bytes);
            let lazy = ParamsKZG::<Bls12>::read_custom_lazy(&mut reader, format).unwrap();
            assert_eq!(reader.position() as usize, bytes.len());
            assert!(lazy.g_lagrange.get().is_none(), "{format:?}");
            assert_eq!(lazy.max_k(), 4);
            assert!(
                lazy.g_lagrange.get().is_none(),
                "max_k materialised {format:?}"
            );
            assert_eq!(lazy.g, original.g);
            assert_eq!(lazy.g2, original.g2);
            assert_eq!(lazy.s_g2, original.s_g2);
            assert_eq!(lazy.g_lagrange(), original.g_lagrange(), "{format:?}");
            assert!(lazy.g_lagrange.get().is_some());
            let mut rewritten = Vec::new();
            lazy.write_custom(&mut rewritten, format).unwrap();
            assert_eq!(rewritten, bytes, "wire changed for {format:?}");
        }

        let mut bytes = Vec::new();
        original.write_custom(&mut bytes, SerdeFormat::RawBytes).unwrap();
        bytes.truncate(bytes.len() - 1);
        assert!(
            ParamsKZG::<Bls12>::read_custom_lazy(&mut Cursor::new(bytes), SerdeFormat::RawBytes)
                .is_err(),
            "truncated lazy parameter stream was accepted"
        );
        let mut unchecked = Vec::new();
        original.write_custom(&mut unchecked, SerdeFormat::RawBytesUnchecked).unwrap();
        unchecked.truncate(unchecked.len() - 1);
        assert_eq!(
            ParamsKZG::<Bls12>::read_custom_lazy(
                &mut Cursor::new(unchecked),
                SerdeFormat::RawBytesUnchecked,
            )
            .err()
            .unwrap()
            .kind(),
            std::io::ErrorKind::UnexpectedEof,
        );
    }

    #[test]
    fn test_downsize_invalidates_derived_bases() {
        use midnight_curves::Bls12;

        let mut params: ParamsKZG<Bls12> = ParamsKZG::unsafe_setup(5, OsRng);
        let _ = params.bases::<LagrangeDoubleDeltaCoeff>();
        assert!(params.g_lagrange_delta.get().is_some());
        assert!(params.g_lagrange_double_delta.get().is_some());

        params.downsize(4);
        assert!(params.g_lagrange_delta.get().is_none());
        assert!(params.g_lagrange_double_delta.get().is_none());
        assert_eq!(
            params.bases::<LagrangeDeltaCoeff>(),
            super::suffix_sum(params.g_lagrange())
        );
        assert_eq!(
            params.bases::<LagrangeDoubleDeltaCoeff>(),
            super::suffix_sum(params.bases::<LagrangeDeltaCoeff>())
        );
    }

    #[cfg(feature = "mmap")]
    #[allow(unsafe_code)]
    #[test]
    fn test_affine_mmap_companion_round_trip_and_downsize() {
        use midnight_curves::Bls12;
        use std::sync::Arc;

        let params: ParamsKZG<Bls12> = ParamsKZG::unsafe_setup(4, OsRng);
        let mut file = tempfile::tempfile().unwrap();
        params.write_mmap_companion(&mut file).unwrap();
        file.sync_all().unwrap();
        // SAFETY: this test owns the file and never mutates it after mapping.
        let mmap = Arc::new(unsafe { memmap2::Mmap::map(&file) }.unwrap());
        // SAFETY: the test owns the immutable companion for every clone.
        let mut mapped = unsafe { ParamsKZG::<Bls12>::read_mmap_arc(mmap) }.unwrap();
        assert!(mapped.g.is_mapped());
        assert!(mapped.g_lagrange.get().unwrap().is_mapped());
        assert_eq!(params.g, mapped.g);
        assert_eq!(params.g_lagrange(), mapped.g_lagrange());
        assert_eq!(params.g2, mapped.g2);
        assert_eq!(params.s_g2, mapped.s_g2);
        let cloned = mapped.clone();
        assert!(cloned.g.is_mapped());
        assert_eq!(
            params.bases::<LagrangeDoubleDeltaCoeff>(),
            mapped.bases::<LagrangeDoubleDeltaCoeff>()
        );

        mapped.downsize(3);
        assert!(!mapped.g.is_mapped());
        assert!(mapped.g_lagrange.get().is_none());
        assert_eq!(mapped.max_k(), 3);
        assert_eq!(cloned.max_k(), 4);
    }

    #[cfg(feature = "mmap")]
    #[allow(unsafe_code)]
    #[test]
    fn test_affine_mmap_companion_rejects_old_and_damaged_layouts() {
        use midnight_curves::Bls12;
        use std::sync::Arc;

        fn load(bytes: &[u8]) -> std::io::Result<ParamsKZG<Bls12>> {
            let mut mapping = memmap2::MmapMut::map_anon(bytes.len().max(1)).unwrap();
            mapping[..bytes.len()].copy_from_slice(bytes);
            let mapping = Arc::new(mapping.make_read_only().unwrap());
            // SAFETY: this test owns the read-only anonymous mapping.
            unsafe { ParamsKZG::<Bls12>::read_mmap_arc(mapping) }
        }

        let params: ParamsKZG<Bls12> = ParamsKZG::unsafe_setup(4, OsRng);
        let mut good = Vec::new();
        params.write_mmap_companion(&mut good).unwrap();
        assert!(load(&good).is_ok());
        let mut old = good.clone();
        old[..8].copy_from_slice(b"MDNGHTV2");
        assert_eq!(
            load(&old).err().unwrap().kind(),
            std::io::ErrorKind::InvalidData
        );
        for at in [8, 16, 20, 24, 32, 40, 48] {
            let mut damaged = good.clone();
            damaged[at] ^= 1;
            let error = load(&damaged).err().expect("damaged companion was accepted");
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData, "offset {at}");
        }
        assert_eq!(
            load(&good[..good.len() - 1]).err().unwrap().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[cfg(feature = "mmap")]
    #[test]
    fn test_affine_mmap_companion_publication_does_not_replace() {
        use midnight_curves::Bls12;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("params.mmap");
        let params: ParamsKZG<Bls12> = ParamsKZG::unsafe_setup(4, OsRng);
        params.publish_mmap_companion(&path).unwrap();
        let first = std::fs::read(&path).unwrap();
        let error = params.publish_mmap_companion(&path).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), first);
    }
}
