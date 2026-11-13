//! Owned or read-only mapped proving-key columns.

use std::io;

use ff::PrimeField;
use midnight_curves::serde::SerdeObject;

#[cfg(feature = "disk-spill")]
use super::mmap_pk::{MmappedPolys, spill_iter_to_disk, spill_try_iter_to_disk};
#[cfg(feature = "disk-spill")]
use crate::utils::SerdeFormat;
use crate::{
    poly::{Polynomial, PolynomialView, polynomial_views},
    utils::helpers::{polynomial_slice_byte_length, write_polynomial_slice},
};

#[derive(Debug)]
pub(crate) enum KeyPolys<F, B> {
    Owned(Vec<Polynomial<F, B>>),
    #[cfg(feature = "disk-spill")]
    Mapped(MmappedPolys<F, B>),
}

impl<F, B> KeyPolys<F, B> {
    pub(crate) fn views(&self) -> Vec<PolynomialView<'_, F, B>> {
        match self {
            Self::Owned(polys) => polynomial_views(polys),
            #[cfg(feature = "disk-spill")]
            Self::Mapped(polys) => polys.views(),
        }
    }

    #[cfg(feature = "disk-spill")]
    pub(crate) fn map_to_disk(self, spill_dir: Option<&std::path::Path>) -> io::Result<Self>
    where
        F: Copy,
    {
        let owned = match self {
            Self::Owned(polys) => polys,
            Self::Mapped(polys) => return Ok(Self::Mapped(polys)),
        };
        if owned.is_empty() {
            return Ok(Self::Owned(owned));
        }
        let count = owned.len();
        let len = owned[0].len();
        Ok(Self::Mapped(spill_iter_to_disk(
            spill_dir, owned, count, len,
        )?))
    }
}

impl<F: PrimeField, B> KeyPolys<F, B> {
    pub(crate) fn bytes_length(&self) -> usize {
        match self {
            Self::Owned(polys) => polynomial_slice_byte_length(polys),
            #[cfg(feature = "disk-spill")]
            Self::Mapped(polys) => {
                let views = polys.views();
                let field_len = F::default().to_repr().as_ref().len();
                4 + views.len() * (4 + field_len * views.first().map_or(0, |poly| poly.len()))
            }
        }
    }
}

impl<F: PrimeField + SerdeObject, B> KeyPolys<F, B> {
    pub(crate) fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        match self {
            Self::Owned(polys) => write_polynomial_slice(polys, writer),
            #[cfg(feature = "disk-spill")]
            Self::Mapped(polys) => {
                let views = polys.views();
                writer.write_all(&(views.len() as u32).to_be_bytes())?;
                for poly in views {
                    writer.write_all(&(poly.len() as u32).to_be_bytes())?;
                    for value in poly.iter() {
                        value.write_raw(writer)?;
                    }
                }
                Ok(())
            }
        }
    }
}

#[cfg(feature = "disk-spill")]
impl<F: PrimeField + SerdeObject + Copy, B> KeyPolys<F, B> {
    /// Deserialize one column at a time into a reserved, read-only mapping.
    /// The expected shape comes from the already checked verifying key.
    pub(crate) fn read_mapped<R: io::Read>(
        reader: &mut R,
        format: SerdeFormat,
        expected_count: usize,
        expected_len: usize,
        spill_dir: Option<&std::path::Path>,
    ) -> io::Result<Self> {
        let mut count = [0u8; 4];
        reader.read_exact(&mut count)?;
        let count = u32::from_be_bytes(count) as usize;
        if count != expected_count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("key column count {count}, expected {expected_count}"),
            ));
        }
        if count == 0 {
            return Ok(Self::Owned(Vec::new()));
        }
        let columns =
            (0..count).map(|_| Polynomial::read_with_expected_len(reader, format, expected_len));
        Ok(Self::Mapped(spill_try_iter_to_disk(
            spill_dir,
            columns,
            count,
            expected_len,
        )?))
    }
}

#[cfg(all(test, feature = "disk-spill"))]
mod tests {
    use std::{io, marker::PhantomData};

    use midnight_curves::Fq;

    use super::*;
    use crate::poly::LagrangeCoeff;

    #[test]
    fn mapped_key_read_streams_and_rejects_bad_shape_or_truncation() {
        let source = KeyPolys::<Fq, LagrangeCoeff>::Owned(vec![
            Polynomial {
                values: vec![Fq::from(1), Fq::from(2)],
                _marker: PhantomData,
            },
            Polynomial {
                values: vec![Fq::from(3), Fq::from(4)],
                _marker: PhantomData,
            },
        ]);
        let mut bytes = Vec::new();
        source.write(&mut bytes).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let read = |data: &[u8]| {
            KeyPolys::<Fq, LagrangeCoeff>::read_mapped(
                &mut &data[..],
                SerdeFormat::RawBytes,
                2,
                2,
                Some(dir.path()),
            )
        };

        let mapped = read(&bytes).unwrap();
        assert!(matches!(mapped, KeyPolys::Mapped(_)));
        assert_eq!(mapped.views()[0][..], source.views()[0][..]);
        assert_eq!(mapped.views()[1][..], source.views()[1][..]);
        let mut roundtrip = Vec::new();
        mapped.write(&mut roundtrip).unwrap();
        assert_eq!(roundtrip, bytes);

        let mut bad_count = bytes.clone();
        bad_count[..4].copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(
            read(&bad_count).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut bad_len = bytes.clone();
        bad_len[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            read(&bad_len).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            read(&bytes[..bytes.len() - 1]).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(dir.path().read_dir().unwrap().count(), 0);
    }
}
