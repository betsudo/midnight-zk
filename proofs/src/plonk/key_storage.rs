//! Owned or read-only mapped proving-key columns.

use std::io;

use ff::PrimeField;
use midnight_curves::serde::SerdeObject;

#[cfg(feature = "disk-spill")]
use super::mmap_pk::{MmappedPolys, spill_iter_to_disk};
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
