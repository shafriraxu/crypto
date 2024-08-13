// Copyright © 2023 Marvin Beckmann
//
// This file is part of qFALL-crypto.
//
// qFALL-crypto is free software: you can redistribute it and/or modify it under
// the terms of the Mozilla Public License Version 2.0 as published by the
// Mozilla Foundation. See <https://mozilla.org/en-US/MPL/2.0/>.

//! This Module contains a general implementation of the [`FDH`] scheme,
//! which only has to be instantiated with a corresponding PSF, a storage and
//! a corresponding hash function.
//!
//! Implementation of a [`FDH`]-signature scheme are thereby fairly easy,
//! see [`FDH::init_gpv`] that works with every PSF and a corresponding hash function

use super::SignatureScheme;
use crate::{construction::hash::HashInto, primitive::psf::PSF};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, marker::PhantomData};

pub mod gpv;
pub mod gpv_ring;
pub mod serialize;

/// This struct captures the general definition of a hash-then-sign signature scheme
/// that uses a hash function as in [\[1\]](<index.html#:~:text=[1]>) and a PSF.
/// An explicit instantiation for defined types makes understanding this struct much
/// easier, compare [`FDH::init_gpv`].
/// This signature scheme uses a storage, so it is stateful.
///
/// Implementing a function for a specific set of types(replacing the generic types)
/// allows for easy implementation of the signature scheme. Any PSF and a corresponding
/// hash-function can be directly translated to an implementation of this signature
/// scheme.
///
/// Attributes
/// - `psf`: The PSF which has to implement the [`PSF`] trait and must also be
///     (de-)serializable.
/// - `storage`: A Hashmap that safes all previously signed messages and their signature
/// - `hash`: The hash-function which has to map a string into the correct domain
///
/// # Example
/// ## Signature Scheme from [`PSFGPV`](crate::primitive::psf::PSFGPV)
/// ```
/// use qfall_crypto::construction::signature::{FDH, SignatureScheme};
///
/// let mut fdh = FDH::init_gpv(4, 113, 17);
///
/// let m = "Hello World!";
///
/// let (pk, sk) = fdh.gen();
/// let sigma = fdh.sign(m.to_owned(), &sk, &pk);
///
/// assert!(fdh.vfy(m.to_owned(), &sigma, &pk));
/// ```
#[derive(Serialize)]
pub struct FDH<
    A,
    Trapdoor,
    Domain: Serialize + for<'a> Deserialize<'a>,
    Range,
    T: PSF<A, Trapdoor, Domain, Range> + Serialize + for<'a> Deserialize<'a>,
    Hash: HashInto<Range> + Serialize + for<'a> Deserialize<'a>,
> {
    pub psf: Box<T>,
    pub storage: HashMap<String, Domain>,
    pub hash: Box<Hash>,

    // The parameters below can be ignored, they are just there for generic usage
    #[serde(skip_serializing)]
    pub _a_type: PhantomData<A>,
    #[serde(skip_serializing)]
    pub _trapdoor_type: PhantomData<Trapdoor>,
    #[serde(skip_serializing)]
    pub _range_type: PhantomData<Range>,
}

impl<A, Trapdoor, Domain, Range, T, Hash> SignatureScheme
    for FDH<A, Trapdoor, Domain, Range, T, Hash>
where
    Domain: Clone + Serialize + for<'a> Deserialize<'a>,
    Range: PartialEq<Range>,
    T: PSF<A, Trapdoor, Domain, Range> + Serialize + for<'a> Deserialize<'a>,
    Hash: HashInto<Range> + Serialize + for<'a> Deserialize<'a>,
{
    type SecretKey = Trapdoor;
    type PublicKey = A;
    type Signature = Domain;

    /// Generates a trapdoor by calling the `trap_gen` of the psf
    fn gen(&mut self) -> (Self::PublicKey, Self::SecretKey) {
        self.psf.trap_gen()
    }

    /// Firstly checks if the message has been signed before, and if, return that
    /// signature, else it continues.
    /// It hashes the message into the domain and then computes a signature using
    /// `samp_p` from the psf with the trapdoor.
    fn sign(&mut self, m: String, sk: &Self::SecretKey, pk: &Self::PublicKey) -> Self::Signature {
        // check if it is in the HashMap
        if let Some(sigma) = self.storage.get(&m) {
            return sigma.clone();
        }

        let u = (self.hash).hash(&m);
        let signature = self.psf.samp_p(pk, sk, &u);

        // insert signature in HashMap
        self.storage.insert(m, signature.clone());
        signature
    }

    /// Checks if a signature is firstly within D_n, and then checks if
    /// the signature is actually a valid preimage under `fa` of `hash(m)`.
    fn vfy(&self, m: String, sigma: &Self::Signature, pk: &Self::PublicKey) -> bool {
        if !self.psf.check_domain(sigma) {
            return false;
        }

        let u = (self.hash).hash(&m);

        self.psf.f_a(pk, sigma) == u
    }
}
