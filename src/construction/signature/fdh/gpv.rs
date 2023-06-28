// Copyright © 2023 Marvin Beckmann
//
// This file is part of qFALL-crypto.
//
// qFALL-crypto is free software: you can redistribute it and/or modify it under
// the terms of the Mozilla Public License Version 2.0 as published by the
// Mozilla Foundation. See <https://mozilla.org/en-US/MPL/2.0/>.

//! A classical implementation of the [`Fdh`] scheme using the [`PSFGPV`]
//! according to [\[1\]](<../index.html#:~:text=[1]>).

use super::Fdh;
use crate::{
    primitive::hash::HashMatZq,
    sample::{distribution::psf::gpv::PSFGPV, g_trapdoor::gadget_parameters::GadgetParameters},
};
use qfall_math::{
    integer::{MatZ, Z},
    integer_mod_q::{MatZq, Modulus},
    rational::Q,
};
use std::{collections::HashMap, marker::PhantomData};

impl Fdh<MatZq, MatZ, MatZ, MatZq, PSFGPV, HashMatZq> {
    /// Initializes an FDH signature scheme from a [`PSFGPV`].
    ///
    /// This function corresponds to an implementation of an FDH-signature
    /// scheme with the explicit PSF [`PSFGPV`] which is generated using
    /// the default of [`GadgetParameters`].
    ///
    /// Parameters:
    /// - `n`: The security parameter
    /// - `modulus`: The modulus used for the G-Trapdoors
    /// - `s`: The standard deviation with which is sampled
    ///
    /// Returns an explicit implementation of a FDH-signature scheme.
    ///
    /// # Example
    /// ```
    /// use qfall_crypto::construction::signature::fdh::Fdh;
    /// use qfall_math::integer::Z;
    /// use qfall_math::integer_mod_q::Modulus;
    /// use qfall_math::rational::Q;
    /// use crate::qfall_crypto::construction::signature::SignatureScheme;
    ///
    /// let s = Q::from(17);
    /// let n = Z::from(4);
    /// let modulus = Modulus::try_from(&Z::from(113)).unwrap();
    ///
    /// let mut fdh = Fdh::init_gpv(n, &modulus, &s);
    ///
    /// let m = "Hello World!";
    ///
    /// let (pk, sk) = fdh.gen();
    /// let sigma = fdh.sign(m.to_owned(), &sk, &pk);
    ///
    /// assert_eq!(&sigma, &fdh.sign(m.to_owned(), &sk, &pk));
    /// // TODO: include once all parameters are revised
    /// // assert!(fdh.vfy(m.to_owned(), &sigma, &pk))
    /// ```
    pub fn init_gpv(n: impl Into<Z>, modulus: &Modulus, s: &Q) -> Self {
        let n = n.into();
        let psf = PSFGPV {
            gp: GadgetParameters::init_default(&n, modulus),
            s: s.clone(),
        };
        let n = i64::try_from(&n).unwrap();
        let modulus = modulus.clone();
        Self {
            psf: Box::new(psf),
            storage: HashMap::new(),
            hash: Box::new(HashMatZq {
                modulus,
                rows: n,
                cols: 1,
            }),
            _a_type: PhantomData,
            _trapdoor_type: PhantomData,
            _range_type: PhantomData,
        }
    }
}

#[cfg(test)]
mod text_fdh {
    use super::Fdh;
    use crate::{
        construction::signature::SignatureScheme, primitive::hash::HashMatZq,
        sample::distribution::psf::gpv::PSFGPV,
    };
    use qfall_math::{
        integer::{MatZ, Z},
        integer_mod_q::{MatZq, Modulus},
        rational::Q,
    };

    /// Ensure that the generated signature is valid
    #[ignore = "Currently fails, because vectors sometimes a little bit too large: TODO see issue"]
    #[test]
    fn ensure_valid_signature_is_generated() {
        let s = Q::from(250);
        let n = Z::from(8);
        let modulus = Modulus::try_from(&Z::from(113)).unwrap();

        let mut fdh = Fdh::init_gpv(n, &modulus, &s);

        let m = "Hello World!";

        let (pk, sk) = fdh.gen();
        let sigma = fdh.sign(m.to_owned(), &sk, &pk);
        println!("{}", sigma);

        assert_eq!(&sigma, &fdh.sign(m.to_owned(), &sk, &pk));
        assert!(fdh.vfy(m.to_owned(), &sigma, &pk))
    }

    /// Ensure that an entry is actually added to the local storage
    #[test]
    fn storage_filled() {
        let s = Q::from(10);
        let n = Z::from(5);
        let modulus = Modulus::try_from(&Z::from(1024)).unwrap();

        let mut fdh = Fdh::init_gpv(n, &modulus, &s);

        let m = "Hello World!";
        let (pk, sk) = fdh.gen();
        let _ = fdh.sign(m.to_owned(), &sk, &pk);

        assert!(fdh.storage.contains_key(m))
    }

    /// Ensure that after deserialization the HashMap still contains all entries.
    #[test]
    fn reload_hashmap() {
        let s = Q::from(10);
        let n = Z::from(5);
        let modulus = Modulus::try_from(&Z::from(1024)).unwrap();

        let mut fdh = Fdh::init_gpv(&n, &modulus, &s);

        // fill one entry in the HashMap
        let m = "Hello World!";
        let (pk, sk) = fdh.gen();
        let _ = fdh.sign(m.to_owned(), &sk, &pk);

        let fdh_string = serde_json::to_string(&fdh).expect("Unable to create a json object");
        println!("{}", fdh_string);
        let fdh_2: Fdh<MatZq, MatZ, MatZ, MatZq, PSFGPV, HashMatZq> =
            serde_json::from_str(&fdh_string).unwrap();

        assert_eq!(fdh.storage, fdh_2.storage);
    }
}