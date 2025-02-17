// Copyright © 2023 Phil Milewski
//
// This file is part of qFALL-crypto.
//
// qFALL-crypto is free software: you can redistribute it and/or modify it under
// the terms of the Mozilla Public License Version 2.0 as published by the
// Mozilla Foundation. See <https://mozilla.org/en-US/MPL/2.0/>.

//! This module contains an implementation of the IND-CPA secure
//! identity based public key encryption scheme. The encryption scheme is based
//! on [`DualRegevIBE`].

use super::IBEScheme;
use crate::{
    construction::{
        hash::sha256::hash_to_mat_zq_sha256,
        pk_encryption::{DualRegev, PKEncryptionScheme},
    },
    primitive::psf::{PSF, PSFGPV},
    sample::g_trapdoor::gadget_parameters::GadgetParameters,
};
use qfall_math::{
    error::MathError,
    integer::{MatZ, Z},
    integer_mod_q::{MatZq, Modulus},
    rational::{MatQ, Q},
    traits::{Concatenate, GetNumRows, Pow},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// This struct manages and stores the public parameters of a [`IBEScheme`]
/// public key encryption instance based on [\[1\]](<index.html#:~:text=[1]>).
///
/// Attributes:
/// - `r`: specifies the Gaussian parameter used by the [`PSF`]
/// - `dual_regev`: a [`DualRegev`] instance with fitting parameters `n`, `m`, `q`, `alpha`
/// - `psf`: specifies the PSF used for extracting secret keys
/// - `storage`: is a [`HashMap`] which stores all previously computed secret keys
///     corresponding to their identities
///
/// # Examples
/// ```
/// use qfall_crypto::construction::identity_based_encryption::{DualRegevIBE, IBEScheme};
/// use qfall_math::integer::Z;
/// // setup public parameters and key pair
/// let mut ibe = DualRegevIBE::default();
/// let (pk, sk) = ibe.setup();
///
/// // extract a identity based secret key
/// let identity = String::from("identity");
/// let id_sk = ibe.extract(&pk, &sk, &identity);
///
/// // encrypt a bit
/// let msg = Z::ZERO; // must be a bit, i.e. msg = 0 or 1
/// let cipher = ibe.enc(&pk, &identity, &msg);
///
/// // decrypt
/// let m = ibe.dec(&id_sk, &cipher);
///
/// assert_eq!(msg, m)
/// ```
#[derive(Serialize, Deserialize)]
pub struct DualRegevIBE {
    pub dual_regev: DualRegev,
    pub psf: PSFGPV,
    storage: HashMap<String, MatZ>,
}

impl DualRegevIBE {
    /// Initializes a [`DualRegevIBE`] struct with parameters generated by
    /// `DualRegev::new(n, q, r, alpha)`
    ///
    /// Returns an [`DualRegevIBE`] instance.
    ///
    /// # Examples
    /// ```
    /// use qfall_crypto::construction::identity_based_encryption::DualRegevIBE;
    ///
    /// let ibe = DualRegevIBE::new(4, 54983, 14, 0.0025);
    /// ```
    pub fn new(
        n: impl Into<Z>,       // security parameter
        q: impl Into<Modulus>, // modulus
        r: impl Into<Q>,       // Gaussian parameter for sampleD
        alpha: impl Into<Q>,   // Gaussian parameter for sampleZ
    ) -> Self {
        let n = n.into();
        let q = q.into();
        let r = r.into();
        let alpha = alpha.into();

        let gadget = GadgetParameters::init_default(&n, &q);

        let log_q = Z::from(&q).log_ceil(2).unwrap();
        let n_log_q = &n * &log_q;
        let m = &gadget.m_bar + n_log_q;

        let psf = PSFGPV { gp: gadget, s: r };
        Self {
            psf,
            dual_regev: DualRegev::new(n, m, q, alpha),
            storage: HashMap::new(),
        }
    }

    /// Initializes a [`DualRegevIBE`] struct with parameters generated by `DualRegev::new_from_n(n)`.
    ///
    /// **WARNING:** Due to the [`PSF`] this schemes extract algorithm is slow for n > 5.
    ///
    /// Returns an [`DualRegevIBE`] instance.
    ///
    /// # Examples
    /// ```
    /// use qfall_crypto::construction::identity_based_encryption::DualRegevIBE;
    ///
    /// let dual_regev = DualRegevIBE::new_from_n(4);
    /// ```
    pub fn new_from_n(n: impl Into<Z>) -> Self {
        let n: Z = n.into();
        if n < Z::from(2) {
            panic!("Security parameter n has to be larger than 1");
        }

        let n_i64 = i64::try_from(&n).unwrap();
        // these powers are chosen according to experience s.t. at least every
        // fifth generation of public parameters outputs a valid pair
        // the exponent is only tested for n < 8
        let power = match n_i64 {
            2..=3 => 10,
            4 => 7,
            5..=7 => 6,
            _ => 5,
        };

        // generate prime q in [n^power / 2, n^power]
        let upper_bound: Z = n.pow(power).unwrap();
        let lower_bound = upper_bound.div_ceil(2);
        // prime used due to guide from GPV08 after Proposition 8.1
        // on how to choose appropriate parameters, but prime is not
        // necessarily needed for this scheme to be correct or secure
        let q = Modulus::from(Z::sample_prime_uniform(&lower_bound, &upper_bound).unwrap());

        let gadget = GadgetParameters::init_default(&n, &q);
        let log_q = Z::from(&q).log_ceil(2).unwrap();
        let n_log_q = &n * &log_q;

        // m is computed due to the [`PSFGPV`] implementation
        let m = &gadget.m_bar + n_log_q;
        let r: Q = m.sqrt();
        let alpha = 1 / (&r * 2 * (&m + Z::ONE).sqrt() * (n).log(2).unwrap());

        let psf = PSFGPV { gp: gadget, s: r };
        Self {
            psf,
            dual_regev: DualRegev::new(n, m, q, alpha),
            storage: HashMap::new(),
        }
    }

    /// Checks the public parameters for security according to Theorem 1.1
    /// and Lemma 5.4 of [\[2\]](<index.html#:~:text=[2]>), as well as
    /// the requirements of [\[1\]](<index.html#:~:text=[1]>)`s eprint version
    /// at Section 7.1 of [GPV08 - eprint](https://eprint.iacr.org/2007/432.pdf).
    ///
    /// The required properties are:
    /// - q >= 5 * r * (m + 1)
    /// - r >= sqrt(m)
    /// - m > (n + 1) * log(q)
    ///
    /// Returns an empty result if the public parameters guarantees security w.r.t. `n`
    /// or a [`MathError`] if the instance would not be secure.
    ///
    /// # Examples
    /// ```
    /// use qfall_crypto::construction::identity_based_encryption::DualRegevIBE;
    /// let ibe = DualRegevIBE::default();
    ///
    /// assert!(ibe.check_security().is_ok());
    /// ```
    ///
    /// # Errors and Failures
    /// - Returns a [`MathError`] of type [`InvalidIntegerInput`](MathError::InvalidIntegerInput)
    ///     if at least one parameter was not chosen appropriately for a
    ///     secure Dual Regev public key encryption instance.
    pub fn check_security(&self) -> Result<(), MathError> {
        let q = Q::from(&self.dual_regev.q);

        // Security requirements
        // q >= 5 * r * (m + 1)
        if q < (5 * &self.psf.s) * (&self.dual_regev.m + Q::ONE) {
            return Err(MathError::InvalidIntegerInput(String::from(
                "Security is not guaranteed as q < 5 * r * (m + 1), but q >= 5 * r * (m + 1) is required.",
            )));
        }

        // r >= sqrt(m)
        if self.psf.s < self.dual_regev.m.sqrt() {
            return Err(MathError::InvalidIntegerInput(String::from(
                "Security is not guaranteed as r < sqrt(m), but r >= sqrt(m) is required.",
            )));
        }

        // m >= (n + 1) * log(q)
        if Q::from(&self.dual_regev.m) <= (&self.dual_regev.n + 1) * &q.log(2).unwrap() {
            return Err(MathError::InvalidIntegerInput(String::from(
                "Security is not guaranteed as m <= (n + 1) * log(q), \
                but m > (n + 1) * log(q) is required.",
            )));
        }

        Ok(())
    }

    /// Checks the public parameters for
    /// correctness according to Lemma 5.1 of [\[2\]](<index.html#:~:text=[2]>).
    ///
    /// The required properties are:
    /// - α <= 1/(2 * r * sqrt(m) * log(n))
    ///
    /// **WARNING:** Some requirements are missing to ensure overwhelming correctness of the scheme.
    ///
    /// Returns an empty result if the public parameters guarantee correctness
    /// with overwhelming probability or a [`MathError`] if the instance would
    /// not be correct.
    ///
    /// # Examples
    /// ```
    /// use qfall_crypto::construction::identity_based_encryption::DualRegevIBE;
    /// let ibe = DualRegevIBE::default();
    ///
    /// assert!(ibe.check_correctness().is_ok());
    /// ```
    ///
    /// # Errors and Failures
    /// - Returns a [`MathError`] of type [`InvalidIntegerInput`](MathError::InvalidIntegerInput)
    ///     if at least one parameter was not chosen appropriately for a
    ///     correct Dual Regev IBE public key encryption instance.
    pub fn check_correctness(&self) -> Result<(), MathError> {
        if self.dual_regev.n <= Z::ONE {
            return Err(MathError::InvalidIntegerInput(String::from(
                "n must be chosen bigger than 1.",
            )));
        }

        // α <= 1/(2 * r * sqrt(m) * log(n))
        if self.dual_regev.alpha
            > 1 / (2 * &self.psf.s * (&self.dual_regev.m + Z::ONE).sqrt())
                * self.dual_regev.n.log(2).unwrap()
        {
            return Err(MathError::InvalidIntegerInput(String::from(
                "Correctness is not guaranteed as α > 1/(r * sqrt(m) * log(n)), but α <= 1/(2 * r * sqrt(m) * log(n)) is required.",
            )));
        }

        Ok(())
    }
}

impl Default for DualRegevIBE {
    /// Initializes a [`DualRegevIBE`] struct with parameters generated by `DualRegevIBE::new_from_n(4)`.
    /// This parameter choice is not secure as the dimension of the lattice is too small,
    /// but it provides an efficient working example.
    ///
    /// Returns an [`DualRegevIBE`] instance.
    ///
    /// # Examples
    /// ```
    /// use qfall_crypto::construction::identity_based_encryption::DualRegevIBE;
    ///
    /// let ibe = DualRegevIBE::default();
    /// ```
    fn default() -> Self {
        DualRegevIBE::new_from_n(4)
    }
}

impl IBEScheme for DualRegevIBE {
    type Cipher = MatZq;
    type MasterPublicKey = MatZq;
    type MasterSecretKey = (MatZ, MatQ);
    type SecretKey = MatZ;
    type Identity = String;

    /// Generates a (pk, sk) pair for the Dual Regev public key encryption scheme
    /// by following these steps:
    /// - s <- Z_q^n
    /// - A <- Z_q^{n x m}
    /// - x <- χ^m
    /// - p = A^t * s + x
    ///
    /// Then, `pk = (A, p)` and `sk = s` is output.
    ///
    /// # Examples
    /// ```
    /// use qfall_crypto::construction::identity_based_encryption::{DualRegevIBE, IBEScheme};
    /// let ibe = DualRegevIBE::default();
    ///
    /// let (pk, sk) = ibe.setup();
    /// ```
    fn setup(&self) -> (Self::MasterPublicKey, Self::MasterSecretKey) {
        self.psf.trap_gen()
    }

    /// Given an identity it extracts a corresponding secret key by using samp_p
    /// of the given [`PSF`].
    ///
    /// Parameters:
    /// - `master_pk`: The master public key for the encryption scheme
    /// - `master_sk`: Zhe master secret key of the encryption scheme, namely
    ///     the trapdoor for the [`PSF`]
    /// - `identity`: The identity, for which the corresponding secret key
    ///     should be returned
    ///
    /// Returns the corresponding secret key of `identity` under public key
    /// `master_pk`.
    ///
    /// # Examples
    /// ```
    /// use qfall_crypto::construction::identity_based_encryption::{IBEScheme, DualRegevIBE};
    /// let mut ibe = DualRegevIBE::default();
    /// let (master_pk, master_sk) = ibe.setup();
    ///
    /// let id = String::from("identity");
    /// let sk = ibe.extract(&master_pk, &master_sk, &id);
    /// ```
    fn extract(
        &mut self,
        master_pk: &Self::MasterPublicKey,
        master_sk: &Self::MasterSecretKey,
        identity: &Self::Identity,
    ) -> Self::SecretKey {
        // check if it is in the HashMap
        if let Some(value) = self.storage.get(&format!(
            "{master_pk} {} {} {identity}",
            master_sk.0, master_sk.1
        )) {
            return value.clone();
        }

        let u = hash_to_mat_zq_sha256(identity, &self.dual_regev.n, 1, &self.dual_regev.q);
        let secret_key = self.psf.samp_p(master_pk, master_sk, &u);

        // insert secret key in HashMap
        self.storage.insert(
            format!("{master_pk} {} {} {identity}", master_sk.0, master_sk.1),
            secret_key.clone(),
        );

        secret_key
    }

    /// Generates an encryption of `message mod 2` for the provided public key
    /// and identity by by calling [`DualRegev::enc()`] on
    /// pk = [master_pk | H(id)] which corresponds to to [A | u] in
    /// [GPV08 - eprint](https://eprint.iacr.org/2007/432.pdf).
    /// Constructing the public key this way yields a identity based public key
    /// which secret key can be extracted by the [`PSF`].
    ///
    /// Then, `cipher = [u | c]` is output.
    ///
    /// Parameters:
    /// - `master_pk`: specifies the public key, which cis matrix `pk = A`
    /// - `identity`: specifies the identity used for encryption
    /// - `message`: specifies the message that should be encrypted
    ///
    /// Returns a cipher of type [`MatZq`] for master_pk an identity.
    ///
    /// # Examples
    /// ```
    /// use qfall_crypto::construction::identity_based_encryption::{DualRegevIBE, IBEScheme};
    /// let ibe = DualRegevIBE::default();
    /// let (pk, sk) = ibe.setup();
    ///
    /// let id = String::from("identity");
    /// let cipher = ibe.enc(&pk, &id, 1);
    /// ```
    fn enc(
        &self,
        master_pk: &Self::MasterPublicKey,
        identity: &Self::Identity,
        message: impl Into<Z>,
    ) -> Self::Cipher {
        let identity_based_pk =
            hash_to_mat_zq_sha256(identity, master_pk.get_num_rows(), 1, master_pk.get_mod());
        self.dual_regev.enc(
            &master_pk.concat_horizontal(&identity_based_pk).unwrap(),
            message,
        )
    }

    /// Decrypts the provided `cipher` using the secret key `sk` by using
    /// [`DualRegev::dec()`]
    ///
    /// Parameters:
    /// - `sk_id`: specifies the secret key `sk = s` obtained by extract
    /// - `cipher`: specifies the cipher containing `cipher = c`
    ///
    /// Returns the decryption of `cipher` as a [`Z`] instance.
    ///
    /// # Examples
    /// ```
    /// use qfall_crypto::construction::identity_based_encryption::{DualRegevIBE, IBEScheme};
    /// use qfall_math::integer::Z;
    /// // setup public parameters and key pair
    /// let mut ibe = DualRegevIBE::default();
    /// let (pk, sk) = ibe.setup();
    ///
    /// // extract a identity based secret key
    /// let identity = String::from("identity");
    /// let id_sk = ibe.extract(&pk, &sk, &identity);
    ///
    /// // encrypt a bit
    /// let msg = Z::ZERO; // must be a bit, i.e. msg = 0 or 1
    /// let cipher = ibe.enc(&pk, &identity, &msg);
    ///
    /// // decrypt
    /// let m = ibe.dec(&id_sk, &cipher);
    ///
    /// assert_eq!(msg, m)
    /// ```
    fn dec(&self, sk_id: &Self::SecretKey, cipher: &Self::Cipher) -> Z {
        self.dual_regev.dec(sk_id, cipher)
    }
}

#[cfg(test)]
mod test_dual_regev_ibe {
    use super::DualRegevIBE;
    use crate::construction::identity_based_encryption::IBEScheme;
    use qfall_math::integer::Z;

    /// Checks whether `new` is available for types implementing [`Into<Z>`].
    #[test]
    fn new_availability() {
        let _ = DualRegevIBE::new(2u8, 2u16, 2u32, 2u64);
        let _ = DualRegevIBE::new(2u16, 2u64, 2i32, 2i64);
        let _ = DualRegevIBE::new(2i16, 2i64, 2u32, 2u8);
        let _ = DualRegevIBE::new(Z::from(2), Z::from(2), 2u8, 2i8);
    }

    /// Ensures that `new_from_n` is available for types implementing [`Into<Z>`].
    #[test]
    #[allow(clippy::needless_borrows_for_generic_args)]
    fn availability() {
        let _ = DualRegevIBE::new_from_n(4u8);
        let _ = DualRegevIBE::new_from_n(4u16);
        let _ = DualRegevIBE::new_from_n(4u32);
        let _ = DualRegevIBE::new_from_n(4u64);
        let _ = DualRegevIBE::new_from_n(4i8);
        let _ = DualRegevIBE::new_from_n(4i16);
        let _ = DualRegevIBE::new_from_n(4i32);
        let _ = DualRegevIBE::new_from_n(4i64);
        let _ = DualRegevIBE::new_from_n(Z::from(4));
        let _ = DualRegevIBE::new_from_n(&Z::from(4));
    }

    /// Checks whether `new_from_n` returns an error for invalid input n.
    #[test]
    #[should_panic]
    fn invalid_n() {
        DualRegevIBE::new_from_n(1);
    }

    /// Checks whether the full-cycle of gen, extract, enc, dec works properly
    /// for message 0 and the default.
    #[test]
    fn cycle_zero_default() {
        let msg = Z::ZERO;
        let id = String::from("Hello World!");
        let mut cryptosystem = DualRegevIBE::default();

        let (pk, sk) = cryptosystem.setup();
        let id_sk = cryptosystem.extract(&pk, &sk, &id);
        let cipher = cryptosystem.enc(&pk, &id, &msg);
        let m = cryptosystem.dec(&id_sk, &cipher);

        assert_eq!(msg, m)
    }

    /// Checks whether the full-cycle of gen, extract, enc, dec works properly
    /// for message 1 and the default.
    #[test]
    fn cycle_one_default() {
        let msg = Z::ONE;
        let id = String::from("Hello World!");
        let mut cryptosystem = DualRegevIBE::default();

        let (pk, sk) = cryptosystem.setup();
        let id_sk = cryptosystem.extract(&pk, &sk, &id);
        let cipher = cryptosystem.enc(&pk, &id, &msg);
        let m = cryptosystem.dec(&id_sk, &cipher);

        assert_eq!(msg, m)
    }

    /// Checks whether the full-cycle of gen, extract, enc, dec works properly
    /// for message 0 and small n.
    #[test]
    fn cycle_zero_small_n() {
        let msg = Z::ZERO;
        let id = String::from("Hel213lo World!");
        let mut cryptosystem = DualRegevIBE::new_from_n(5);

        let (pk, sk) = cryptosystem.setup();
        let id_sk = cryptosystem.extract(&pk, &sk, &id);
        let cipher = cryptosystem.enc(&pk, &id, &msg);
        let m = cryptosystem.dec(&id_sk, &cipher);
        assert_eq!(msg, m);
    }

    /// Checks whether the full-cycle of gen, extract, enc, dec works properly
    /// for message 1 and small n.
    #[test]
    fn cycle_one_small_n() {
        let msg = Z::ONE;
        let id = String::from("Hel213lo World!");
        let mut cryptosystem = DualRegevIBE::new_from_n(5);

        let (pk, sk) = cryptosystem.setup();
        let id_sk = cryptosystem.extract(&pk, &sk, &id);
        let cipher = cryptosystem.enc(&pk, &id, &msg);
        let m = cryptosystem.dec(&id_sk, &cipher);
        assert_eq!(msg, m);
    }

    /// multi test for different identities, message 1 and small n
    #[test]
    fn new_from_n() {
        for i in 1..=5 {
            let msg = Z::ONE;
            let id = format!("Hello World!{i}");
            let mut cryptosystem = DualRegevIBE::default();

            cryptosystem.check_security().unwrap();
            cryptosystem.check_correctness().unwrap();

            let (pk, sk) = cryptosystem.setup();

            let id_sk = cryptosystem.extract(&pk, &sk, &id);
            for _j in 1..=100 {
                let cipher = cryptosystem.enc(&pk, &id, &msg);
                let m = cryptosystem.dec(&id_sk, &cipher);

                assert_eq!(msg, m);
            }
        }
    }

    /// checking whether the storage works properly
    #[test]
    fn extract_storage_same_identity_mk_pk() {
        let id = "Hello World!".to_string();
        let mut cryptosystem = DualRegevIBE::default();
        let (pk, sk) = cryptosystem.setup();

        let id_sk_1 = cryptosystem.extract(&pk, &sk, &id);
        let id_sk_2 = cryptosystem.extract(&pk, &sk, &id);

        assert_eq!(id_sk_1, id_sk_2)
    }

    /// checking whether the storage works properly for different master secret and public key
    /// may fail with small probability
    #[test]
    fn extract_storage_same_identity_different_mk_pk() {
        let id = "Hello World!".to_string();
        let mut cryptosystem = DualRegevIBE::default();
        let (pk_1, sk_1) = cryptosystem.setup();
        let (pk_2, sk_2) = cryptosystem.setup();

        let id_sk_1 = cryptosystem.extract(&pk_1, &sk_1, &id);
        let id_sk_2 = cryptosystem.extract(&pk_2, &sk_2, &id);

        assert_ne!(id_sk_1, id_sk_2)
    }
}
