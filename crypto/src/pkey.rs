// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

//! Asymmetric encryption / decryption, signing / verification wrapper.
use std::{
    self,
    fmt::{Debug, Formatter},
    result::Result,
};

use openssl::{hash, pkey::{self, Private, Public}, rsa::{self, Rsa}, sign};

use opcua_types::status_code::StatusCode;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum RsaPadding {
    PKCS1,
    OAEP,
    OAEP_SHA256,
    PSS,
}

impl Into<rsa::Padding> for RsaPadding {
    fn into(self) -> rsa::Padding {
        match self {
            RsaPadding::PKCS1 => rsa::Padding::PKCS1,
            RsaPadding::OAEP => rsa::Padding::PKCS1_OAEP,
            RsaPadding::PSS => rsa::Padding::PKCS1_PSS,
            // This is wrong, but it must be handled by special case in the code
            RsaPadding::OAEP_SHA256 => rsa::Padding::PKCS1_OAEP,
            _ => panic!("Unsupported conversion to rsa::Padding")
        }
    }
}

/// This is a wrapper around an `OpenSSL` asymmetric key pair. Since openssl 0.10, the PKey is either
/// a public or private key so we have to differentiate that as well.
pub struct PKey<T> {
    pub(crate) value: pkey::PKey<T>,
}

/// A public key
pub type PublicKey = PKey<pkey::Public>;
// A private key
pub type PrivateKey = PKey<pkey::Private>;

impl<T> Debug for PKey<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // This impl will not write out the key, but it exists to keep structs happy
        // that contain a key as a field
        write!(f, "[pkey]")
    }
}

pub trait KeySize {
    fn bit_length(&self) -> usize;

    fn size(&self) -> usize { self.bit_length() / 8 }

    fn calculate_cipher_text_size(&self, data_size: usize, padding: RsaPadding) -> usize {
        let plain_text_block_size = self.plain_text_block_size(padding);
        let block_count = if data_size % plain_text_block_size == 0 {
            data_size / plain_text_block_size
        } else {
            (data_size / plain_text_block_size) + 1
        };
        block_count * self.cipher_text_block_size()
    }

    fn plain_text_block_size(&self, padding: RsaPadding) -> usize {
        // flen must not be more than RSA_size(rsa) - 11 for the PKCS #1 v1.5 based padding modes,
        // not more than RSA_size(rsa) - 42 for RSA_PKCS1_OAEP_PADDING and exactly RSA_size(rsa)
        // for RSA_NO_PADDING.
        match padding {
            RsaPadding::PKCS1 => self.size() - 11,
            RsaPadding::OAEP => self.size() - 42,
            RsaPadding::OAEP_SHA256 => self.size() - 66,
            _ => panic!("Unsupported padding")
        }
    }

    fn cipher_text_block_size(&self) -> usize {
        self.size()
    }
}

impl KeySize for PrivateKey {
    /// Length in bits
    fn bit_length(&self) -> usize {
        self.value.bits() as usize
    }
}

impl PrivateKey {
    pub fn new(bit_length: u32) -> PrivateKey {
        PKey {
            value: {
                let rsa = rsa::Rsa::generate(bit_length).unwrap();
                pkey::PKey::from_rsa(rsa).unwrap()
            },
        }
    }

    pub fn wrap_private_key(pkey: pkey::PKey<pkey::Private>) -> PrivateKey {
        PrivateKey { value: pkey }
    }

    pub fn from_pem(pem: &[u8]) -> Result<PrivateKey, ()> {
        pkey::PKey::private_key_from_pem(pem)
            .map(|value| PKey { value })
            .map_err(|_| {
                error!("Cannot produce a private key from the data supplied");
            })
    }

    pub fn private_key_to_pem(&self) -> Result<Vec<u8>, ()> {
        self.value.private_key_to_pem_pkcs8()
            .map_err(|_| {
                error!("Cannot turn private key to PEM");
            })
    }

    /// Creates a message digest from the specified block of data and then signs it to return a signature
    fn sign(&self, message_digest: hash::MessageDigest, data: &[u8], signature: &mut [u8], padding: RsaPadding) -> Result<usize, StatusCode> {
        trace!("RSA signing");
        if let Ok(mut signer) = sign::Signer::new(message_digest, &self.value) {
            signer.set_rsa_padding(padding.into()).unwrap();
            if signer.update(data).is_ok() {
                return signer.sign_to_vec()
                    .map(|result| {
                        trace!("Signature result, len {} = {:?}, copying to signature len {}", result.len(), result, signature.len());
                        signature.copy_from_slice(&result);
                        result.len()
                    })
                    .map_err(|err| {
                        debug!("Cannot sign data - error = {:?}", err);
                        StatusCode::BadUnexpectedError
                    });
            }
        }
        Err(StatusCode::BadUnexpectedError)
    }

    /// Signs the data using RSA-SHA1
    pub fn sign_hmac_sha1(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, StatusCode> {
        self.sign(hash::MessageDigest::sha1(), data, signature, RsaPadding::PKCS1)
    }

    /// Signs the data using RSA-SHA256
    pub fn sign_hmac_sha256(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, StatusCode> {
        self.sign(hash::MessageDigest::sha256(), data, signature, RsaPadding::PKCS1)
    }

    /// Signs the data using RSA-SHA256-PSS
    pub fn sign_hmac_sha256_pss(&self, data: &[u8], signature: &mut [u8]) -> Result<usize, StatusCode> {
        self.sign(hash::MessageDigest::sha256(), data, signature, RsaPadding::PSS)
    }

    /// Decrypts data in src to dst using the specified padding and returning the size of the decrypted
    /// data in bytes or an error.
    pub fn private_decrypt(&self, src: &[u8], dst: &mut [u8], padding: RsaPadding) -> Result<usize, ()> {
        // decrypt data using our private key
        let cipher_text_block_size = self.cipher_text_block_size();
        let rsa = self.value.rsa().unwrap();
        let is_oaep_sha256 = padding == RsaPadding::OAEP_SHA256;
        let rsa_padding: rsa::Padding = padding.into();

        // Decrypt the data
        let mut src_idx = 0;
        let mut dst_idx = 0;

        let src_len = src.len();
        while src_idx < src_len {
            // Decrypt and advance
            dst_idx += {
                let src = &src[src_idx..(src_idx + cipher_text_block_size)];
                let dst = &mut dst[dst_idx..(dst_idx + cipher_text_block_size)];

                if is_oaep_sha256 {
                    decrypt_oaep_sha256(&rsa, src, dst)?
                } else {
                    rsa.private_decrypt(src, dst, rsa_padding)
                        .map_err(|err| {
                            error!("Decryption failed for key size {}, src idx {}, dst idx {}, padding {:?}, error - {:?}", cipher_text_block_size, src_idx, dst_idx, padding, err);
                        })?
                }
            };
            src_idx += cipher_text_block_size;
        }
        Ok(dst_idx)
    }
}

impl KeySize for PublicKey {
    /// Length in bits
    fn bit_length(&self) -> usize {
        self.value.bits() as usize
    }
}

impl PublicKey {
    pub fn wrap_public_key(pkey: pkey::PKey<pkey::Public>) -> PublicKey {
        PublicKey { value: pkey }
    }

    /// Verifies that the signature matches the hash / signing key of the supplied data
    fn verify(&self, message_digest: hash::MessageDigest, data: &[u8], signature: &[u8], padding: RsaPadding) -> Result<bool, StatusCode> {
        trace!("RSA verifying, against signature {:?}, len {}", signature, signature.len());
        if let Ok(mut verifier) = sign::Verifier::new(message_digest, &self.value) {
            verifier.set_rsa_padding(padding.into()).unwrap();
            if verifier.update(data).is_ok() {
                return verifier.verify(signature)
                    .map(|result| {
                        trace!("Key verified = {:?}", result);
                        result
                    })
                    .map_err(|err| {
                        debug!("Cannot verify key - error = {:?}", err);
                        StatusCode::BadUnexpectedError
                    });
            }
        }
        Err(StatusCode::BadUnexpectedError)
    }

    /// Verifies the data using RSA-SHA1
    pub fn verify_hmac_sha1(&self, data: &[u8], signature: &[u8]) -> Result<bool, StatusCode> {
        self.verify(hash::MessageDigest::sha1(), data, signature, RsaPadding::PKCS1)
    }

    /// Verifies the data using RSA-SHA256
    pub fn verify_hmac_sha256(&self, data: &[u8], signature: &[u8]) -> Result<bool, StatusCode> {
        self.verify(hash::MessageDigest::sha256(), data, signature, RsaPadding::PKCS1)
    }

    /// Verifies the data using RSA-SHA256-PSS
    pub fn verify_hmac_sha256_pss(&self, data: &[u8], signature: &[u8]) -> Result<bool, StatusCode> {
        self.verify(hash::MessageDigest::sha256(), data, signature, RsaPadding::PSS)
    }

    /// Encrypts data from src to dst using the specified padding and returns the size of encrypted
    /// data in bytes or an error.
    pub fn public_encrypt(&self, src: &[u8], dst: &mut [u8], padding: RsaPadding) -> Result<usize, ()> {
        let cipher_text_block_size = self.cipher_text_block_size();
        let plain_text_block_size = self.plain_text_block_size(padding);

        // For reference:
        //
        // https://www.openssl.org/docs/man1.0.2/crypto/RSA_public_encrypt.html
        let rsa = self.value.rsa().unwrap();
        let is_oaep_sha256 = padding == RsaPadding::OAEP_SHA256;
        let padding: rsa::Padding = padding.into();

        // Encrypt the data in chunks no larger than the key size less padding
        let mut src_idx = 0;
        let mut dst_idx = 0;

        let src_len = src.len();
        while src_idx < src_len {
            let bytes_to_encrypt = if src_len < plain_text_block_size {
                src_len
            } else if (src_len - src_idx) < plain_text_block_size {
                src_len - src_idx
            } else {
                plain_text_block_size
            };

            // Encrypt data, advance dst index by number of bytes after encrypted
            dst_idx += {
                let src = &src[src_idx..(src_idx + bytes_to_encrypt)];
                let dst = &mut dst[dst_idx..(dst_idx + cipher_text_block_size)];

                if is_oaep_sha256 {
                    encrypt_oaep_sha256(&rsa, src, dst)?
                } else {
                    rsa.public_encrypt(src, dst, padding)
                        .map_err(|err| {
                            error!("Encryption failed for bytes_to_encrypt {}, key_size {}, src_idx {}, dst_idx {} error - {:?}", bytes_to_encrypt, cipher_text_block_size, src_idx, dst_idx, err);
                        })?
                }
            };

            // Src advances by bytes to encrypt
            src_idx += bytes_to_encrypt;
        }

        Ok(dst_idx)
    }
}

/// Special case implementation uses OAEP with SHA256
fn decrypt_oaep_sha256(pkey: &Rsa<Private>, from: &[u8], to: &mut [u8]) -> Result<usize, ()> {
    use openssl_sys::*;
    use std::ptr;

    let mut result = Err(());
    unsafe {
        // https://stackoverflow.com/questions/17784022/how-to-encrypt-data-using-rsa-with-sha-256-as-hash-function-and-mgf1-as-mask-ge
        let bioPrivKey = BIO_new(BIO_s_mem());
        if !bioPrivKey.is_null() {
            if PEM_write_bio_RSAPrivateKey(bioPrivKey, pkey.as_ptr(), ptr::null(), ptr::null_mut(), 0, None, ptr::null_mut()) {
                let privKey = PEM_read_bio_PrivateKey(bioPrivKey, ptr::null_mut(), None, ptr::null_mut());
                if !privKey.is_null() {
                    let ctx = EVP_PKEY_CTX_new(privKey, ptr::null_mut());
                    EVP_PKEY_free(privKey);

                    if !ctx.is_null() {

                        EVP_PKEY_CTX_set_rsa_padding(ctx, pad: c_int) -> c_int {
                        EVP_PKEY_CTX_ctrl_str(ctx, "rsa_oaep_md", "sha256");
                        EVP_PKEY_CTX_ctrl_str(ctx, "rsa_mgf1_md", "sha256");

                        let mut outLen: size_t = to.size();
                        let ret = EVP_PKEY_decrypt(ctx, dataOut, &mut outLen, dataIn, from.size());
                        if ret > 0 && outLen > 0 {
                            result = Ok(outLen as usize);
                        }
                        EVP_PKEY_CTX_free(ctx);
                    }
                }
            }
            BIO_free_all(bioPrivKey);
        }
    }
    result
}

/// Special case implementation uses OAEP with SHA256
fn encrypt_oaep_sha256(pkey: &Rsa<Public>, from: &[u8], to: &mut [u8]) -> Result<usize, ()> {
    // TODO special case for OAEP_SHA256
    // https://stackoverflow.com/questions/17784022/how-to-encrypt-data-using-rsa-with-sha-256-as-hash-function-and-mgf1-as-mask-ge
    Err(())
}