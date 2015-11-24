// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use cbor::{Config, Decoder, Encoder};
use cbor::skip::Skip;
use elliptic::curve25519;
use internal::types::{DecodeError, DecodeResult, EncodeResult};
use internal::util::{Bytes64, Bytes32, fmt_hex, opt};
use sodiumoxide::randombytes;
use std::fmt::{self, Debug, Formatter, Error};
use std::io::{Cursor, Read, Write};
use std::slice::bytes::copy_memory;
use std::u16;
use std::vec::Vec;

// Identity Key /////////////////////////////////////////////////////////////

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct IdentityKey {
    pub public_key: PublicKey
}

impl IdentityKey {
    pub fn new(k: PublicKey) -> IdentityKey {
        IdentityKey { public_key: k }
    }

    pub fn fingerprint(&self) -> String {
        self.public_key.fingerprint()
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(1));
        try!(e.u8(0)); self.public_key.encode(e)
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<IdentityKey> {
        let n = try!(d.object());
        let mut public_key = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => public_key = Some(try!(PublicKey::decode(d))),
                _ => try!(d.skip())
            }
        }
        Ok(IdentityKey {
            public_key: to_field!(public_key, "IdentityKey::public_key")
        })
    }
}

// Identity Keypair /////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct IdentityKeyPair {
    pub version:    u8,
    pub secret_key: SecretKey,
    pub public_key: IdentityKey
}

impl IdentityKeyPair {
    pub fn new() -> IdentityKeyPair {
        let k = KeyPair::new();
        IdentityKeyPair {
            version:    1,
            secret_key: k.secret_key,
            public_key: IdentityKey { public_key: k.public_key }
        }
    }

    pub fn serialise(&self) -> EncodeResult<Vec<u8>> {
        let mut e = Encoder::new(Cursor::new(Vec::new()));
        try!(self.encode(&mut e));
        Ok(e.into_writer().into_inner())
    }

    pub fn deserialise(b: &[u8]) -> DecodeResult<IdentityKeyPair> {
        IdentityKeyPair::decode(&mut Decoder::new(Config::default(), Cursor::new(b)))
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(3));
        try!(e.u8(0)); try!(e.u8(self.version));
        try!(e.u8(1)); try!(self.secret_key.encode(e));
        try!(e.u8(2)); self.public_key.encode(e)
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<IdentityKeyPair> {
        let n = try!(d.object());
        let mut version    = None;
        let mut secret_key = None;
        let mut public_key = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => version    = Some(try!(d.u8())),
                1 => secret_key = Some(try!(SecretKey::decode(d))),
                2 => public_key = Some(try!(IdentityKey::decode(d))),
                _ => try!(d.skip())
            }
        }
        Ok(IdentityKeyPair {
            version:    to_field!(version, "IdentityKeyPair::version"),
            secret_key: to_field!(secret_key, "IdentityKeyPair::secret_key"),
            public_key: to_field!(public_key, "IdentityKeyPair::public_key")
        })
    }
}

// Prekey ///////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct PreKey {
    pub version:  u8,
    pub key_id:   PreKeyId,
    pub key_pair: KeyPair
}

impl PreKey {
    pub fn new(i: PreKeyId) -> PreKey {
        PreKey {
            version: 1,
            key_id: i,
            key_pair: KeyPair::new()
        }
    }

    pub fn last_resort() -> PreKey {
        PreKey::new(MAX_PREKEY_ID)
    }

    pub fn serialise(&self) -> EncodeResult<Vec<u8>> {
        let mut e = Encoder::new(Cursor::new(Vec::new()));
        try!(self.encode(&mut e));
        Ok(e.into_writer().into_inner())
    }

    pub fn deserialise(b: &[u8]) -> DecodeResult<PreKey> {
        PreKey::decode(&mut Decoder::new(Config::default(), Cursor::new(b)))
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(3));
        try!(e.u8(0)); try!(e.u8(self.version));
        try!(e.u8(1)); try!(self.key_id.encode(e));
        try!(e.u8(2)); self.key_pair.encode(e)
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<PreKey> {
        let n = try!(d.object());
        let mut version  = None;
        let mut key_id   = None;
        let mut key_pair = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => version  = Some(try!(d.u8())),
                1 => key_id   = Some(try!(PreKeyId::decode(d))),
                2 => key_pair = Some(try!(KeyPair::decode(d))),
                _ => try!(d.skip())
            }
        }
        Ok(PreKey {
            version:  to_field!(version, "PreKey::version"),
            key_id:   to_field!(key_id, "PreKey::key_id"),
            key_pair: to_field!(key_pair, "PreKey::key_pair")
        })
    }
}

pub fn gen_prekeys(start: PreKeyId, size: u16) -> Vec<PreKey> {
    (1 ..).map(|i| ((start.value() as u32 + i) % (MAX_PREKEY_ID.value() as u32)))
          .map(|i| PreKey::new(PreKeyId::new(i as u16)))
          .take(size as usize)
          .collect()
}

// Prekey bundle ////////////////////////////////////////////////////////////

#[derive(PartialEq, Eq, Debug)]
pub enum PreKeyAuth {
    Invalid,
    Valid,
    Unknown
}

#[derive(PartialEq, Eq, Debug)]
pub struct PreKeyBundle {
    pub version:      u8,
    pub prekey_id:    PreKeyId,
    pub public_key:   PublicKey,
    pub identity_key: IdentityKey,
    pub signature:    Option<Signature>
}

impl PreKeyBundle {
    pub fn new(ident: IdentityKey, key: &PreKey) -> PreKeyBundle {
        PreKeyBundle {
            version:      1,
            prekey_id:    key.key_id,
            public_key:   key.key_pair.public_key,
            identity_key: ident,
            signature:    None
        }
    }

    pub fn signed(ident: &IdentityKeyPair, key: &PreKey) -> PreKeyBundle {
        let ratchet_key = key.key_pair.public_key;
        let signature   = ident.secret_key.sign(&ratchet_key.0);
        PreKeyBundle {
            version:      1,
            prekey_id:    key.key_id,
            public_key:   ratchet_key,
            identity_key: ident.public_key,
            signature:    Some(signature)
        }
    }

    pub fn verify(&self) -> PreKeyAuth {
        match self.signature {
            Some(ref sig) =>
                if self.identity_key.public_key.verify(sig, &self.public_key.0) {
                    PreKeyAuth::Valid
                } else {
                    PreKeyAuth::Invalid
                },
            None => PreKeyAuth::Unknown
        }
    }

    pub fn serialise(&self) -> EncodeResult<Vec<u8>> {
        let mut e = Encoder::new(Cursor::new(Vec::new()));
        try!(self.encode(&mut e));
        Ok(e.into_writer().into_inner())
    }

    pub fn deserialise(b: &[u8]) -> DecodeResult<PreKeyBundle> {
        PreKeyBundle::decode(&mut Decoder::new(Config::default(), Cursor::new(b)))
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(5));
        try!(e.u8(0)); try!(e.u8(self.version));
        try!(e.u8(1)); try!(self.prekey_id.encode(e));
        try!(e.u8(2)); try!(self.public_key.encode(e));
        try!(e.u8(3)); try!(self.identity_key.encode(e));
        try!(e.u8(4)); match self.signature {
            Some(ref sig) => sig.encode(e),
            None          => e.null().map_err(From::from)
        }
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<PreKeyBundle> {
        let n = try!(d.object());
        let mut version      = None;
        let mut prekey_id    = None;
        let mut public_key   = None;
        let mut identity_key = None;
        let mut signature    = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => version      = Some(try!(d.u8())),
                1 => prekey_id    = Some(try!(PreKeyId::decode(d))),
                2 => public_key   = Some(try!(PublicKey::decode(d))),
                3 => identity_key = Some(try!(IdentityKey::decode(d))),
                4 => signature    = try!(opt(Signature::decode(d))),
                _ => try!(d.skip())
            }
        }
        Ok(PreKeyBundle {
            version:      to_field!(version, "PreKeyBundle::version"),
            prekey_id:    to_field!(prekey_id, "PreKeyBundle::prekey_id"),
            public_key:   to_field!(public_key, "PreKeyBundle::public_key"),
            identity_key: to_field!(identity_key, "PreKeyBundle::identity_key"),
            signature:    signature
        })
    }
}

// Prekey ID ////////////////////////////////////////////////////////////////

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PreKeyId(u16);

pub const MAX_PREKEY_ID: PreKeyId = PreKeyId(u16::MAX);

impl PreKeyId {
    pub fn new(i: u16) -> PreKeyId {
        PreKeyId(i)
    }

    pub fn value(&self) -> u16 {
        self.0
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.u16(self.0).map_err(From::from)
    }

    pub fn decode<R: Read>(d: &mut Decoder<R>) -> DecodeResult<PreKeyId> {
        d.u16().map(PreKeyId).map_err(From::from)
    }
}

impl fmt::Display for PreKeyId {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0)
    }
}

// Keypair //////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct KeyPair {
    pub secret_key: SecretKey,
    pub public_key: PublicKey
}

impl KeyPair {
    pub fn new() -> KeyPair {
        let mut sk = [0u8; 32];
        copy_memory(&rand_bytes(32), &mut sk);
        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;
        let pk = curve25519::keygen(&sk);
        KeyPair {
            secret_key: SecretKey(sk),
            public_key: PublicKey(pk)
        }
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(2));
        try!(e.u8(0)); try!(self.secret_key.encode(e));
        try!(e.u8(1)); self.public_key.encode(e)
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<KeyPair> {
        let n = try!(d.object());
        let mut secret_key = None;
        let mut public_key = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => secret_key = Some(try!(SecretKey::decode(d))),
                1 => public_key = Some(try!(PublicKey::decode(d))),
                _ => try!(d.skip())
            }
        }
        Ok(KeyPair {
            secret_key: to_field!(secret_key, "KeyPair::secret_key"),
            public_key: to_field!(public_key, "KeyPair::public_key")
        })
    }
}

// SecretKey ////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct SecretKey(pub [u8; 32]);

impl SecretKey {
    pub fn sign(&self, m: &[u8]) -> Signature {
        let mut random = [0u8; 64];
        copy_memory(&rand_bytes(64), &mut random);
        Signature(curve25519::sign(&self.0, m, &random).unwrap())
    }

    pub fn shared_secret(&self, p: &PublicKey) -> [u8; 32] {
        curve25519::donna(&self.0, &p.0).unwrap()
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(1));
        try!(e.u8(0).and(e.bytes(&self.0)));
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<SecretKey> {
        let n = try!(d.object());
        let mut sk = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => sk = Some(try!(Bytes32::decode(d).map(|v| v.array))),
                _ => try!(d.skip())
            }
        }
        Ok(SecretKey(to_field!(sk, "SecretKey")))
    }
}

// PublicKey ////////////////////////////////////////////////////////////////

#[derive(Copy, Clone)]
pub struct PublicKey(pub [u8; 32]);

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        &self.0 == &other.0
    }
}

impl Eq for PublicKey {}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{:?}", &self.0)
    }
}

impl PublicKey {
    pub fn verify(&self, s: &Signature, m: &[u8]) -> bool {
        curve25519::verify(&s.0, &self.0, &m)
    }

    pub fn fingerprint(&self) -> String {
        fmt_hex(&self.0)
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(1));
        try!(e.u8(0).and(e.bytes(&self.0)));
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<PublicKey> {
        let n = try!(d.object());
        let mut pk = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => pk = Some(try!(Bytes32::decode(d).map(|v| v.array))),
                _ => try!(d.skip())
            }
        }
        Ok(PublicKey(to_field!(pk, "PublicKey")))
    }
}

// Random ///////////////////////////////////////////////////////////////////

pub fn rand_bytes(size: usize) -> Vec<u8> {
    randombytes::randombytes(size)
}

// Signature ////////////////////////////////////////////////////////////////

pub const SIGNATUREBYTES: usize = 64;

pub struct Signature(pub [u8; SIGNATUREBYTES]);

impl PartialEq for Signature {
    fn eq(&self, other: &Signature) -> bool {
        &self.0[..] == &other.0[..]
    }
}

impl Eq for Signature {}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{:?}", &self.0[..])
    }
}

impl Signature {
    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(1));
        try!(e.u8(0).and(e.bytes(&self.0)));
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<Signature> {
        let n = try!(d.object());
        let mut sig = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => sig = Some(try!(Bytes64::decode(d).map(|v| v.array))),
                _ => try!(d.skip())
            }
        }
        Ok(Signature(to_field!(sig, "Signature")))
    }
}


// Tests ////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use internal::util::roundtrip;
    use super::*;

    #[test]
    fn prekey_generation() {
        let k = gen_prekeys(PreKeyId::new(0xFFFC), 5)
                .iter()
                .map(|k| k.key_id.value())
                .collect::<Vec<_>>();
        assert_eq!(vec![0xFFFD, 0xFFFE, 0, 1, 2], k)
    }

    #[test]
    fn dh_agreement() {
        let a  = KeyPair::new();
        let b  = KeyPair::new();
        let sa = a.secret_key.shared_secret(&b.public_key);
        let sb = b.secret_key.shared_secret(&a.public_key);
        assert_eq!(&sa, &sb)
    }

    #[test]
    fn sign_and_verify() {
        let a = KeyPair::new();
        let s = a.secret_key.sign(b"foobarbaz");
        assert!(a.public_key.verify(&s, b"foobarbaz"));
        assert!(!a.public_key.verify(&s, b"foobar"));
    }

    #[test]
    fn enc_dec_pubkey() {
        let k = KeyPair::new();
        let r = roundtrip(|mut e| k.public_key.encode(&mut e), |mut d| PublicKey::decode(&mut d));
        assert_eq!(k.public_key, r)
    }

    #[test]
    fn enc_dec_seckey() {
        let k = KeyPair::new();
        let r = roundtrip(|mut e| k.secret_key.encode(&mut e), |mut d| SecretKey::decode(&mut d));
        assert_eq!(&k.secret_key.0, &r.0)
    }

    #[test]
    fn enc_dec_prekey_bundle() {
        let i = IdentityKeyPair::new();
        let k = PreKey::new(PreKeyId::new(1));
        let b = PreKeyBundle::new(i.public_key, &k);
        let r = roundtrip(|mut e| b.encode(&mut e), |mut d| PreKeyBundle::decode(&mut d));
        assert_eq!(None, b.signature);
        assert_eq!(b, r);
    }

    #[test]
    fn enc_dec_signed_prekey_bundle() {
        let i = IdentityKeyPair::new();
        let k = PreKey::new(PreKeyId::new(1));
        let b = PreKeyBundle::signed(&i, &k);
        let r = roundtrip(|mut e| b.encode(&mut e), |mut d| PreKeyBundle::decode(&mut d));
        assert_eq!(b, r);
        assert_eq!(PreKeyAuth::Valid, b.verify());
        assert_eq!(PreKeyAuth::Valid, r.verify());
    }
}
