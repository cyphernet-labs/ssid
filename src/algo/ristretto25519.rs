// Self-sovereign identity (SSID)
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2023-204 by
//     Cypher<cypher@cyphernet.io>
//
// Copyright 2023-2024 Cyphernet DAO, Switzerland
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::io;
use std::ops::Deref;
use std::str::FromStr;

use baid58::{Baid58ParseError, Chunking, FromBaid58, ToBaid58, CHUNKING_32};
use ec25519::{Noise, PublicKey, SecretKey, Signature};
use rand::{random, thread_rng, Rng};
use strict_encoding::{
    DecodeError, ReadTuple, StrictDecode, StrictDeserialize, StrictDumb, StrictEncode,
    StrictProduct, StrictSerialize, StrictTuple, StrictType, TypedRead, TypedWrite,
};

use super::{Fingerprint, Pk, Sig};
use crate::{BindleContent, Digest, Sk, LIB_NAME_SSID};

pub struct RistrettoSk(SecretKey);

impl StrictType for RistrettoSk {
    const STRICT_LIB_NAME: &'static str = LIB_NAME_SSID;
}
impl StrictProduct for RistrettoSk {}
impl StrictTuple for RistrettoSk {
    const FIELD_COUNT: u8 = 1;
}
impl StrictEncode for RistrettoSk {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> io::Result<W> {
        writer.write_newtype::<Self>(self.0.deref())
    }
}
impl StrictDecode for RistrettoSk {
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        reader.read_tuple(|r| {
            let data = r.read_field()?;
            Ok(Self(SecretKey::new(data)))
        })
    }
}
impl StrictDumb for RistrettoSk {
    fn strict_dumb() -> Self { Self(SecretKey::new([0xFAu8; 64])) }
}
impl StrictSerialize for RistrettoSk {}
impl StrictDeserialize for RistrettoSk {}

impl Sk for RistrettoSk {
    type Sig = RistrettoSig;

    fn generate() -> Self {
        let mut data = [0u8; 64];
        thread_rng().fill(&mut data);
        Self(SecretKey::new(data))
    }

    fn sign(&self, message: impl Into<Digest>) -> Self::Sig {
        RistrettoSig(self.0.sign(message.into(), Some(Noise::new(random()))))
    }
}

impl BindleContent for RistrettoSk {
    const MAGIC: [u8; 4] = *b"SSSK";
    const PLATE_TITLE: &'static str = "SSID SECRET KEY";
    type Id = RistrettoPk;

    fn bindle_id(&self) -> Self::Id { RistrettoPk::with(self) }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[display(Self::to_baid58_string)]
pub struct RistrettoPk(PublicKey);

impl From<[u8; 33]> for RistrettoPk {
    fn from(value: [u8; 33]) -> Self {
        assert_eq!(value[0], Self::ID, "invalid key type");
        let mut data = [0u8; 32];
        data.copy_from_slice(&value[1..]);
        Self(PublicKey::new(data))
    }
}

impl ToBaid58<33> for RistrettoPk {
    const HRI: &'static str = "ssi";
    const CHUNKING: Option<Chunking> = CHUNKING_32;
    fn to_baid58_payload(&self) -> [u8; 33] {
        let mut payload = [0u8; 33];
        payload[0] = Self::ID;
        payload[1..].copy_from_slice(self.0.deref());
        payload
    }
    fn to_baid58_string(&self) -> String { self.to_string() }
}
impl FromBaid58<33> for RistrettoPk {}
impl FromStr for RistrettoPk {
    type Err = Baid58ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid58_chunked_str(s, ':', '#') }
}
impl RistrettoPk {
    pub fn to_baid58_string(&self) -> String { format!("{::<#.2}", self.to_baid58()) }
    pub fn to_mnemonic(&self) -> String { self.to_baid58().mnemonic() }
}

impl Pk for RistrettoPk {
    type Sk = RistrettoSk;
    const ID: u8 = 1;

    fn with(sk: &Self::Sk) -> Self { Self(sk.0.public_key()) }

    fn verify(&self, message: impl Into<Digest>, sig: &<Self::Sk as Sk>::Sig) -> bool {
        self.0.verify(message.into(), &sig.0).is_ok()
    }

    fn fingerprint(&self) -> Fingerprint {
        Fingerprint::copy_from_slice(&self.0[0..4]).expect("fixed length")
    }
}

impl StrictType for RistrettoPk {
    const STRICT_LIB_NAME: &'static str = LIB_NAME_SSID;
}
impl StrictProduct for RistrettoPk {}
impl StrictTuple for RistrettoPk {
    const FIELD_COUNT: u8 = 1;
}
impl StrictEncode for RistrettoPk {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> io::Result<W> {
        writer.write_newtype::<Self>(self.0.deref())
    }
}
impl StrictDecode for RistrettoPk {
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        reader.read_tuple(|r| {
            let data = r.read_field()?;
            Ok(Self(PublicKey::new(data)))
        })
    }
}
impl StrictDumb for RistrettoPk {
    fn strict_dumb() -> Self { Self(PublicKey::new([0xFAu8; 32])) }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct RistrettoSig(Signature);

impl Sig for RistrettoSig {}

impl StrictType for RistrettoSig {
    const STRICT_LIB_NAME: &'static str = LIB_NAME_SSID;
}
impl StrictProduct for RistrettoSig {}
impl StrictTuple for RistrettoSig {
    const FIELD_COUNT: u8 = 1;
}
impl StrictEncode for RistrettoSig {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> io::Result<W> {
        writer.write_newtype::<Self>(self.0.deref())
    }
}
impl StrictDecode for RistrettoSig {
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        reader.read_tuple(|r| {
            let data = r.read_field()?;
            Ok(Self(Signature::new(data)))
        })
    }
}
impl StrictDumb for RistrettoSig {
    fn strict_dumb() -> Self { Self(Signature::new([0xFAu8; 64])) }
}
