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

use amplify::confinement::{SmallVec, U8};
use commit_verify::{Digest as _, Sha256};
use strict_encoding::{StrictDeserialize, StrictSerialize};

use crate::{BindleContent, Digest, Fingerprint, Pk, Proof, RistrettoPk, Seal, Sk, LIB_NAME_SSID};

pub struct Ssi<K: Pk = RistrettoPk> {
    pub sk: K::Sk,
    pub cert: IdCert<K>,
}

impl<K: Pk> Ssi<K> {
    pub fn new(seal: Seal) -> Self {
        let sk = K::Sk::generate();
        let identity = Identity {
            key: K::with(&sk),
            seal,
        };
        let sig = sk.sign(identity);
        Ssi {
            sk,
            cert: IdCert::new(identity, sig),
        }
    }

    pub fn fingerprint(&self) -> Fingerprint { self.cert.fingerprint() }
}

/// Has binary form included into the blockchain (witness in case of bitcoin)
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_SSID)]
#[display("ssi:{key}", alt = "ssi:{key}@{seal}")]
pub struct Identity<K: Pk = RistrettoPk> {
    pub key: K,
    pub seal: Seal,
}

impl<K: Pk> StrictSerialize for Identity<K> {}

impl<K: Pk> Identity<K> {
    pub fn fingerprint(&self) -> Fingerprint { self.key.fingerprint() }
}

impl<K: Pk> From<Identity<K>> for Digest {
    fn from(identity: Identity<K>) -> Self {
        let data = identity
            .to_strict_serialized::<U8>()
            .expect("serialized identity does not fit 256 bytes");
        let mut hasher = Sha256::new();
        hasher.update(data);
        <[u8; 32]>::from(hasher.finalize()).into()
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_SSID)]
pub struct Revocation<K: Pk = RistrettoPk> {
    pub new_identity: Identity<K>,
    pub revocation_proof: Proof,
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_SSID)]
pub struct IdCert<K: Pk = RistrettoPk> {
    pub revocations: SmallVec<Revocation<K>>,
    pub genesis_id: Identity<K>,
    pub genesis_sig: <K::Sk as Sk>::Sig,
}

impl<K: Pk> StrictSerialize for IdCert<K> {}
impl<K: Pk> StrictDeserialize for IdCert<K> {}

impl<K: Pk> IdCert<K> {
    pub fn new(identity: Identity<K>, sig: <K::Sk as Sk>::Sig) -> Self {
        Self {
            revocations: none!(),
            genesis_id: identity,
            genesis_sig: sig,
        }
    }

    pub fn identity(&self) -> Identity<K> {
        self.revocations.last().map(|r| r.new_identity).unwrap_or(self.genesis_id)
    }

    pub fn fingerprint(&self) -> Fingerprint { self.identity().fingerprint() }
}

impl<K: Pk> BindleContent for IdCert<K> {
    const MAGIC: [u8; 4] = *b"SSID";
    const PLATE_TITLE: &'static str = "SSID IDENTITY CERTIFICATE";
    type Id = K;

    fn bindle_id(&self) -> Self::Id { self.identity().key }
}
