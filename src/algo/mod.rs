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

mod ristretto25519;

use std::fmt::{Debug, Display};
use std::str::FromStr;

use amplify::Bytes4;
use baid58::Baid58ParseError;
pub use ristretto25519::{RistrettoPk, RistrettoSig, RistrettoSk};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode, StrictType};

use crate::{BindleContent, Digest};

pub type Fingerprint = Bytes4;

pub trait Sk: BindleContent {
    type Sig: Sig;

    fn generate() -> Self;

    fn sign(&self, message: impl Into<Digest>) -> Self::Sig;
}

pub trait Pk:
    Copy
    + Eq
    + Debug
    + Display
    + FromStr<Err = Baid58ParseError>
    + StrictType
    + StrictDumb
    + StrictEncode
    + StrictDecode
{
    type Sk: Sk;
    const ID: u8;

    fn with(sk: &Self::Sk) -> Self;

    #[must_use]
    fn verify(&self, message: impl Into<Digest>, sig: &<Self::Sk as Sk>::Sig) -> bool;

    fn fingerprint(&self) -> Fingerprint;
}

pub trait Sig: Copy + Eq + Debug + StrictType + StrictDumb + StrictEncode + StrictDecode {}
