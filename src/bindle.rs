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

//! Bindle is a wrapper for ASCII armoring binary data containers, which can be serialized
//! and optionally signed by the creator with certain id and send over to a
//! remote party.

use std::collections::BTreeMap;
use std::fmt::{Debug, Display};
use std::io::{Read, Write};
use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;
use std::{fs, io};

use amplify::confinement;
use amplify::confinement::{Confined, TinyVec, U24};
use baid58::Baid58ParseError;
use strict_encoding::{
    DecodeError, StrictDecode, StrictDeserialize, StrictDumb, StrictEncode, StrictReader,
    StrictSerialize, StrictType, StrictWriter, STRICT_TYPES_LIB,
};

use crate::{Pk, RistrettoPk, SigCert};

pub trait BindleContent: StrictSerialize + StrictDeserialize + StrictDumb {
    /// Magic bytes used in saving/restoring container from a file.
    const MAGIC: [u8; 4];
    /// String used in ASCII armored blocks
    const PLATE_TITLE: &'static str;

    type Id: Copy
        + Eq
        + Debug
        + Display
        + FromStr<Err = Baid58ParseError>
        + StrictType
        + StrictDumb
        + StrictEncode
        + StrictDecode;

    fn bindle_id(&self) -> Self::Id;
    fn bindle_headers(&self) -> BTreeMap<&'static str, String> { none!() }
    fn bindle(self) -> Bindle<Self> { Bindle::new(self) }
    fn bindle_mnemonic(&self) -> Option<String> { None }
}

#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = STRICT_TYPES_LIB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Bindle<C: BindleContent, K: Pk = RistrettoPk> {
    id: C::Id,
    data: C,
    sigs: TinyVec<SigCert<K>>,
}

impl<C: BindleContent, K: Pk> Deref for Bindle<C, K> {
    type Target = C;
    fn deref(&self) -> &Self::Target { &self.data }
}

impl<C: BindleContent, K: Pk> From<C> for Bindle<C, K> {
    fn from(data: C) -> Self { Bindle::new(data) }
}

impl<C: BindleContent, K: Pk> Bindle<C, K> {
    pub fn new(data: C) -> Self {
        Bindle {
            id: data.bindle_id(),
            data,
            sigs: empty!(),
        }
    }

    pub fn id(&self) -> C::Id { self.id }

    pub fn into_split(self) -> (C, TinyVec<SigCert<K>>) { (self.data, self.sigs) }
    pub fn unbindle(self) -> C { self.data }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum BindleParseError<Id: Copy + Eq + Debug + Display> {
    /// the provided text doesn't represent a recognizable ASCII-armored RGB
    /// bindle encoding.
    WrongStructure,

    /// Id header of the bindle contains unparsable information. Details: {0}
    InvalidId(Baid58ParseError),

    /// the actual data doesn't match the provided id.
    ///
    /// Actual id: {actual}.
    ///
    /// Expected id: {expected}.
    MismatchedId { actual: Id, expected: Id },

    /// bindle data has invalid Base85 encoding (ASCII armoring).
    #[from(base85::Error)]
    Base85,

    /// unable to decode the provided bindle data. Details: {0}
    #[from]
    Deserialize(strict_encoding::DeserializeError),

    /// bindle contains more than 16MB of data.
    #[from(confinement::Error)]
    TooLarge,
}

impl<C: BindleContent, K: Pk> FromStr for Bindle<C, K> {
    type Err = BindleParseError<C::Id>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines = s.lines();
        let first = format!("-----BEGIN {}-----", C::PLATE_TITLE);
        let last = format!("-----END {}-----", C::PLATE_TITLE);
        if (lines.next(), lines.next_back()) != (Some(&first), Some(&last)) {
            return Err(BindleParseError::WrongStructure);
        }
        let mut header_id = None;
        for line in lines.by_ref() {
            if line.is_empty() {
                break;
            }
            if let Some(id_str) = line.strip_prefix("Id: ") {
                header_id = Some(C::Id::from_str(id_str).map_err(BindleParseError::InvalidId)?);
            }
        }
        let armor = lines.filter(|l| !l.is_empty()).collect::<String>();
        let data = base85::decode(&armor)?;
        let data = C::from_strict_serialized::<U24>(Confined::try_from(data)?)?;
        let id = data.bindle_id();
        if let Some(header_id) = header_id {
            if header_id != id {
                return Err(BindleParseError::MismatchedId {
                    actual: id,
                    expected: header_id,
                });
            }
        }
        // TODO: check mnemonic
        // TODO: parse and validate sigs
        Ok(Self {
            id,
            data,
            sigs: none!(),
        })
    }
}

impl<C: BindleContent, K: Pk> Display for Bindle<C, K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "-----BEGIN {}-----", C::PLATE_TITLE)?;
        writeln!(f, "Id: {:-#}", self.id)?;
        if let Some(mnemonic) = self.bindle_mnemonic() {
            writeln!(f, "Mnemonic: {}", mnemonic)?;
        }
        for (header, value) in self.bindle_headers() {
            writeln!(f, "{header}: {value}")?;
        }
        for cert in &self.sigs {
            writeln!(f, "Signed-By: {}", cert.identity())?;
        }
        writeln!(f)?;

        // TODO: Replace with streamed writer
        let data = self.data.to_strict_serialized::<U24>().expect("in-memory");
        let data = base85::encode(&data);
        let mut data = data.as_str();
        while data.len() >= 64 {
            let (line, rest) = data.split_at(64);
            writeln!(f, "{}", line)?;
            data = rest;
        }
        writeln!(f, "{}", data)?;

        writeln!(f, "\n-----END {}-----", C::PLATE_TITLE)?;
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum LoadError {
    /// invalid file data.
    InvalidMagic,

    #[display(inner)]
    #[from]
    #[from(io::Error)]
    Decode(DecodeError),
}

impl<C: BindleContent, K: Pk> Bindle<C, K> {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, LoadError> {
        let mut magic = [0u8; 4];
        let mut file = fs::File::open(path)?;
        file.read_exact(&mut magic)?;
        if magic != C::MAGIC {
            return Err(LoadError::InvalidMagic);
        }
        let mut reader = StrictReader::with(usize::MAX, file);
        let me = Self::strict_decode(&mut reader)?;
        Ok(me)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), io::Error> {
        let mut file = fs::File::create(path)?;
        file.write_all(&C::MAGIC)?;
        let writer = StrictWriter::with(usize::MAX, file);
        self.strict_encode(writer)?;
        Ok(())
    }
}
