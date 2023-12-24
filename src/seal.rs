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

use std::str::FromStr;

use bpstd::{Outpoint, OutpointParseError};

use crate::LIB_NAME_SSID;

// TODO: Move to BP Seals; generalize
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_SSID, tags = custom, dumb = Self::Bitcoin(strict_dumb!()))]
pub enum Seal {
    #[strict_type(tag = 0x00)]
    #[display("bitcoin:{0}")]
    Bitcoin(Outpoint),

    #[strict_type(tag = 0x01)]
    #[display("liquid:{0}")]
    Liquid(Outpoint),
}

impl FromStr for Seal {
    type Err = OutpointParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(outpoint) = s.strip_prefix("bitcoin:") {
            Outpoint::from_str(outpoint).map(Self::Bitcoin)
        } else if let Some(outpoint) = s.strip_prefix("liquid:") {
            Outpoint::from_str(outpoint).map(Self::Liquid)
        } else {
            Outpoint::from_str(s).map(Self::Bitcoin)
        }
    }
}
