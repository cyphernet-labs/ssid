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

use amplify::confinement::LargeVec;
use amplify::Bytes32;
use bpstd::{Tx, UnsignedTx};

use crate::LIB_NAME_SSID;

// TODO: Move to BP Seals
#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_SSID, tags = custom, dumb = Self::Bitcoin(strict_dumb!()))]
pub enum Proof {
    #[strict_type(tag = 0x00)]
    Bitcoin(BpProof),

    #[strict_type(tag = 0x01)]
    Liquid(BpProof),
}

// TODO: Move to BP Seals
#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_SSID)]
pub struct BpProof {
    pub seal_tx: UnsignedTx,
    pub witness_tx: Tx,
    pub merkle_path: LargeVec<Bytes32>,
}
