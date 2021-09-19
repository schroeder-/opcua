// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE
#![allow(unused_attributes)]

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    encoding::*,
    basic_types::*,
    node_ids::ObjectId,
    node_id::NodeId,
    service_types::impls::MessageInfo,
};

#[derive(Debug, Clone, PartialEq)]
pub struct HistoryUpdateDetails {
    pub node_id: NodeId,
}

impl MessageInfo for HistoryUpdateDetails {
    fn object_id(&self) -> ObjectId {
        ObjectId::HistoryUpdateDetails_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<HistoryUpdateDetails> for HistoryUpdateDetails {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.node_id.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.node_id.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let node_id = NodeId::decode(stream, decoding_options)?;
        Ok(HistoryUpdateDetails {
            node_id,
        })
    }

    fn type_id() -> NodeId {
        ObjectId::HistoryUpdateDetails_Encoding_DefaultBinary.into()
    }
}
