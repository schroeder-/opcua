// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{basic_types::*, date_time::DateTime, encoding::*, node_id::NodeId};

#[derive(Debug, Clone, PartialEq)]
pub struct DeleteRawModifiedDetails {
    pub node_id: NodeId,
    pub is_delete_modified: bool,
    pub start_time: DateTime,
    pub end_time: DateTime,
}

impl BinaryEncoder<DeleteRawModifiedDetails> for DeleteRawModifiedDetails {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.node_id.byte_len();
        size += self.is_delete_modified.byte_len();
        size += self.start_time.byte_len();
        size += self.end_time.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.node_id.encode(stream)?;
        size += self.is_delete_modified.encode(stream)?;
        size += self.start_time.encode(stream)?;
        size += self.end_time.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(
        stream: &mut S,
        decoding_limits: &DecodingLimits,
    ) -> EncodingResult<Self> {
        let node_id = NodeId::decode(stream, decoding_limits)?;
        let is_delete_modified = bool::decode(stream, decoding_limits)?;
        let start_time = DateTime::decode(stream, decoding_limits)?;
        let end_time = DateTime::decode(stream, decoding_limits)?;
        Ok(DeleteRawModifiedDetails {
            node_id,
            is_delete_modified,
            start_time,
            end_time,
        })
    }
}
