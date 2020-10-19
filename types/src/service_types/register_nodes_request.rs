// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    basic_types::*, encoding::*, node_id::NodeId, node_ids::ObjectId,
    request_header::RequestHeader, service_types::impls::MessageInfo,
};

#[derive(Debug, Clone, PartialEq)]
pub struct RegisterNodesRequest {
    pub request_header: RequestHeader,
    pub nodes_to_register: Option<Vec<NodeId>>,
}

impl MessageInfo for RegisterNodesRequest {
    fn object_id(&self) -> ObjectId {
        ObjectId::RegisterNodesRequest_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<RegisterNodesRequest> for RegisterNodesRequest {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.request_header.byte_len();
        size += byte_len_array(&self.nodes_to_register);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.request_header.encode(stream)?;
        size += write_array(stream, &self.nodes_to_register)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(
        stream: &mut S,
        decoding_limits: &DecodingLimits,
    ) -> EncodingResult<Self> {
        let request_header = RequestHeader::decode(stream, decoding_limits)?;
        let nodes_to_register: Option<Vec<NodeId>> =
            read_array(stream, decoding_limits)?;
        Ok(RegisterNodesRequest {
            request_header,
            nodes_to_register,
        })
    }
}
