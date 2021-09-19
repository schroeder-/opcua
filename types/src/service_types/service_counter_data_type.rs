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
pub struct ServiceCounterDataType {
    pub total_count: u32,
    pub error_count: u32,
}

impl MessageInfo for ServiceCounterDataType {
    fn object_id(&self) -> ObjectId {
        ObjectId::ServiceCounterDataType_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<ServiceCounterDataType> for ServiceCounterDataType {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.total_count.byte_len();
        size += self.error_count.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.total_count.encode(stream)?;
        size += self.error_count.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let total_count = u32::decode(stream, decoding_options)?;
        let error_count = u32::decode(stream, decoding_options)?;
        Ok(ServiceCounterDataType {
            total_count,
            error_count,
        })
    }

    fn type_id() -> NodeId {
        ObjectId::ServiceCounterDataType_Encoding_DefaultBinary.into()
    }
}
