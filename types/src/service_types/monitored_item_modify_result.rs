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
    status_codes::StatusCode,
    extension_object::ExtensionObject,
};

#[derive(Debug, Clone, PartialEq)]
pub struct MonitoredItemModifyResult {
    pub status_code: StatusCode,
    pub revised_sampling_interval: f64,
    pub revised_queue_size: u32,
    pub filter_result: ExtensionObject,
}

impl MessageInfo for MonitoredItemModifyResult {
    fn object_id(&self) -> ObjectId {
        ObjectId::MonitoredItemModifyResult_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<MonitoredItemModifyResult> for MonitoredItemModifyResult {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.status_code.byte_len();
        size += self.revised_sampling_interval.byte_len();
        size += self.revised_queue_size.byte_len();
        size += self.filter_result.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.status_code.encode(stream)?;
        size += self.revised_sampling_interval.encode(stream)?;
        size += self.revised_queue_size.encode(stream)?;
        size += self.filter_result.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let status_code = StatusCode::decode(stream, decoding_options)?;
        let revised_sampling_interval = f64::decode(stream, decoding_options)?;
        let revised_queue_size = u32::decode(stream, decoding_options)?;
        let filter_result = ExtensionObject::decode(stream, decoding_options)?;
        Ok(MonitoredItemModifyResult {
            status_code,
            revised_sampling_interval,
            revised_queue_size,
            filter_result,
        })
    }

    fn type_id() -> NodeId {
        ObjectId::MonitoredItemModifyResult_Encoding_DefaultBinary.into()
    }
}
