// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE
#![allow(unused_attributes)]
#![rustfmt::skip]

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    encoding::*,
    basic_types::*,
    service_types::impls::MessageInfo,
    node_ids::ObjectId,
    data_value::DataValue,
};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MonitoredItemNotification {
    pub client_handle: u32,
    pub value: DataValue,
}

impl MessageInfo for MonitoredItemNotification {
    fn object_id(&self) -> ObjectId {
        ObjectId::MonitoredItemNotification_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<MonitoredItemNotification> for MonitoredItemNotification {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.client_handle.byte_len();
        size += self.value.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.client_handle.encode(stream)?;
        size += self.value.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let client_handle = u32::decode(stream, decoding_options)?;
        let value = DataValue::decode(stream, decoding_options)?;
        Ok(MonitoredItemNotification {
            client_handle,
            value,
        })
    }
}
