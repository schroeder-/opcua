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
    variant::Variant,
};

#[derive(Debug, Clone, PartialEq)]
pub struct HistoryEventFieldList {
    pub event_fields: Option<Vec<Variant>>,
}

impl MessageInfo for HistoryEventFieldList {
    fn object_id(&self) -> ObjectId {
        ObjectId::HistoryEventFieldList_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<HistoryEventFieldList> for HistoryEventFieldList {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += byte_len_array(&self.event_fields);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += write_array(stream, &self.event_fields)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let event_fields: Option<Vec<Variant>> = read_array(stream, decoding_options)?;
        Ok(HistoryEventFieldList {
            event_fields,
        })
    }

    fn type_id() -> NodeId {
        ObjectId::HistoryEventFieldList_Encoding_DefaultBinary.into()
    }
}
