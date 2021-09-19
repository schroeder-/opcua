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
    service_types::enums::PerformUpdateType,
    service_types::EventFilter,
    service_types::HistoryEventFieldList,
};

#[derive(Debug, Clone, PartialEq)]
pub struct UpdateEventDetails {
    pub node_id: NodeId,
    pub perform_insert_replace: PerformUpdateType,
    pub filter: EventFilter,
    pub event_data: Option<Vec<HistoryEventFieldList>>,
}

impl BinaryEncoder<UpdateEventDetails> for UpdateEventDetails {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.node_id.byte_len();
        size += self.perform_insert_replace.byte_len();
        size += self.filter.byte_len();
        size += byte_len_array(&self.event_data);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.node_id.encode(stream)?;
        size += self.perform_insert_replace.encode(stream)?;
        size += self.filter.encode(stream)?;
        size += write_array(stream, &self.event_data)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let node_id = NodeId::decode(stream, decoding_options)?;
        let perform_insert_replace = PerformUpdateType::decode(stream, decoding_options)?;
        let filter = EventFilter::decode(stream, decoding_options)?;
        let event_data: Option<Vec<HistoryEventFieldList>> = read_array(stream, decoding_options)?;
        Ok(UpdateEventDetails {
            node_id,
            perform_insert_replace,
            filter,
            event_data,
        })
    }

    fn type_id() -> NodeId {
        ObjectId::UpdateEventDetails_Encoding_DefaultBinary.into()
    }
}
