// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    basic_types::*, encoding::*, node_ids::ObjectId, service_types::impls::MessageInfo,
    service_types::HistoryEventFieldList,
};

#[derive(Debug, Clone, PartialEq)]
pub struct HistoryEvent {
    pub events: Option<Vec<HistoryEventFieldList>>,
}

impl MessageInfo for HistoryEvent {
    fn object_id(&self) -> ObjectId {
        ObjectId::HistoryEvent_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<HistoryEvent> for HistoryEvent {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += byte_len_array(&self.events);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += write_array(stream, &self.events)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(
        stream: &mut S,
        decoding_limits: &DecodingLimits,
    ) -> EncodingResult<Self> {
        let events: Option<Vec<HistoryEventFieldList>> =
            read_array(stream, decoding_limits)?;
        Ok(HistoryEvent { events })
    }
}
