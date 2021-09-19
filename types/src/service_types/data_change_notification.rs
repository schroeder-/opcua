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
    diagnostic_info::DiagnosticInfo,
    service_types::MonitoredItemNotification,
};

#[derive(Debug, Clone, PartialEq)]
pub struct DataChangeNotification {
    pub monitored_items: Option<Vec<MonitoredItemNotification>>,
    pub diagnostic_infos: Option<Vec<DiagnosticInfo>>,
}

impl BinaryEncoder<DataChangeNotification> for DataChangeNotification {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += byte_len_array(&self.monitored_items);
        size += byte_len_array(&self.diagnostic_infos);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += write_array(stream, &self.monitored_items)?;
        size += write_array(stream, &self.diagnostic_infos)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let monitored_items: Option<Vec<MonitoredItemNotification>> = read_array(stream, decoding_options)?;
        let diagnostic_infos: Option<Vec<DiagnosticInfo>> = read_array(stream, decoding_options)?;
        Ok(DataChangeNotification {
            monitored_items,
            diagnostic_infos,
        })
    }

    fn type_id() -> NodeId {
        ObjectId::DataChangeNotification_Encoding_DefaultBinary.into()
    }
}
