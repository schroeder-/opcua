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
    response_header::ResponseHeader,
    diagnostic_info::DiagnosticInfo,
    service_types::HistoryReadResult,
};

#[derive(Debug, Clone, PartialEq)]
pub struct HistoryReadResponse {
    pub response_header: ResponseHeader,
    pub results: Option<Vec<HistoryReadResult>>,
    pub diagnostic_infos: Option<Vec<DiagnosticInfo>>,
}

impl MessageInfo for HistoryReadResponse {
    fn object_id(&self) -> ObjectId {
        ObjectId::HistoryReadResponse_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<HistoryReadResponse> for HistoryReadResponse {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.response_header.byte_len();
        size += byte_len_array(&self.results);
        size += byte_len_array(&self.diagnostic_infos);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.response_header.encode(stream)?;
        size += write_array(stream, &self.results)?;
        size += write_array(stream, &self.diagnostic_infos)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let response_header = ResponseHeader::decode(stream, decoding_options)?;
        let results: Option<Vec<HistoryReadResult>> = read_array(stream, decoding_options)?;
        let diagnostic_infos: Option<Vec<DiagnosticInfo>> = read_array(stream, decoding_options)?;
        Ok(HistoryReadResponse {
            response_header,
            results,
            diagnostic_infos,
        })
    }

    fn type_id() -> NodeId {
        ObjectId::HistoryReadResponse_Encoding_DefaultBinary.into()
    }
}
