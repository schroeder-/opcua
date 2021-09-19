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
    diagnostic_info::DiagnosticInfo,
};

#[derive(Debug, Clone, PartialEq)]
pub struct ContentFilterElementResult {
    pub status_code: StatusCode,
    pub operand_status_codes: Option<Vec<StatusCode>>,
    pub operand_diagnostic_infos: Option<Vec<DiagnosticInfo>>,
}

impl MessageInfo for ContentFilterElementResult {
    fn object_id(&self) -> ObjectId {
        ObjectId::ContentFilterElementResult_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<ContentFilterElementResult> for ContentFilterElementResult {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.status_code.byte_len();
        size += byte_len_array(&self.operand_status_codes);
        size += byte_len_array(&self.operand_diagnostic_infos);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.status_code.encode(stream)?;
        size += write_array(stream, &self.operand_status_codes)?;
        size += write_array(stream, &self.operand_diagnostic_infos)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let status_code = StatusCode::decode(stream, decoding_options)?;
        let operand_status_codes: Option<Vec<StatusCode>> = read_array(stream, decoding_options)?;
        let operand_diagnostic_infos: Option<Vec<DiagnosticInfo>> = read_array(stream, decoding_options)?;
        Ok(ContentFilterElementResult {
            status_code,
            operand_status_codes,
            operand_diagnostic_infos,
        })
    }

    fn type_id() -> NodeId {
        ObjectId::ContentFilterElementResult_Encoding_DefaultBinary.into()
    }
}
