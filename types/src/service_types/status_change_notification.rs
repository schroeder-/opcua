// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    basic_types::*, diagnostic_info::DiagnosticInfo, encoding::*,
    status_codes::StatusCode,
};

#[derive(Debug, Clone, PartialEq)]
pub struct StatusChangeNotification {
    pub status: StatusCode,
    pub diagnostic_info: DiagnosticInfo,
}

impl BinaryEncoder<StatusChangeNotification> for StatusChangeNotification {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.status.byte_len();
        size += self.diagnostic_info.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.status.encode(stream)?;
        size += self.diagnostic_info.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(
        stream: &mut S,
        decoding_limits: &DecodingLimits,
    ) -> EncodingResult<Self> {
        let status = StatusCode::decode(stream, decoding_limits)?;
        let diagnostic_info = DiagnosticInfo::decode(stream, decoding_limits)?;
        Ok(StatusChangeNotification {
            status,
            diagnostic_info,
        })
    }
}
