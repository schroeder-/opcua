// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    basic_types::*, encoding::*, node_ids::ObjectId, request_header::RequestHeader,
    service_types::impls::MessageInfo, string::UAString,
};

#[derive(Debug, Clone, PartialEq)]
pub struct FindServersOnNetworkRequest {
    pub request_header: RequestHeader,
    pub starting_record_id: u32,
    pub max_records_to_return: u32,
    pub server_capability_filter: Option<Vec<UAString>>,
}

impl MessageInfo for FindServersOnNetworkRequest {
    fn object_id(&self) -> ObjectId {
        ObjectId::FindServersOnNetworkRequest_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<FindServersOnNetworkRequest> for FindServersOnNetworkRequest {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.request_header.byte_len();
        size += self.starting_record_id.byte_len();
        size += self.max_records_to_return.byte_len();
        size += byte_len_array(&self.server_capability_filter);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.request_header.encode(stream)?;
        size += self.starting_record_id.encode(stream)?;
        size += self.max_records_to_return.encode(stream)?;
        size += write_array(stream, &self.server_capability_filter)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(
        stream: &mut S,
        decoding_limits: &DecodingLimits,
    ) -> EncodingResult<Self> {
        let request_header = RequestHeader::decode(stream, decoding_limits)?;
        let starting_record_id = u32::decode(stream, decoding_limits)?;
        let max_records_to_return = u32::decode(stream, decoding_limits)?;
        let server_capability_filter: Option<Vec<UAString>> =
            read_array(stream, decoding_limits)?;
        Ok(FindServersOnNetworkRequest {
            request_header,
            starting_record_id,
            max_records_to_return,
            server_capability_filter,
        })
    }
}
