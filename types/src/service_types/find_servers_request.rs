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
    request_header::RequestHeader,
    string::UAString,
};

#[derive(Debug, Clone, PartialEq)]
pub struct FindServersRequest {
    pub request_header: RequestHeader,
    pub endpoint_url: UAString,
    pub locale_ids: Option<Vec<UAString>>,
    pub server_uris: Option<Vec<UAString>>,
}

impl MessageInfo for FindServersRequest {
    fn object_id(&self) -> ObjectId {
        ObjectId::FindServersRequest_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<FindServersRequest> for FindServersRequest {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.request_header.byte_len();
        size += self.endpoint_url.byte_len();
        size += byte_len_array(&self.locale_ids);
        size += byte_len_array(&self.server_uris);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.request_header.encode(stream)?;
        size += self.endpoint_url.encode(stream)?;
        size += write_array(stream, &self.locale_ids)?;
        size += write_array(stream, &self.server_uris)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let request_header = RequestHeader::decode(stream, decoding_options)?;
        let endpoint_url = UAString::decode(stream, decoding_options)?;
        let locale_ids: Option<Vec<UAString>> = read_array(stream, decoding_options)?;
        let server_uris: Option<Vec<UAString>> = read_array(stream, decoding_options)?;
        Ok(FindServersRequest {
            request_header,
            endpoint_url,
            locale_ids,
            server_uris,
        })
    }

    fn type_id() -> NodeId {
        ObjectId::FindServersRequest_Encoding_DefaultBinary.into()
    }
}
