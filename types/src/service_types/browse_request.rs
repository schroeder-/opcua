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
    service_types::ViewDescription,
    service_types::BrowseDescription,
};

#[derive(Debug, Clone, PartialEq)]
pub struct BrowseRequest {
    pub request_header: RequestHeader,
    pub view: ViewDescription,
    pub requested_max_references_per_node: u32,
    pub nodes_to_browse: Option<Vec<BrowseDescription>>,
}

impl MessageInfo for BrowseRequest {
    fn object_id(&self) -> ObjectId {
        ObjectId::BrowseRequest_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<BrowseRequest> for BrowseRequest {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.request_header.byte_len();
        size += self.view.byte_len();
        size += self.requested_max_references_per_node.byte_len();
        size += byte_len_array(&self.nodes_to_browse);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.request_header.encode(stream)?;
        size += self.view.encode(stream)?;
        size += self.requested_max_references_per_node.encode(stream)?;
        size += write_array(stream, &self.nodes_to_browse)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let request_header = RequestHeader::decode(stream, decoding_options)?;
        let view = ViewDescription::decode(stream, decoding_options)?;
        let requested_max_references_per_node = u32::decode(stream, decoding_options)?;
        let nodes_to_browse: Option<Vec<BrowseDescription>> = read_array(stream, decoding_options)?;
        Ok(BrowseRequest {
            request_header,
            view,
            requested_max_references_per_node,
            nodes_to_browse,
        })
    }

    fn type_id() -> NodeId {
        ObjectId::BrowseRequest_Encoding_DefaultBinary.into()
    }
}
