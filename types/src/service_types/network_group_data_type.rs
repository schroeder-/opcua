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
    string::UAString,
    service_types::EndpointUrlListDataType,
};

#[derive(Debug, Clone, PartialEq)]
pub struct NetworkGroupDataType {
    pub server_uri: UAString,
    pub network_paths: Option<Vec<EndpointUrlListDataType>>,
}

impl MessageInfo for NetworkGroupDataType {
    fn object_id(&self) -> ObjectId {
        ObjectId::NetworkGroupDataType_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<NetworkGroupDataType> for NetworkGroupDataType {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.server_uri.byte_len();
        size += byte_len_array(&self.network_paths);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.server_uri.encode(stream)?;
        size += write_array(stream, &self.network_paths)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let server_uri = UAString::decode(stream, decoding_options)?;
        let network_paths: Option<Vec<EndpointUrlListDataType>> = read_array(stream, decoding_options)?;
        Ok(NetworkGroupDataType {
            server_uri,
            network_paths,
        })
    }

    fn type_id() -> NodeId {
        ObjectId::NetworkGroupDataType_Encoding_DefaultBinary.into()
    }
}
