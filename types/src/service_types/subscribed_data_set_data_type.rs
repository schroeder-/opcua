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
};

#[derive(Debug, Clone, PartialEq)]
pub struct SubscribedDataSetDataType {
}

impl MessageInfo for SubscribedDataSetDataType {
    fn object_id(&self) -> ObjectId {
        ObjectId::SubscribedDataSetDataType_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<SubscribedDataSetDataType> for SubscribedDataSetDataType {
    fn byte_len(&self) -> usize {
        0
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        Ok(0)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        Ok(SubscribedDataSetDataType {
        })
    }

    fn type_id() -> NodeId {
        ObjectId::SubscribedDataSetDataType_Encoding_DefaultBinary.into()
    }
}
