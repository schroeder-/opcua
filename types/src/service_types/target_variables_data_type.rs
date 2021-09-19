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
    service_types::FieldTargetDataType,
};

#[derive(Debug, Clone, PartialEq)]
pub struct TargetVariablesDataType {
    pub target_variables: Option<Vec<FieldTargetDataType>>,
}

impl BinaryEncoder<TargetVariablesDataType> for TargetVariablesDataType {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += byte_len_array(&self.target_variables);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += write_array(stream, &self.target_variables)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let target_variables: Option<Vec<FieldTargetDataType>> = read_array(stream, decoding_options)?;
        Ok(TargetVariablesDataType {
            target_variables,
        })
    }

    fn type_id() -> NodeId {
        ObjectId::TargetVariablesDataType_Encoding_DefaultBinary.into()
    }
}
