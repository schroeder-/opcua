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
    service_types::enums::StructureType,
    service_types::StructureField,
};

#[derive(Debug, Clone, PartialEq)]
pub struct StructureDefinition {
    pub default_encoding_id: NodeId,
    pub base_data_type: NodeId,
    pub structure_type: StructureType,
    pub fields: Option<Vec<StructureField>>,
}

impl BinaryEncoder<StructureDefinition> for StructureDefinition {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.default_encoding_id.byte_len();
        size += self.base_data_type.byte_len();
        size += self.structure_type.byte_len();
        size += byte_len_array(&self.fields);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.default_encoding_id.encode(stream)?;
        size += self.base_data_type.encode(stream)?;
        size += self.structure_type.encode(stream)?;
        size += write_array(stream, &self.fields)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let default_encoding_id = NodeId::decode(stream, decoding_options)?;
        let base_data_type = NodeId::decode(stream, decoding_options)?;
        let structure_type = StructureType::decode(stream, decoding_options)?;
        let fields: Option<Vec<StructureField>> = read_array(stream, decoding_options)?;
        Ok(StructureDefinition {
            default_encoding_id,
            base_data_type,
            structure_type,
            fields,
        })
    }

    fn type_id() -> NodeId {
        ObjectId::StructureDefinition_Encoding_DefaultBinary.into()
    }
}
