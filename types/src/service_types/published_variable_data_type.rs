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
    variant::Variant,
    qualified_name::QualifiedName,
};

#[derive(Debug, Clone, PartialEq)]
pub struct PublishedVariableDataType {
    pub published_variable: NodeId,
    pub attribute_id: u32,
    pub sampling_interval_hint: f64,
    pub deadband_type: u32,
    pub deadband_value: f64,
    pub index_range: UAString,
    pub substitute_value: Variant,
    pub meta_data_properties: Option<Vec<QualifiedName>>,
}

impl MessageInfo for PublishedVariableDataType {
    fn object_id(&self) -> ObjectId {
        ObjectId::PublishedVariableDataType_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<PublishedVariableDataType> for PublishedVariableDataType {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.published_variable.byte_len();
        size += self.attribute_id.byte_len();
        size += self.sampling_interval_hint.byte_len();
        size += self.deadband_type.byte_len();
        size += self.deadband_value.byte_len();
        size += self.index_range.byte_len();
        size += self.substitute_value.byte_len();
        size += byte_len_array(&self.meta_data_properties);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.published_variable.encode(stream)?;
        size += self.attribute_id.encode(stream)?;
        size += self.sampling_interval_hint.encode(stream)?;
        size += self.deadband_type.encode(stream)?;
        size += self.deadband_value.encode(stream)?;
        size += self.index_range.encode(stream)?;
        size += self.substitute_value.encode(stream)?;
        size += write_array(stream, &self.meta_data_properties)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let published_variable = NodeId::decode(stream, decoding_options)?;
        let attribute_id = u32::decode(stream, decoding_options)?;
        let sampling_interval_hint = f64::decode(stream, decoding_options)?;
        let deadband_type = u32::decode(stream, decoding_options)?;
        let deadband_value = f64::decode(stream, decoding_options)?;
        let index_range = UAString::decode(stream, decoding_options)?;
        let substitute_value = Variant::decode(stream, decoding_options)?;
        let meta_data_properties: Option<Vec<QualifiedName>> = read_array(stream, decoding_options)?;
        Ok(PublishedVariableDataType {
            published_variable,
            attribute_id,
            sampling_interval_hint,
            deadband_type,
            deadband_value,
            index_range,
            substitute_value,
            meta_data_properties,
        })
    }

    fn type_id() -> NodeId {
        ObjectId::PublishedVariableDataType_Encoding_DefaultBinary.into()
    }
}
