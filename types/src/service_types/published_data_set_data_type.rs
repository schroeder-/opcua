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
    extension_object::ExtensionObject,
    service_types::DataSetMetaDataType,
    service_types::KeyValuePair,
};

#[derive(Debug, Clone, PartialEq)]
pub struct PublishedDataSetDataType {
    pub name: UAString,
    pub data_set_folder: Option<Vec<UAString>>,
    pub data_set_meta_data: DataSetMetaDataType,
    pub extension_fields: Option<Vec<KeyValuePair>>,
    pub data_set_source: ExtensionObject,
}

impl MessageInfo for PublishedDataSetDataType {
    fn object_id(&self) -> ObjectId {
        ObjectId::PublishedDataSetDataType_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<PublishedDataSetDataType> for PublishedDataSetDataType {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.name.byte_len();
        size += byte_len_array(&self.data_set_folder);
        size += self.data_set_meta_data.byte_len();
        size += byte_len_array(&self.extension_fields);
        size += self.data_set_source.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.name.encode(stream)?;
        size += write_array(stream, &self.data_set_folder)?;
        size += self.data_set_meta_data.encode(stream)?;
        size += write_array(stream, &self.extension_fields)?;
        size += self.data_set_source.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let name = UAString::decode(stream, decoding_options)?;
        let data_set_folder: Option<Vec<UAString>> = read_array(stream, decoding_options)?;
        let data_set_meta_data = DataSetMetaDataType::decode(stream, decoding_options)?;
        let extension_fields: Option<Vec<KeyValuePair>> = read_array(stream, decoding_options)?;
        let data_set_source = ExtensionObject::decode(stream, decoding_options)?;
        Ok(PublishedDataSetDataType {
            name,
            data_set_folder,
            data_set_meta_data,
            extension_fields,
            data_set_source,
        })
    }

    fn type_id() -> NodeId {
        ObjectId::PublishedDataSetDataType_Encoding_DefaultBinary.into()
    }
}
