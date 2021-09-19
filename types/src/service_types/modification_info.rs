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
    date_time::DateTime,
    service_types::enums::HistoryUpdateType,
    string::UAString,
};

#[derive(Debug, Clone, PartialEq)]
pub struct ModificationInfo {
    pub modification_time: DateTime,
    pub update_type: HistoryUpdateType,
    pub user_name: UAString,
}

impl MessageInfo for ModificationInfo {
    fn object_id(&self) -> ObjectId {
        ObjectId::ModificationInfo_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<ModificationInfo> for ModificationInfo {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.modification_time.byte_len();
        size += self.update_type.byte_len();
        size += self.user_name.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.modification_time.encode(stream)?;
        size += self.update_type.encode(stream)?;
        size += self.user_name.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let modification_time = DateTime::decode(stream, decoding_options)?;
        let update_type = HistoryUpdateType::decode(stream, decoding_options)?;
        let user_name = UAString::decode(stream, decoding_options)?;
        Ok(ModificationInfo {
            modification_time,
            update_type,
            user_name,
        })
    }

    fn type_id() -> NodeId {
        ObjectId::ModificationInfo_Encoding_DefaultBinary.into()
    }
}
