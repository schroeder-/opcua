// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    basic_types::*, encoding::*, node_ids::ObjectId, service_types::impls::MessageInfo,
    variant::Variant,
};

#[derive(Debug, Clone, PartialEq)]
pub struct GenericAttributeValue {
    pub attribute_id: u32,
    pub value: Variant,
}

impl MessageInfo for GenericAttributeValue {
    fn object_id(&self) -> ObjectId {
        ObjectId::GenericAttributeValue_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<GenericAttributeValue> for GenericAttributeValue {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.attribute_id.byte_len();
        size += self.value.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.attribute_id.encode(stream)?;
        size += self.value.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(
        stream: &mut S,
        decoding_limits: &DecodingLimits,
    ) -> EncodingResult<Self> {
        let attribute_id = u32::decode(stream, decoding_limits)?;
        let value = Variant::decode(stream, decoding_limits)?;
        Ok(GenericAttributeValue {
            attribute_id,
            value,
        })
    }
}
