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
    localized_text::LocalizedText,
};

#[derive(Debug, Clone, PartialEq)]
pub struct CurrencyUnitType {
    pub numeric_code: i16,
    pub exponent: i8,
    pub alphabetic_code: UAString,
    pub currency: LocalizedText,
}

impl MessageInfo for CurrencyUnitType {
    fn object_id(&self) -> ObjectId {
        ObjectId::CurrencyUnitType_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<CurrencyUnitType> for CurrencyUnitType {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.numeric_code.byte_len();
        size += self.exponent.byte_len();
        size += self.alphabetic_code.byte_len();
        size += self.currency.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.numeric_code.encode(stream)?;
        size += self.exponent.encode(stream)?;
        size += self.alphabetic_code.encode(stream)?;
        size += self.currency.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let numeric_code = i16::decode(stream, decoding_options)?;
        let exponent = i8::decode(stream, decoding_options)?;
        let alphabetic_code = UAString::decode(stream, decoding_options)?;
        let currency = LocalizedText::decode(stream, decoding_options)?;
        Ok(CurrencyUnitType {
            numeric_code,
            exponent,
            alphabetic_code,
            currency,
        })
    }

    fn type_id() -> NodeId {
        ObjectId::CurrencyUnitType_Encoding_DefaultBinary.into()
    }
}
