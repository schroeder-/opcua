// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    basic_types::*, byte_string::ByteString, encoding::*, node_ids::ObjectId,
    service_types::impls::MessageInfo,
};

#[derive(Debug, Clone, PartialEq)]
pub struct TrustListDataType {
    pub specified_lists: u32,
    pub trusted_certificates: Option<Vec<ByteString>>,
    pub trusted_crls: Option<Vec<ByteString>>,
    pub issuer_certificates: Option<Vec<ByteString>>,
    pub issuer_crls: Option<Vec<ByteString>>,
}

impl MessageInfo for TrustListDataType {
    fn object_id(&self) -> ObjectId {
        ObjectId::TrustListDataType_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<TrustListDataType> for TrustListDataType {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.specified_lists.byte_len();
        size += byte_len_array(&self.trusted_certificates);
        size += byte_len_array(&self.trusted_crls);
        size += byte_len_array(&self.issuer_certificates);
        size += byte_len_array(&self.issuer_crls);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.specified_lists.encode(stream)?;
        size += write_array(stream, &self.trusted_certificates)?;
        size += write_array(stream, &self.trusted_crls)?;
        size += write_array(stream, &self.issuer_certificates)?;
        size += write_array(stream, &self.issuer_crls)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(
        stream: &mut S,
        decoding_limits: &DecodingLimits,
    ) -> EncodingResult<Self> {
        let specified_lists = u32::decode(stream, decoding_limits)?;
        let trusted_certificates: Option<Vec<ByteString>> =
            read_array(stream, decoding_limits)?;
        let trusted_crls: Option<Vec<ByteString>> = read_array(stream, decoding_limits)?;
        let issuer_certificates: Option<Vec<ByteString>> =
            read_array(stream, decoding_limits)?;
        let issuer_crls: Option<Vec<ByteString>> = read_array(stream, decoding_limits)?;
        Ok(TrustListDataType {
            specified_lists,
            trusted_certificates,
            trusted_crls,
            issuer_certificates,
            issuer_crls,
        })
    }
}
