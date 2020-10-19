// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2020 Adam Lock

// This file was autogenerated from Opc.Ua.Types.bsd.xml by tools/schema/gen_types.js
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use crate::{
    basic_types::*, encoding::*, node_ids::ObjectId, service_types::impls::MessageInfo,
    string::UAString,
};

#[derive(Debug, Clone, PartialEq)]
pub struct UserIdentityToken {
    pub policy_id: UAString,
}

impl MessageInfo for UserIdentityToken {
    fn object_id(&self) -> ObjectId {
        ObjectId::UserIdentityToken_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<UserIdentityToken> for UserIdentityToken {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.policy_id.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.policy_id.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(
        stream: &mut S,
        decoding_limits: &DecodingLimits,
    ) -> EncodingResult<Self> {
        let policy_id = UAString::decode(stream, decoding_limits)?;
        Ok(UserIdentityToken { policy_id })
    }
}
