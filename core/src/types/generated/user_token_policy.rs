// This file was autogenerated from Opc.Ua.Types.bsd.xml
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use types::*;

/// Describes a user token that can be used with a server.
#[derive(Debug, Clone, PartialEq)]
pub struct UserTokenPolicy {
    pub policy_id: UAString,
    pub token_type: UserTokenType,
    pub issued_token_type: UAString,
    pub issuer_endpoint_url: UAString,
    pub security_policy_uri: UAString,
}

impl MessageInfo for UserTokenPolicy {
    fn object_id(&self) -> ObjectId {
        ObjectId::UserTokenPolicy_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<UserTokenPolicy> for UserTokenPolicy {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.policy_id.byte_len();
        size += self.token_type.byte_len();
        size += self.issued_token_type.byte_len();
        size += self.issuer_endpoint_url.byte_len();
        size += self.security_policy_uri.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.policy_id.encode(stream)?;
        size += self.token_type.encode(stream)?;
        size += self.issued_token_type.encode(stream)?;
        size += self.issuer_endpoint_url.encode(stream)?;
        size += self.security_policy_uri.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let policy_id = UAString::decode(stream)?;
        let token_type = UserTokenType::decode(stream)?;
        let issued_token_type = UAString::decode(stream)?;
        let issuer_endpoint_url = UAString::decode(stream)?;
        let security_policy_uri = UAString::decode(stream)?;
        Ok(UserTokenPolicy {
            policy_id,
            token_type,
            issued_token_type,
            issuer_endpoint_url,
            security_policy_uri,
        })
    }
}
