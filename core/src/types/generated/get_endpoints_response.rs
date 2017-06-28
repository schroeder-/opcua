// This file was autogenerated from Opc.Ua.Types.bsd.xml
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use types::*;

/// Gets the endpoints used by the server.
#[derive(Debug, Clone, PartialEq)]
pub struct GetEndpointsResponse {
    pub response_header: ResponseHeader,
    pub endpoints: Option<Vec<EndpointDescription>>,
}

impl MessageInfo for GetEndpointsResponse {
    fn object_id(&self) -> ObjectId {
        ObjectId::GetEndpointsResponse_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<GetEndpointsResponse> for GetEndpointsResponse {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.response_header.byte_len();
        size += byte_len_array(&self.endpoints);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.response_header.encode(stream)?;
        size += write_array(stream, &self.endpoints)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let response_header = ResponseHeader::decode(stream)?;
        let endpoints: Option<Vec<EndpointDescription>> = read_array(stream)?;
        Ok(GetEndpointsResponse {
            response_header,
            endpoints,
        })
    }
}
