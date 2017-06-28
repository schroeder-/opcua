// This file was autogenerated from Opc.Ua.Types.bsd.xml
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use types::*;

/// Adds one or more nodes to the server address space.
#[derive(Debug, Clone, PartialEq)]
pub struct AddNodesResponse {
    pub response_header: ResponseHeader,
    pub results: Option<Vec<AddNodesResult>>,
    pub diagnostic_infos: Option<Vec<DiagnosticInfo>>,
}

impl MessageInfo for AddNodesResponse {
    fn object_id(&self) -> ObjectId {
        ObjectId::AddNodesResponse_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<AddNodesResponse> for AddNodesResponse {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.response_header.byte_len();
        size += byte_len_array(&self.results);
        size += byte_len_array(&self.diagnostic_infos);
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.response_header.encode(stream)?;
        size += write_array(stream, &self.results)?;
        size += write_array(stream, &self.diagnostic_infos)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let response_header = ResponseHeader::decode(stream)?;
        let results: Option<Vec<AddNodesResult>> = read_array(stream)?;
        let diagnostic_infos: Option<Vec<DiagnosticInfo>> = read_array(stream)?;
        Ok(AddNodesResponse {
            response_header,
            results,
            diagnostic_infos,
        })
    }
}
