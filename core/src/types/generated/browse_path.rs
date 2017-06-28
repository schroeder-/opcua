// This file was autogenerated from Opc.Ua.Types.bsd.xml
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use types::*;

/// A request to translate a path into a node id.
#[derive(Debug, Clone, PartialEq)]
pub struct BrowsePath {
    pub starting_node: NodeId,
    pub relative_path: RelativePath,
}

impl MessageInfo for BrowsePath {
    fn object_id(&self) -> ObjectId {
        ObjectId::BrowsePath_Encoding_DefaultBinary
    }
}

impl BinaryEncoder<BrowsePath> for BrowsePath {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.starting_node.byte_len();
        size += self.relative_path.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.starting_node.encode(stream)?;
        size += self.relative_path.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let starting_node = NodeId::decode(stream)?;
        let relative_path = RelativePath::decode(stream)?;
        Ok(BrowsePath {
            starting_node,
            relative_path,
        })
    }
}
