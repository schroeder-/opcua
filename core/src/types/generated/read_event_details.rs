// This file was autogenerated from Opc.Ua.Types.bsd.xml
// DO NOT EDIT THIS FILE

use std::io::{Read, Write};

#[allow(unused_imports)]
use types::*;

#[derive(Debug, Clone, PartialEq)]
pub struct ReadEventDetails {
    pub num_values_per_node: UInt32,
    pub start_time: DateTime,
    pub end_time: DateTime,
    pub filter: EventFilter,
}

impl BinaryEncoder<ReadEventDetails> for ReadEventDetails {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.num_values_per_node.byte_len();
        size += self.start_time.byte_len();
        size += self.end_time.byte_len();
        size += self.filter.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.num_values_per_node.encode(stream)?;
        size += self.start_time.encode(stream)?;
        size += self.end_time.encode(stream)?;
        size += self.filter.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S) -> EncodingResult<Self> {
        let num_values_per_node = UInt32::decode(stream)?;
        let start_time = DateTime::decode(stream)?;
        let end_time = DateTime::decode(stream)?;
        let filter = EventFilter::decode(stream)?;
        Ok(ReadEventDetails {
            num_values_per_node,
            start_time,
            end_time,
            filter,
        })
    }
}
