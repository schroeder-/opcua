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
    service_types::ThreeDCartesianCoordinates,
    service_types::ThreeDOrientation,
};

#[derive(Debug, Clone, PartialEq)]
pub struct ThreeDFrame {
    pub cartesian_coordinates: ThreeDCartesianCoordinates,
    pub orientation: ThreeDOrientation,
}

impl BinaryEncoder<ThreeDFrame> for ThreeDFrame {
    fn byte_len(&self) -> usize {
        let mut size = 0;
        size += self.cartesian_coordinates.byte_len();
        size += self.orientation.byte_len();
        size
    }

    #[allow(unused_variables)]
    fn encode<S: Write>(&self, stream: &mut S) -> EncodingResult<usize> {
        let mut size = 0;
        size += self.cartesian_coordinates.encode(stream)?;
        size += self.orientation.encode(stream)?;
        Ok(size)
    }

    #[allow(unused_variables)]
    fn decode<S: Read>(stream: &mut S, decoding_options: &DecodingOptions) -> EncodingResult<Self> {
        let cartesian_coordinates = ThreeDCartesianCoordinates::decode(stream, decoding_options)?;
        let orientation = ThreeDOrientation::decode(stream, decoding_options)?;
        Ok(ThreeDFrame {
            cartesian_coordinates,
            orientation,
        })
    }

    fn type_id() -> NodeId {
        ObjectId::ThreeDFrame_Encoding_DefaultBinary.into()
    }
}
