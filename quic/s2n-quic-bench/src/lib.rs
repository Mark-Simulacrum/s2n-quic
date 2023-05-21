// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use criterion::Criterion;

//mod buffer;
//mod crypto;
//mod frame;
//mod inet;
//mod packet;
mod request_response;
//mod sync;
//mod varint;
//mod xdp;

pub fn benchmarks(c: &mut Criterion) {
    //buffer::benchmarks(c);
    //crypto::benchmarks(c);
    //frame::benchmarks(c);
    //inet::benchmarks(c);
    //packet::benchmarks(c);
    //sync::benchmarks(c);
    //varint::benchmarks(c);
    //xdp::benchmarks(c);
    request_response::benchmarks(c);
}
