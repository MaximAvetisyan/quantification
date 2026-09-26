pub const COMPRESSOR_PROTO: &[u8] = include_bytes!("../compressor/v1/compressor.proto");

pub mod compressor {
    pub mod v1 {
        tonic::include_proto!("compressor.v1");
    }
}

pub mod convert;
