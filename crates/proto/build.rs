fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=compressor/v1/compressor.proto");
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&["compressor/v1/compressor.proto"], &["."])?;
    Ok(())
}
