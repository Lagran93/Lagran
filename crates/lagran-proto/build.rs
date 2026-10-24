fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Uncomment and adjust when .proto files are ready:
    //
    // tonic_build::configure()
    //     .build_server(true)
    //     .build_client(true)
    //     .out_dir("src/generated")
    //     .compile(
    //         &[
    //             "../../proto/control/config.proto",
    //             "../../proto/control/node.proto",
    //             "../../proto/control/purge.proto",
    //             "../../proto/control/stats.proto",
    //             "../../proto/common/types.proto",
    //         ],
    //         &["../../proto"],
    //     )?;

    println!("cargo:rerun-if-changed=../../proto");
    Ok(())
}
