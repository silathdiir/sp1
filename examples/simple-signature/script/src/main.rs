use sp1_core_executor::SP1Context;
use sp1_prover::{components::DefaultProverComponents, utils::get_cycles, SP1Prover, SP1Stdin};
use sp1_sdk::utils;
use sp1_stark::SP1ProverOpts;
use std::time::Instant;

pub const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    utils::setup_logger();

    println!("Proving start");

    let stdin = SP1Stdin::new();
    let cycles = get_cycles(ELF, &stdin);
    println!("The compiled ELF has {cycles} cycles");

    let prover = SP1Prover::<DefaultProverComponents>::new();

    let start = Instant::now();
    let (pk, vk) = prover.setup(ELF);
    let duration = start.elapsed();
    println!("Setup time is: {} ms", duration.as_millis());

    let ctx = SP1Context::default();
    let start = Instant::now();
    prover.execute(ELF, &stdin, ctx.clone()).unwrap();
    let duration = start.elapsed();
    println!("Execution time is: {} ms", duration.as_millis());

    let opts = SP1ProverOpts::default();

    let start = Instant::now();
    let core_proof = prover.prove_core(&pk, &stdin, opts, ctx).unwrap();
    let duration = start.elapsed();
    println!("Core proving time is: {} ms", duration.as_millis());

    let num_shards = core_proof.proof.0.len();
    println!("The core proof has {num_shards} shards");

    let start = Instant::now();
    prover.verify(&core_proof.proof, &vk).expect("Proof verification failed");
    let duration = start.elapsed();
    println!("Core verification time is: {} ms", duration.as_millis());

    let start = Instant::now();
    let comporessed_proof = prover.compress(&vk, core_proof, vec![], opts).unwrap();
    let duration = start.elapsed();
    println!("Proof compress time is: {} ms", duration.as_millis());

    let start = Instant::now();
    let shrinked_proof = prover.shrink(comporessed_proof, opts).unwrap();
    let duration = start.elapsed();
    println!("Proof shrink time is: {} ms", duration.as_millis());

    let start = Instant::now();
    let outer_proof = prover.wrap_bn254(shrinked_proof, opts).unwrap();
    let duration = start.elapsed();
    println!("Proof bn254 wrapping time is: {} ms", duration.as_millis());

    println!("Building Groth16 artifacts ...");
    let start = Instant::now();
    let groth16_bn254_artifacts = sp1_prover::build::try_build_groth16_bn254_artifacts_dev(
        prover.wrap_vk(),
        &outer_proof.proof,
    );
    let duration = start.elapsed();
    println!("Groth16 artifacts building time is: {} ms", duration.as_millis());

    println!("Generating Groth16 proof ...");
    let start = Instant::now();
    let _final_proof = prover.wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);
    let duration = start.elapsed();
    println!("Groth16 proof generating time is: {} ms", duration.as_millis());

    println!("Proving complete");
}
