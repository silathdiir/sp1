#![no_main]

use bn::{pairing_batch, Group, G1, G2};
// use bn254_hash2curve::hash2g2::HashToG2;
use rand::{thread_rng, Rng};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let rng = &mut thread_rng();

    // X G1 point additions
    {
        const NUM_G1_POINTS: usize = 20;

        let mut result = G1::zero();
        let points: [_; NUM_G1_POINTS] = [0; NUM_G1_POINTS].map(|_| G1::random(rng));

        println!("g1-point-additions BEGIN: {NUM_G1_POINTS}");
        for p in points {
            result = result + p;
        }
        println!("g1-point-additions END");
    }

    /* No sp1 vm optimization
        {
            let msg: [u32; 32] = [0; 32].map(|_| rng.gen());
            let dst: u32 = rng.gen();

            let msg_bytes: [u8; 32 * 4] = {
                let mut res = [0u8; 32 * 4];
                for (i, &val) in msg.iter().enumerate() {
                    let bytes = val.to_be_bytes();
                    res[i * 4..(i * 4 + 4)].copy_from_slice(&bytes);
                }
                res
            };
            let dst_bytes = dst.to_be_bytes();

            println!("hash-to-g2 BEGIN");
            let _g2 = HashToG2(&msg_bytes, &dst_bytes);
            println!("hash-to-g2 END");
        }
    */

    // Pairing batch
    {
        let p1 = G1::random(&mut rand::thread_rng());
        let q1 = G2::random(&mut rand::thread_rng());
        let p2 = G1::random(&mut rand::thread_rng());
        let q2 = G2::random(&mut rand::thread_rng());

        println!("pairing BEGIN");
        pairing_batch(&[(p1, q1), (p2, q2)]).final_exponentiation();
        println!("pairing END");
    }
}
