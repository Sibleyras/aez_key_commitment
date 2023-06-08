pub mod aez_utils;
pub mod tools;

#[cfg(test)]
mod tests;

use crate::tools::*;

fn main() {
    println!("Hello, world!");

    let trials = 1_u64 << 30;

    if let Some((data1, data2)) = second_attack_scenario(trials) {
        assert_ne!(data1.key, data2.key);
        assert_ne!(data1.plaintext, data2.plaintext);

        assert!(data1.is_valid());
        assert_eq!(data1.ciphertext(), data2.ciphertext());

        println!("Found two great datas:");
        println!("1{}", data1);
        println!("2{}", data2);
    }
}
