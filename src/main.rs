pub mod aez_utils;
pub mod parallel;
pub mod tools;

#[cfg(test)]
mod tests;

use crate::tools::*;

const TRIALS: u64 = 1_u64 << 30;
fn main() {
    _find_and_print_datas();
}

fn _find_and_print_datas() {
    if let Some((data1, data2)) = second_attack_scenario(TRIALS) {
        assert_ne!(data1.key, data2.key);
        assert_ne!(data1.plaintext, data2.plaintext);

        assert!(data1.is_valid());
        assert_eq!(data1.ciphertext(), data2.ciphertext());

        println!("Found two great datas:");
        println!("1{}", data1);
        println!("2{}", data2);
    }
}

fn _estimate_proba() {
    let proba = second_attack_proba(TRIALS);
    println!("Estimate 2^{} probability of success.", proba.log2());
}
