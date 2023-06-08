use bit_vec::BitVec;
use rand::prelude::*;
use std::sync::mpsc;
use std::thread;

/*
A collection of useful function to be used to break AEZ key commitment.
*/
use crate::aez_utils::*;
use aes::hazmat::*;
use aes::Block;

/*
Return a couple of data with different keys and plaintext but the same ciphertext and tau = 128 authentication bits.
*/
pub fn second_attack_scenario(trials: u64) -> Option<(AezData, AezData)> {
    match parrallel_search(trials) {
        (work, Some((sx, key1, key2))) => {
            println!(
                "Found a zero diff trail after {} trials.",
                (work as f64).log2()
            );
            Some(derive_plaintext(sx, key1, key2))
        }
        (_, None) => {
            println!("No trail found.");
            None
        }
    }
}

/*
Takes in input sx, key1, key2 such that tbc( tbc(sx, -1, 1), -1, 2) is the same using key1 or key2.
Return two data with keys key1 and key2 having the same ciphertext and tau = 128 authentication bits.
*/
pub fn derive_plaintext(sx: Block, key1: [Block; 3], key2: [Block; 3]) -> (AezData, AezData) {
    let mut data1 = AezData {
        key: key1,
        tau: 16,
        nonce: rand_block().to_vec(),
        ad: Vec::new(),
        plaintext: Vec::new(),
    };

    let mut data2 = AezData {
        key: key2,
        tau: 16,
        nonce: rand_block().to_vec(),
        ad: Vec::new(),
        plaintext: Vec::new(),
    };

    let sy = tbc(&sx, &key1, -1, 1); // My is all zero because tau = 128.

    let cty = xor_block(&sx, &tbc(&sy, &key1, -1, 2));
    let ctx = rand_block();
    let ciphertext: Vec<u8> = (0..2)
        .flat_map(|_| rand_block())
        .chain(ctx)
        .chain(cty)
        .collect(); // the target ciphertext is (5 random blocks) || cty

    data1.update_plaintext(&ciphertext);
    data2.update_plaintext(&ciphertext);

    let (_, sumxy) = aez_core_into(&data1, &data1.hash());
    let sum_y1 = sumxy[1];
    let (_, sumxy) = aez_core_into(&data2, &data2.hash());
    let sum_y2 = sumxy[1];

    let tar_delta1 = xor_blocks(&[tbc(&cty, &key1, 0, 2), ctx, sum_y1, sy]);
    let tar_delta2 = xor_blocks(&[tbc(&cty, &key2, 0, 2), ctx, sum_y2, sy]);

    set_delta(&mut data1, &tar_delta1);
    set_delta(&mut data2, &tar_delta2);

    data1.update_plaintext(&ciphertext);
    data2.update_plaintext(&ciphertext);

    (data1, data2)
}

/* Try hard to make the attack works. */
pub fn parrallel_search(trials: u64) -> (u64, Option<(Block, [Block; 3], [Block; 3])>) {
    const CHUNK_WORK: u64 = 0x1000;
    let mut threads = Vec::new();
    let (t_finish, r_finish) = mpsc::channel();
    let nbthreads = num_cpus::get();

    for _ in 0..nbthreads {
        let t_finish = t_finish.clone();

        threads.push(thread::spawn(move || {
            while t_finish.send(None).is_ok() {
                for _ in 0..CHUNK_WORK {
                    let attempt = zero_diff_val();
                    if attempt.is_some() {
                        t_finish.send(attempt).unwrap();
                    }
                }
            }
        }));
    }

    let mut total_works = 0;
    for attempt in r_finish {
        if attempt.is_some() {
            return (total_works, attempt);
        }
        total_works += CHUNK_WORK;
        if total_works >= trials {
            return (total_works, None);
        }
    }
    (total_works, None)
}

/* Try to randomly find a set of values to break key commitment. This is the heart of the attack with an estimated 2^-27 probability of success. */
pub fn zero_diff_val() -> Option<(Block, [Block; 3], [Block; 3])> {
    let w = rand_block();
    let (key1, key2) = involution_keys(&w);

    let mid_res = tbc(&w, &key1, -1, 1); // This value has to be independent of key1 and key2 by involution_keys.

    if tbc(&mid_res, &key1, -1, 2) == tbc(&mid_res, &key2, -1, 2) {
        Some((w, key1, key2))
    } else {
        None
    }
}

/* Get random keys that create an involution and has good differentials for the attack */
pub fn involution_keys(w: &Block) -> ([Block; 3], [Block; 3]) {
    let (l, i, lp, ip) = guess_keys(w);

    let j = aes_enc(&aes_enc(&xor_block(w, &l), &i), &aes_dec(w, &zero_block()));

    ([i, j, l], [ip, j.to_owned(), lp])
}

/*
We chose a difference that pass DL -> DI with probability 2^-7 and 2DL -> DI with probability 2^-6.
The transition DL -> DI with input IN_BYTE is guaranteed.
*/
pub fn guess_keys(w: &Block) -> (Block, Block, Block, Block) {
    const DL: [u8; 16] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    const DI: [u8; 16] = [40, 20, 20, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    const IN_BYTE: u8 = 0x2a;

    let mut l = rand_block();
    l[0] = w[0] ^ IN_BYTE;
    //println!("l : {:#016x}", block_to_u128(&l));

    let lp = l.to_owned();
    let lp = xor_block(&lp, &Block::from(DL));

    let i = aes_enc(&xor_block(w, &l), &zero_block());

    let ip = i.to_owned();
    let ip = xor_block(&ip, &Block::from(DI));

    (l, i, lp, ip)
}

pub fn rand_block() -> Block {
    let mut rng = rand::thread_rng();
    u128_to_block(rng.gen())
}

/*
Add blocks of additional data to get to the tagetted delta.
Return true if successful.
*/
pub fn set_delta(data: &mut AezData, target: &Block) -> bool {
    if &data.hash() == target {
        return true;
    }

    let len_ad = data.ad.len();
    let ad_blocks = [vec![5u8], vec![76u8]];
    let target = block_to_u128(target);

    // Increase the number of data to append until we have enough to get our target.
    let nb_data_start = 126;
    let nb_data_end = 250;
    data.ad
        .append(&mut vec![ad_blocks[0].to_owned(); nb_data_start - 1]); // we push one at the start of the loop.
    for nb_data in nb_data_start..nb_data_end {
        // add one element of additional data.
        data.ad.push(ad_blocks[0].to_owned());

        // adding a element changes the base hash.
        let curr_hash = block_to_u128(&data.hash());
        let tar_diff = target ^ curr_hash;

        if tar_diff == 0 {
            return true;
        }

        // Fill an array with the differences implied by each swap of block of ad.
        let mut arr_diff = vec![0u128; nb_data];
        for i in 0..nb_data {
            data.ad[len_ad + i] = ad_blocks[1].to_owned();
            arr_diff[i] = curr_hash ^ block_to_u128(&data.hash());
            data.ad[len_ad + i] = ad_blocks[0].to_owned();
        }

        // If a combnination is found, we swap the block at those positions and we're done.
        if let Some(ad_combination) = find_xor(&arr_diff, tar_diff) {
            for i in ad_combination {
                data.ad[len_ad + i] = ad_blocks[1].to_owned();
            }
            return true;
        }
    }
    return false;
}

// Take an array and return all positions such that the XOR of values at those positions equal to tar.
pub fn find_xor(arr: &[u128], tar: u128) -> Option<Vec<usize>> {
    // The variable @gauss is an len x 128 + len bit matrix where a line is a tuple (u128, u128).
    // The left side is the len x 128 input arr and the right side is the len x len identity matrix to keep track of line combinations during the gaussian elimination.
    let mut gauss: Vec<(u128, BitVec)> = arr
        .to_owned()
        .into_iter()
        .enumerate()
        .map(|(i, u)| {
            (u, {
                let mut vec = BitVec::from_elem(arr.len(), false);
                vec.set(i, true);
                vec
            })
        })
        .collect();

    // Add the target at the end.
    gauss.push((tar, BitVec::from_elem(arr.len(), false)));

    // Perform gaussian elimination.
    gaussian_elimination(&mut gauss);

    match gauss.last() {
        Some((0, v)) => Some((0..v.len()).filter(|pos| v[*pos]).collect()),
        _ => return None,
    }
}

// Take a matrix and return it in echeloned form.
pub fn gaussian_elimination(matrix: &mut [(u128, BitVec)]) {
    let id_matrix_len = matrix[0].1.len(); // This is the dimension of the identity matrix and where to look for pivot.

    let mut echeloned_rows = 0;
    for bit_pos in 0..128 {
        if let Some((i, _)) = matrix
            .iter()
            .enumerate()
            // Look for a pivot row with a 'one' on its bit_pos position among the remaining rows.
            .find(|(i, (v, _))| {
                *i >= echeloned_rows && *i < id_matrix_len && (((*v) >> bit_pos) & 1) == 1
            })
        {
            matrix.swap(i, echeloned_rows);
            let curr_row = matrix[echeloned_rows].to_owned();
            for row in matrix[echeloned_rows + 1..].iter_mut() {
                if (row.0 >> bit_pos) & 1 == 1 {
                    row_xor(row, &curr_row);
                }
            }
            echeloned_rows += 1;
            if echeloned_rows >= id_matrix_len {
                return;
            }
        }
    }
}

fn row_xor(a: &mut (u128, BitVec), b: &(u128, BitVec)) {
    a.0 ^= b.0;
    a.1.xor(&b.1);
}

#[inline]
pub fn aes_enc(block: &Block, key: &Block) -> Block {
    let mut res = block.to_owned();
    aes_forward(&mut res, key);
    res
}

#[inline]
pub fn aes_dec(block: &Block, key: &Block) -> Block {
    let mut res = block.to_owned();
    aes_backward(&mut res, key);
    res
}

#[inline]
pub fn aes_forward(block: &mut Block, key: &Block) {
    cipher_round(block, &key);
}

#[inline]
pub fn aes_backward(block: &mut Block, key: &Block) {
    xor_block_assign(block, &key);
    inv_mix_columns(block);
    equiv_inv_cipher_round(block, &zero_block());
    mix_columns(block);
}

#[cfg(test)]
mod tests {
    extern crate rustc_serialize;
    use super::*;

    use self::rustc_serialize::hex::FromHex;
    use aes::Block;

    #[test]
    pub fn test_derive_plaintext() {
        for (sx, key1, key2) in crate::tests::test_vectors::DIFF_ZERO_VECTORS {
            let sx = u128_to_block(sx);
            let key1 = key1.map(|k| u128_to_block(k));
            let key2 = key2.map(|k| u128_to_block(k));
            let (data1, data2) = derive_plaintext(sx, key1, key2);

            for data in [&data1, &data2] {
                assert!(data.is_valid());
            }

            assert_ne!(data1.plaintext, data2.plaintext);
            assert_eq!(data1.ciphertext(), data2.ciphertext());
        }
    }

    #[test]
    pub fn test_involution_keys() {
        let w = rand_block();
        let (k1, k2) = involution_keys(&w);

        let mut enc1 = xor_block(&w, &k1[2]);
        let mut enc2 = xor_block(&w, &k2[2]);
        cipher_round(&mut enc1, &k1[0]);
        cipher_round(&mut enc2, &k2[0]);
        assert_eq!(enc1, enc2, "Output not equal after L,I");

        cipher_round(&mut enc1, &k1[1]);
        cipher_round(&mut enc2, &k2[1]);
        cipher_round(&mut enc1, &zero_block());
        cipher_round(&mut enc2, &zero_block());
        assert_eq!(enc1, w, "No involution after L,I,J");
        assert_eq!(enc1, enc2, "Output not equal after Lp,Ip,J");

        let enc1 = tbc(&w, &k1, -1, 1);
        let enc2 = tbc(&w, &k2, -1, 1);

        assert_eq!(enc1, enc2, "Output of tbc not equal");
    }

    #[test]
    pub fn test_aes() {
        let key = rand_block();
        let input = rand_block();

        let mut output = input.to_owned();
        aes_forward(&mut output, &key);
        aes_backward(&mut output, &key);

        assert_eq!(input, output);
    }

    #[test]
    pub fn test_set_delta() {
        let key = "2923be84e16cd6ae529049f1f1bbe9ebb3a6db3c870c3e99245e0d1c06b747deb3124dc843bb8ba61f035a7d0938251f";
        let nonce = "8747290a0d805e104a1ec8477e2fccd5";
        let mut data = AezData::new(
            &key.from_hex().unwrap().try_into().unwrap(),
            16,
            nonce.from_hex().unwrap(),
            Vec::new(),
            Vec::new(),
        );

        let target: Block = u8_to_block(&"015482b36334d9abbda295064b6063c3".from_hex().unwrap());

        assert_ne!(data.hash(), target);
        if !set_delta(&mut data, &target) {
            panic!("Set delta FAILED");
        }
        assert_eq!(data.hash(), target);
    }

    #[test]
    pub fn test_gaussian_elimination() {
        let matrix = [
            0x8748290a0d805e104a1ec8477e2fccd5_u128,
            0xe6ec77f068c7023cffcdd16bdd38c727_u128,
            0x34c7fff3f1524e7177089c7abe4ad226_u128,
            0xcad106bc0a83dfa2454678753483e114_u128,
            0xe6ec77f068c7023cffcdd16bdd38c721_u128,
            0x34c7fff3f1524e7177089c7abe4ad223_u128,
            0xcad106bc0a83dfa2454678753483e11a_u128,
            0x38cae41343f1d93517052cd0cb90ce5c_u128,
            0xd8b81d123771b53e14f2274b08036b5d_u128,
        ];

        let mut gauss: Vec<(u128, BitVec)> = matrix
            .to_owned()
            .into_iter()
            .enumerate()
            .map(|(i, u)| {
                (u, {
                    let mut vec = BitVec::from_elem(matrix.len(), false);
                    vec.set(i, true);
                    vec
                })
            })
            .collect();

        gaussian_elimination(&mut gauss);
        let gaussed = gauss.to_owned();

        gaussian_elimination(&mut gauss);

        assert_eq!(gaussed.last().unwrap().0 & 0xFF, 0);
        assert_eq!(gaussed, gauss);
    }
}
