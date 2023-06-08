extern crate rustc_serialize;
pub mod test_vectors;

use self::rustc_serialize::hex::{FromHex, ToHex};
use crate::aez_utils::*;
use aes::Block;
use test_vectors::*;

#[test]
fn test_ceiling() {
    for i in 0..100 {
        assert_eq!(((i as f32 / 8.).ceil() as u32), (i + 7) / 8, "{i}");
    }
}

#[test]
fn test_tbc() {
    for (key, j, i, a, b) in E_VECTORS {
        let key: Vec<Block> = key
            .from_hex()
            .unwrap()
            .chunks_exact(16)
            .map(|b| u8_to_block(b))
            .collect();
        let key = TryInto::<[Block; 3]>::try_into(key).unwrap();
        let a = u8_to_block(&a.from_hex().unwrap());
        let output = tbc(&a, &key, j, i);

        assert_eq!(b, output.to_hex());
    }
}

#[test]
fn test_hash() {
    for (key, tau, nonce, delta) in HASH_VECTORS {
        let key: Vec<Block> = key
            .from_hex()
            .unwrap()
            .chunks_exact(16)
            .map(|b| u8_to_block(b))
            .collect();
        let key = TryInto::<[Block; 3]>::try_into(key).unwrap();
        let nonce = nonce.from_hex().unwrap();

        let output = aez_hash(
            &key,
            &vec![Vec::from(u128::to_be_bytes(tau as u128)), nonce],
        );

        assert_eq!(delta, output.to_hex());
    }
}

#[test]
fn test_aezcore() {
    for (key, nonce, tau, plain, cipher) in ENCRYPT_VECTORS {
        let key = key.from_hex().unwrap();
        let n = nonce.from_hex().unwrap();
        let plain = plain.from_hex().unwrap();
        let ad = Vec::new();

        /* Test encryption with test vectors */
        let output = encrypt(&key.to_owned().try_into().unwrap(), tau, &n, &ad, &plain);
        assert_eq!(
            cipher,
            output.to_hex(),
            "encryption with tau {tau} nonce {nonce}"
        );

        /* Test decryption */
        let dec: Vec<u8> = decrypt(&key.try_into().unwrap(), tau, &n, &ad, &output);
        assert_eq!(
            [plain, vec![0u8; tau as usize]].concat(),
            dec,
            "decryption with tau {tau} nonce {nonce}"
        );
    }
}

#[test]
fn test_breach_example() {
    let mut data = Vec::new();
    for (key, tau, nonce, ad, plaintext) in KEY_COMMITMENT_BREACH_EXAMPLE {
        let key = key.from_hex().unwrap();
        let nonce = nonce.from_hex().unwrap();
        let plaintext = plaintext.from_hex().unwrap();
        let ad = ad.map(|s| s.from_hex().unwrap());

        data.push(AezData::new(
            &key.try_into().unwrap(),
            tau / 8,
            nonce,
            ad.into(),
            plaintext,
        ))
    }
    assert_eq!(data[0].ciphertext(), data[1].ciphertext());
}

#[test]
fn test_xor_block() {
    let a = 265894651684u128;
    let b = 546483268468435653435u128;
    let ab = a ^ b;
    assert_eq!(
        ab,
        u128::from_be_bytes(
            xor_block(&Block::from(a.to_be_bytes()), &Block::from(b.to_be_bytes()))
                .try_into()
                .unwrap()
        )
    );

    let mut blocka = Block::from(a.to_be_bytes());
    xor_block_assign(&mut blocka, &Block::from(b.to_be_bytes()));
    assert_eq!(ab, u128::from_be_bytes(blocka.try_into().unwrap()));
}

#[test]
fn test_u8_to_block() {
    let a = 0u128.to_be_bytes();
    assert_eq!(u8_to_block(&a), zero_block());

    let a = 1685543548u64.to_be_bytes();
    assert_eq!(
        u8_to_block(&a),
        u8_to_block(
            &[
                1685543548u64.to_be_bytes(),
                ((1 as u64) << 63).to_be_bytes()
            ]
            .concat()
        )
    );

    let a = 128u128.to_be_bytes();
    let b = [0u8; 15];
    assert_eq!(u8_to_block(&a), u8_to_block(&b));
    assert_ne!(zero_block(), u8_to_block(&b));
}

#[test]
fn test_galois_mult() {
    let a = u8_to_block(&5656321u128.to_be_bytes());
    assert_eq!(galois_mult(1, &a), a);
    assert_eq!(galois_mult(0, &a), zero_block());

    let a_shift = u8_to_block(&(5656321u128 << 1).to_be_bytes());
    assert_eq!(galois_mult(2, &a), a_shift);

    let a_2shift = u8_to_block(&(5656321u128 << 2).to_be_bytes());
    assert_eq!(galois_mult(4, &a), a_2shift);

    let msb = u8_to_block(&(1u128 << 127).to_be_bytes());
    let fb = u8_to_block(&FEEDBACK_POLY.to_be_bytes());
    assert_eq!(galois_mult(2, &msb), fb);

    let a_plus_msb = u8_to_block(&(5656321u128 ^ (1u128 << 127)).to_be_bytes());
    let a_shift_plus_fb = u8_to_block(&((5656321u128 << 1) ^ FEEDBACK_POLY).to_be_bytes());
    assert_eq!(galois_mult(2, &a_plus_msb), a_shift_plus_fb);

    let a_shift_plus_fb_plus_a_plus_msb = u8_to_block(
        &((5656321u128 << 1) ^ 5656321u128 ^ FEEDBACK_POLY ^ (1u128 << 127)).to_be_bytes(),
    );
    assert_eq!(galois_mult(3, &a_plus_msb), a_shift_plus_fb_plus_a_plus_msb);
}
