use std::cmp::min;
use std::fmt::Display;

use aes::hazmat::cipher_round;
use aes::Block;
use rustc_serialize::hex::ToHex;

pub const AEZ_KEY_SIZE: usize = 16 * 3;

#[derive(Debug)]
pub struct AezData {
    pub key: [Block; 3],
    pub tau: u32,
    pub nonce: Vec<u8>,
    pub ad: Vec<Vec<u8>>,
    pub plaintext: Vec<u8>,
}

impl AezData {
    pub fn new(
        key: &[u8; AEZ_KEY_SIZE],
        tau: u32,
        nonce: Vec<u8>,
        ad: Vec<Vec<u8>>,
        mut plaintext: Vec<u8>,
    ) -> Self {
        let key: Vec<Block> = key
            .chunks_exact(16)
            .map(|chunk| -> Block { u8_to_block(chunk) })
            .collect();
        let key = TryInto::<[Block; 3]>::try_into(key).unwrap();

        plaintext.append(&mut vec![0u8; tau as usize]);

        Self {
            key,
            tau,
            nonce,
            ad,
            plaintext,
        }
    }

    pub fn is_valid(&self) -> bool {
        (self.plaintext.len() >= self.tau as usize)
            && (self.plaintext[(self.plaintext.len() - self.tau as usize)..]
                == vec![0u8; self.tau as usize])
    }

    pub fn ciphertext(&self) -> Vec<u8> {
        let delta = self.hash();
        aez_core(self, &delta)
    }

    pub fn hash(&self) -> Block {
        let header: Vec<Vec<u8>> = Vec::from([
            Vec::from(((self.tau as u128) << 3).to_be_bytes()),
            self.nonce.to_owned(),
        ]);
        aez_hash(&self.key, &[header, self.ad.to_owned()].concat())
    }

    pub fn update_plaintext(&mut self, ciphertext: &Vec<u8>) {
        let delta = self.hash();
        self.plaintext = aez_core_inv(&self, ciphertext, &delta);
    }
}

pub fn parse_aez(
    message: &Vec<u8>,
) -> (
    Vec<(Block, Block)>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Block,
    Block,
) {
    if message.len() < 32 {
        panic!("Message to short, implement AEZ-Tiny.");
    }

    let (mx, my) = (
        u8_to_block(&message[message.len() - 32..message.len() - 16]),
        u8_to_block(&message[message.len() - 16..message.len()]),
    );

    let m: Vec<(Block, Block)> = message[0..(message.len() - 32)]
        .chunks_exact(32)
        .map(|chunk| (u8_to_block(&chunk[0..16]), u8_to_block(&chunk[16..32])))
        .collect();

    let d = message.len() % 32;
    let start_index = message.len() - 32 - d;
    let mu = if d == 0 {
        None
    } else {
        Some(message[start_index..start_index + min(16, d)].to_owned())
    };
    let mv = if d < 16 {
        None
    } else {
        Some(message[start_index + 16..start_index + d].to_owned())
    };

    (m, mu, mv, mx, my)
}

pub fn encrypt(
    key: &[u8; AEZ_KEY_SIZE],
    tau: u32,
    nonce_array: &[u8],
    ad: &Vec<Vec<u8>>,
    plaintext: &[u8],
) -> Vec<u8> {
    AezData::new(
        key,
        tau,
        nonce_array.to_owned(),
        ad.to_vec(),
        plaintext.to_owned(),
    )
    .ciphertext()
}

pub fn decrypt(
    key: &[u8; AEZ_KEY_SIZE],
    tau: u32,
    nonce: &Vec<u8>,
    ad: &Vec<Vec<u8>>,
    ciphertext: &Vec<u8>,
) -> Vec<u8> {
    let mut data = AezData::new(key, tau, nonce.to_vec(), ad.to_vec(), Vec::new());
    data.update_plaintext(ciphertext);
    return data.plaintext;
}

/* Use to get access to intermediate states during encryption. */
pub fn aez_core_into(data: &AezData, delta: &Block) -> (Vec<u8>, Vec<Block>) {
    let (plain_m, plain_mu, plain_mv, plain_mx, plain_my) = parse_aez(&data.plaintext);
    let key = &data.key;

    let array_w: Vec<Block> = plain_m
        .iter()
        .enumerate()
        .map(|(i, (mi, mip))| xor_block(mi, &tbc(mip, key, 1, i as u32 + 1)))
        .collect();

    let array_x: Vec<Block> = array_w
        .iter()
        .zip(&plain_m)
        .map(|(wi, (_, mip))| xor_block(mip, &tbc(wi, key, 0, 0)))
        .collect();

    let mut sum_x = xor_blocks(&array_x);
    if let Some(mu) = &plain_mu {
        xor_block_assign(&mut sum_x, &tbc(&u8_to_block(mu), key, 0, 4));
    }
    if let Some(mv) = &plain_mv {
        xor_block_assign(&mut sum_x, &tbc(&u8_to_block(mv), key, 0, 5));
    }

    let sx = xor_blocks(&[plain_mx, *delta, sum_x, tbc(&plain_my, key, 0, 1)]);
    let sy = xor_block(&plain_my, &tbc(&sx, key, -1, 1));
    let s = xor_block(&sx, &sy);

    let mut array_y: Vec<Block> = Vec::new();
    let mut array_z: Vec<Block> = Vec::new();
    let mut array_c: Vec<Block> = Vec::new();
    let mut array_cprime: Vec<Block> = Vec::new();
    for (i, wi) in array_w.iter().enumerate() {
        let sprime = tbc(&s, key, 2, i as u32 + 1);
        array_y.push(xor_block(wi, &sprime));
        array_z.push(xor_block(&array_x[i], &sprime));

        array_cprime.push(xor_block(
            &array_y.last().unwrap(),
            &tbc(array_z.last().unwrap(), key, 0, 0),
        ));
        array_c.push(xor_block(
            &array_z.last().unwrap(),
            &tbc(array_cprime.last().unwrap(), key, 1, i as u32 + 1),
        ));
    }

    let mut sum_y = xor_blocks(&array_y);

    let cu = if let Some(mu) = &plain_mu {
        let mut cu = Vec::new();
        let enc_s = tbc(&s, key, -1, 4);
        for (i, u) in mu.iter().enumerate() {
            let a = *u ^ enc_s[i];
            cu.push(a);
        }
        xor_block_assign(&mut sum_y, &tbc(&u8_to_block(&cu), key, 0, 4));
        cu
    } else {
        Vec::new()
    };

    let cv = if let Some(mv) = &plain_mv {
        let mut cv = Vec::new();
        let enc_s = tbc(&s, key, -1, 5);
        for (i, v) in mv.iter().enumerate() {
            let a = *v ^ enc_s[i];
            cv.push(a);
        }
        xor_block_assign(&mut sum_y, &tbc(&u8_to_block(&cv), key, 0, 5));
        cv
    } else {
        Vec::new()
    };

    let cy = xor_block(&sx, &tbc(&sy, key, -1, 2));
    let cx = xor_blocks(&[sy, *delta, sum_y, tbc(&cy, key, 0, 2)]);

    (
        array_c
            .into_iter()
            .zip(array_cprime)
            .flat_map(|(c, cp)| c.into_iter().chain(cp))
            .chain(cu)
            .chain(cv)
            .chain(cx)
            .chain(cy)
            .collect(),
        vec![sum_x, sum_y],
    )
}

/* Just encryption, ignore the intermediate states. */
pub fn aez_core(data: &AezData, delta: &Block) -> Vec<u8> {
    let (res, _) = aez_core_into(data, delta);
    return res;
}

pub fn aez_core_inv(data: &AezData, ciphertext: &Vec<u8>, delta: &Block) -> Vec<u8> {
    let (ct, ctu, ctv, ctx, cty) = parse_aez(ciphertext);
    let key = &data.key;

    let array_w: Vec<Block> = ct
        .iter()
        .enumerate()
        .map(|(i, (ci, cip))| xor_block(ci, &tbc(cip, key, 1, i as u32 + 1)))
        .collect();

    let array_y: Vec<Block> = array_w
        .iter()
        .zip(&ct)
        .map(|(wi, (_, cip))| xor_block(cip, &tbc(wi, key, 0, 0)))
        .collect();

    let mut sum_y = xor_blocks(&array_y);
    if let Some(cu) = &ctu {
        xor_block_assign(&mut sum_y, &tbc(&u8_to_block(cu), key, 0, 4));
    }
    if let Some(cv) = &ctv {
        xor_block_assign(&mut sum_y, &tbc(&u8_to_block(cv), key, 0, 5));
    }

    let sx = xor_blocks(&[ctx, *delta, sum_y, tbc(&cty, key, 0, 2)]);
    let sy = xor_block(&cty, &tbc(&sx, key, -1, 2));
    let s = xor_block(&sx, &sy);

    let mut array_x: Vec<Block> = Vec::new();
    let mut array_z: Vec<Block> = Vec::new();
    let mut array_m: Vec<Block> = Vec::new();
    let mut array_mprime: Vec<Block> = Vec::new();
    for (i, wi) in array_w.iter().enumerate() {
        let sprime = tbc(&s, key, 2, i as u32 + 1);
        array_x.push(xor_block(wi, &sprime));
        array_z.push(xor_block(&array_y[i], &sprime));

        array_mprime.push(xor_block(
            &array_x.last().unwrap(),
            &tbc(array_z.last().unwrap(), key, 0, 0),
        ));
        array_m.push(xor_block(
            &array_z.last().unwrap(),
            &tbc(array_mprime.last().unwrap(), key, 1, i as u32 + 1),
        ));
    }

    let mut sum_x = xor_blocks(&array_x);

    let mu = if let Some(cu) = &ctu {
        let mut mu = Vec::new();
        let enc_s = tbc(&s, key, -1, 4);
        for (i, u) in cu.iter().enumerate() {
            let a = *u ^ enc_s[i];
            mu.push(a);
        }
        xor_block_assign(&mut sum_x, &tbc(&u8_to_block(&mu), key, 0, 4));
        mu
    } else {
        Vec::new()
    };

    let mv = if let Some(cv) = &ctv {
        let mut mv = Vec::new();
        let enc_s = tbc(&s, key, -1, 5);
        for (i, v) in cv.iter().enumerate() {
            let a = *v ^ enc_s[i];
            mv.push(a);
        }
        xor_block_assign(&mut sum_x, &tbc(&u8_to_block(&mv), key, 0, 5));
        mv
    } else {
        Vec::new()
    };

    let my = xor_block(&sx, &tbc(&sy, key, -1, 1));
    let mx = xor_blocks(&[sy, *delta, sum_x, tbc(&my, key, 0, 1)]);

    array_m
        .into_iter()
        .zip(array_mprime)
        .flat_map(|(c, cp)| c.into_iter().chain(cp))
        .chain(mu)
        .chain(mv)
        .chain(mx)
        .chain(my)
        .collect()
}

pub fn aez_hash(key: &[Block; 3], ad: &Vec<Vec<u8>>) -> Block {
    let mut delta = zero_block();
    for (i, ti) in ad.iter().enumerate() {
        xor_block_assign(&mut delta, &aez_hash_routine(key, ti, i as u32 + 1));
    }
    return delta;
}

pub fn aez_hash_routine(key: &[Block; 3], arz: &[u8], i: u32) -> Block {
    let mut delta = zero_block();
    let j = i as i32 + 2;
    if arz.is_empty() {
        return tbc(&u8_to_block(arz), key, j, 0);
    }
    for (i, ti) in arz.chunks(16).enumerate() {
        xor_block_assign(
            &mut delta,
            &tbc(
                &u8_to_block(ti),
                key,
                j,
                if ti.len() == 16 { i as u32 + 1 } else { 0 },
            ),
        );
    }
    return delta;
}

// Implementation of the tweakable block cipher of AEZ.
/*
   I := key[0]
   J := key[1]
   L := key[2]
*/
pub fn tbc_assign(input: &mut Block, key: &[Block; 3], j: i32, i: u32) {
    if j == -1 {
        let delta = galois_mult(i, &key[2]);
        xor_block_assign(input, &delta);
        for k in [0, 1, 2, 0, 1, 2, 0, 1, 2, 0] {
            cipher_round(input, &key[k]);
        }
        return;
    }

    let delta_i = galois_mult(1 << ((i + 7) / 8), &key[0]); // 2^{ceil(i/8)} * I
    let delta_j = galois_mult(j as u32, &key[1]); // j * J
    let delta_l = galois_mult(i % 8, &key[2]); // (i mod 8) * L
    xor_block_assign(input, &delta_i);
    xor_block_assign(input, &delta_j);
    xor_block_assign(input, &delta_l);

    for k in [1, 0, 2] {
        cipher_round(input, &key[k]);
    }
    cipher_round(input, &zero_block());
    return;
}

pub fn tbc(input: &Block, key: &[Block; 3], j: i32, i: u32) -> Block {
    let mut output = input.to_owned();
    tbc_assign(&mut output, key, j, i);
    return output;
}

// The Galois field multiplication for the AEZ tweekable block cipher.
pub const FEEDBACK_POLY: u128 = 135u128;
pub fn galois_mult(n: u32, val: &Block) -> Block {
    let mut res = 0u128;
    let mut val = u128::from_be_bytes(val.as_slice().try_into().unwrap());

    let mut n = n;
    while n > 0 {
        if n & 1 == 1 {
            res ^= val;
        }
        n >>= 1;
        val = (val << 1) ^ (((val >> 127) & 1) * FEEDBACK_POLY); // val <- 2*val
    }

    Block::from(res.to_be_bytes())
}

#[inline]
pub fn zero_block() -> Block {
    Block::from([0u8; 16])
}

pub fn xor_block(a: &Block, b: &Block) -> Block {
    let mut res = a.to_owned();
    xor_block_assign(&mut res, b);
    res
}

pub fn xor_block_assign(a: &mut Block, b: &Block) {
    a.iter_mut().zip(b).for_each(|(va, vb)| *va ^= *vb);
}

pub fn xor_blocks(a: &[Block]) -> Block {
    a.iter().fold(zero_block(), |a, b| xor_block(&a, b))
}

/* pads with 10* if necessary to complete a full Block. */
pub fn u8_to_block(a: &[u8]) -> Block {
    let mut pad = a.to_owned();
    Block::from(
        TryInto::<[u8; 16]>::try_into(if pad.len() >= 16 {
            &pad[0..16]
        } else {
            // we pad the vector with 10*.
            pad.push(128u8);
            while pad.len() < 16 {
                pad.push(0u8);
            }
            &pad
        })
        .expect("inapropriate u8 vector to block"),
    )
}

pub fn block_to_u128(b: &Block) -> u128 {
    u128::from_be_bytes((*b).into())
}

pub fn u128_to_block(a: u128) -> Block {
    Block::from(a.to_be_bytes())
}

impl Display for AezData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{{")?;
        writeln!(
            f,
            "\"key\": \"{}{}{}\",",
            self.key[0].to_hex(),
            self.key[1].to_hex(),
            self.key[2].to_hex()
        )?;
        writeln!(f, "\"tau\": {},", self.tau * 8)?;
        writeln!(f, "\"nonce\": \"{}\",", self.nonce.to_hex())?;
        write!(f, "\"ad\": [")?;
        for (i, ad) in self.ad.iter().enumerate() {
            write!(
                f,
                "\"{}\"{}",
                ad.to_hex(),
                if i == self.ad.len() - 1 { "" } else { ", " }
            )?;
        }
        writeln!(f, "],")?;
        if self.is_valid() {
            let plen = self.plaintext.len();
            writeln!(
                f,
                "\"plaintext\": \"{}\"",
                self.plaintext[..(plen - self.tau as usize)].to_hex()
            )?;
        } else {
            writeln!(f, "\"invalid plaintext\": \"{}\"", self.plaintext.to_hex())?;
        }
        write!(f, "}}")
    }
}
