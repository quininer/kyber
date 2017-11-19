extern crate rand;
extern crate rustc_hex;
extern crate kyber;

use rand::Rng;
use rustc_hex::{ FromHex, FromHexError };

#[cfg(feature = "kyber512")]
const TEST_VECTOR: &str = include_str!("testvectork2.txt");

#[cfg(feature = "kyber768")]
const TEST_VECTOR: &str = include_str!("testvectork3.txt");

#[cfg(feature = "kyber1024")]
const TEST_VECTOR: &str = include_str!("testvectork4.txt");


#[derive(Default)]
struct FixedRng(pub Vec<u8>);

impl Rng for FixedRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        let drain = self.0.drain(..buf.len()).collect::<Vec<_>>();
        buf.copy_from_slice(&drain);
    }
}

#[derive(Default)]
struct Vectors {
    pub pk: Vec<u8>,
    pub sk_a: Vec<u8>,
    pub sendb: Vec<u8>,
    pub key_b: Vec<u8>,
    pub key_a: Vec<u8>
}

fn parse_testvector(input: &str) -> Result<(FixedRng, Vectors), FromHexError> {
    let (mut rng, mut vecs): (FixedRng, Vectors) = Default::default();

    for (i, line) in input.lines()
        .take(8)
        .map(|line| line.from_hex())
        .enumerate()
    {
        let mut line = line?;
        match i {
            0...1 | 4 => rng.0.append(&mut line),
            2 => vecs.pk.append(&mut line),
            3 => vecs.sk_a.append(&mut line),
            5 => vecs.sendb.append(&mut line),
            6 => vecs.key_b.append(&mut line),
            7 => vecs.key_a.append(&mut line),
            _ => unreachable!()
        }
    }

    Ok((rng, vecs))
}


#[test]
fn test_testvector() {
    use kyber::params::{ SHAREDKEYBYTES, CIPHERTEXTBYTES, PUBLICKEYBYTES, SECRETKEYBYTES };

    let (mut rng, vecs) = parse_testvector(TEST_VECTOR).unwrap();

    let (mut key_a, mut key_b) = ([0; SHAREDKEYBYTES], [0; SHAREDKEYBYTES]);
    let mut pk = [0; PUBLICKEYBYTES];
    let mut sendb = [0; CIPHERTEXTBYTES];
    let mut sk_a = [0; SECRETKEYBYTES];

    kyber::kem::keypair(&mut rng, &mut pk, &mut sk_a);

    assert_eq!(vecs.pk, &pk[..]);
    assert_eq!(&vecs.sk_a[..SECRETKEYBYTES-32], &sk_a[..SECRETKEYBYTES-32]);
    assert_eq!(&vecs.sk_a[SECRETKEYBYTES-32..], &sk_a[SECRETKEYBYTES-32..]);
    assert_eq!(vecs.sk_a, &sk_a[..]);

    kyber::kem::enc(&mut rng, &mut sendb, &mut key_b, &pk);

    assert_eq!(vecs.sendb, &sendb[..]);
    assert_eq!(vecs.key_b, &key_b[..]);

    kyber::kem::dec(&mut key_a, &sendb, &sk_a);

    assert_eq!(vecs.key_a, &key_a[..]);
}
