extern crate rand;
extern crate hex;
extern crate kyber;

use std::io::Cursor;
use rand::{ RngCore, CryptoRng };
use rand::rngs::adapter::ReadRng;
use hex::FromHexError;

#[cfg(feature = "kyber512")]
const TEST_VECTOR: &str = include_str!("testvectork2.txt");

#[cfg(feature = "kyber768")]
const TEST_VECTOR: &str = include_str!("testvectork3.txt");

#[cfg(feature = "kyber1024")]
const TEST_VECTOR: &str = include_str!("testvectork4.txt");


#[derive(Default)]
struct Vector {
    pub pk: Vec<u8>,
    pub sk_a: Vec<u8>,
    pub sendb: Vec<u8>,
    pub key_b: Vec<u8>,
    pub key_a: Vec<u8>
}

type FixedRng = UnsafeRng<ReadRng<Cursor<Vec<u8>>>>;

struct UnsafeRng<R>(R);

impl<R: RngCore> RngCore for UnsafeRng<R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl<R: RngCore> CryptoRng for UnsafeRng<R> {}

fn parse_testvector(input: &str) -> Result<(FixedRng, Vector), FromHexError> {
    let (mut rng, mut vecs): (Vec<u8>, Vector) = Default::default();

    for (i, line) in input.lines()
        .take(8)
        .map(hex::decode)
        .enumerate()
    {
        let mut line = line?;
        match i {
            0...1 | 4 => rng.append(&mut line),
            2 => vecs.pk.append(&mut line),
            3 => vecs.sk_a.append(&mut line),
            5 => vecs.sendb.append(&mut line),
            6 => vecs.key_b.append(&mut line),
            7 => vecs.key_a.append(&mut line),
            _ => unreachable!()
        }
    }

    Ok((UnsafeRng(ReadRng::new(Cursor::new(rng))), vecs))
}


#[test]
fn test_testvector() {
    use kyber::params::{ SYMBYTES, CIPHERTEXTBYTES, PUBLICKEYBYTES, SECRETKEYBYTES };

    let (mut rng, vecs) = parse_testvector(TEST_VECTOR).unwrap();

    let (mut key_a, mut key_b) = ([0; SYMBYTES], [0; SYMBYTES]);
    let mut pk = [0; PUBLICKEYBYTES];
    let mut sendb = [0; CIPHERTEXTBYTES];
    let mut sk_a = [0; SECRETKEYBYTES];

    kyber::kem::keypair(&mut rng, &mut pk, &mut sk_a);

    assert_eq!(vecs.pk, &pk[..]);
    assert_eq!(vecs.sk_a, &sk_a[..]);

    kyber::kem::enc(&mut rng, &mut sendb, &mut key_b, &pk);

    assert_eq!(vecs.sendb, &sendb[..]);
    assert_eq!(vecs.key_b, &key_b[..]);

    kyber::kem::dec(&mut key_a, &sendb, &sk_a);

    assert_eq!(vecs.key_a, &key_a[..]);
}
