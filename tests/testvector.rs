extern crate rand;
extern crate data_encoding;
extern crate kyber;

use rand::Rng;
use data_encoding::{ HEXLOWER, DecodeError };

const TEST_VECTOR: &str = include_str!("testvector.txt");


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

fn parse_testvector(input: &str) -> Result<(FixedRng, Vectors), DecodeError> {
    let (mut rng, mut vecs): (FixedRng, Vectors) = Default::default();

    for (i, line) in input.lines()
        .take(9)
        .map(|line| HEXLOWER.decode(line.as_bytes()))
        .enumerate()
    {
        match i {
            0...2 | 5 => rng.0.append(&mut line?),
            3 => vecs.pk.append(&mut line?),
            4 => vecs.sk_a.append(&mut line?),
            6 => vecs.sendb.append(&mut line?),
            7 => vecs.key_b.append(&mut line?),
            8 => vecs.key_a.append(&mut line?),
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
    assert_eq!(vecs.sk_a, &sk_a[..]);

    kyber::kem::enc(&mut rng, &mut sendb, &mut key_b, &pk);

    assert_eq!(vecs.sendb, &sendb[..]);
    assert_eq!(vecs.key_b, &key_b[..]);

    kyber::kem::dec(&mut key_a, &sendb, &sk_a);

    assert_eq!(vecs.key_a, &key_a[..]);
}
