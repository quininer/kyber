extern crate rand;
extern crate kyber;

use rand::OsRng;
use kyber::params::*;


#[test]
fn test_kex_uake() {
    let mut rng = OsRng::new().unwrap();
    let (mut pkb, mut skb) = ([0; PUBLICKEYBYTES], [0; SECRETKEYBYTES]);
    let mut ska = [0; SECRETKEYBYTES];
    let mut senda = [0; UAKE_SENDABYTES];
    let mut sendb = [0; UAKE_SENDBBYTES];
    let mut tk = [0; SYMBYTES];
    let mut ka = [0; SYMBYTES];
    let mut kb = [0; SYMBYTES];

    kyber::kem::keypair(&mut rng, &mut pkb, &mut skb);
    kyber::kex::uake::init_a(&mut rng, &mut senda, &mut tk, &mut ska, &pkb);
    kyber::kex::uake::shared_b(&mut rng, &mut sendb, &mut kb, &senda, &skb);
    kyber::kex::uake::shared_a(&mut ka, &sendb, &tk, &ska);

    assert!(ka.iter().any(|&n| n != 0));
    assert_eq!(&ka[..], &kb[..]);
}


#[test]
fn test_kex_ake() {
    let mut rng = OsRng::new().unwrap();
    let (mut pkb, mut skb) = ([0; PUBLICKEYBYTES], [0; SECRETKEYBYTES]);
    let (mut pka, mut ska) = ([0; PUBLICKEYBYTES], [0; SECRETKEYBYTES]);
    let mut eska = [0; SECRETKEYBYTES];
    let mut senda = [0; AKE_SENDABYTES];
    let mut sendb = [0; AKE_SENDBBYTES];
    let mut tk = [0; SYMBYTES];
    let mut ka = [0; SYMBYTES];
    let mut kb = [0; SYMBYTES];

    kyber::kem::keypair(&mut rng, &mut pkb, &mut skb);
    kyber::kem::keypair(&mut rng, &mut pka, &mut ska);
    kyber::kex::ake::init_a(&mut rng, &mut senda, &mut tk, &mut eska, &pkb);
    kyber::kex::ake::shared_b(&mut rng, &mut sendb, &mut kb, &senda, &skb, &pka);
    kyber::kex::ake::shared_a(&mut ka, &sendb, &tk, &eska, &ska);

    assert!(ka.iter().any(|&n| n != 0));
    assert_eq!(&ka[..], &kb[..]);
}
