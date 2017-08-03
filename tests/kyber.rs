extern crate rand;
extern crate kyber;

use rand::OsRng;
use kyber::params::{ BYTES, SHAREDKEYBYTES, PUBLICKEYBYTES, SECRETKEYBYTES };


#[test]
fn test_kyber() {
    let mut key_a = [0; SHAREDKEYBYTES];
    let mut key_b = [0; SHAREDKEYBYTES];
    let mut pk = [0; PUBLICKEYBYTES];
    let mut sendb = [0; BYTES];
    let mut sk_a = [0; SECRETKEYBYTES];
    let mut rng = OsRng::new().unwrap();

    for _ in 0..100 {
        kyber::kyber::keypair(&mut rng, &mut pk, &mut sk_a);
        kyber::kyber::enc(&mut rng, &mut sendb, &mut key_b, &pk);
        kyber::kyber::dec(&mut key_a, &sendb, &sk_a);

        assert!(key_a.iter().any(|&n| n != 0));
        assert_eq!(key_a, key_b);
    }
}
