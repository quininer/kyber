extern crate rand;
extern crate kyber;

use rand::thread_rng;
use kyber::params::{ SYMBYTES, CIPHERTEXTBYTES, PUBLICKEYBYTES, SECRETKEYBYTES };


#[test]
fn test_kyber() {
    let mut key_a = [0; SYMBYTES];
    let mut key_b = [0; SYMBYTES];
    let mut pk = [0; PUBLICKEYBYTES];
    let mut sendb = [0; CIPHERTEXTBYTES];
    let mut sk_a = [0; SECRETKEYBYTES];
    let mut rng = thread_rng();

    for _ in 0..100 {
        kyber::kem::keypair(&mut rng, &mut pk, &mut sk_a);
        kyber::kem::enc(&mut rng, &mut sendb, &mut key_b, &pk);
        assert!(kyber::kem::dec(&mut key_a, &sendb, &sk_a));

        assert!(key_a.iter().any(|&n| n != 0));
        assert_eq!(key_a, key_b);
    }
}
