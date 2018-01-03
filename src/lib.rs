extern crate core;

#[macro_use] extern crate arrayref;
extern crate rand;
extern crate subtle;
extern crate byteorder;
extern crate itertools;
extern crate sha3;
extern crate digest;

#[macro_use] mod utils;
mod reduce;
mod poly;
mod polyvec;
mod ntt;
mod cbd;
mod indcpa;
pub mod params;
pub mod kem;
pub mod kex;
