mod set1;
mod set2;

use crate::set1::repeating_xor;
use crate::set1::hamming_distance;
use crate::set1::break_repeating_xor_key;
use crate::set1::from_base64;
use crate::set1::xor_hexstr;
use crate::set1::BASE64CHARS;
use crate::set1::get_key_sizes;
use std::fs;
use std::env;
use std::collections::HashSet;
use std::str;

fn print_array( array: &[u8] ) {
  for b in array {
    print!( "{}, ", b );
  }
  println!();
}

fn main() {

  println!( "There we go again ...");
  // if let Ok( txt ) = fs::read_to_string( "8.txt" ) {
  //   let aes_ecb = txt.split( "\n" ).filter( |l|contains_duplicate(*l) ).collect::<Vec<_>>();
  //   println!( "{}", aes_ecb[0] );
  // }
}
