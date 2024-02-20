mod set1;

use crate::set1::aes::SubBytes;
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
use crate::set1::aes::AES_ECB_decrypt;
use crate::set1::aes::AES_ECB_encrypt;
use crate::set1::aes::AES_ctx;
use crate::set1::aes::MixColumns;


fn print_array( array: &[u8] ) {
  for b in array {
    print!( "{}, ", b );
  }
  println!();
}

fn main() {

  println!( "There we go again ...");
  if let Ok( txt ) = fs::read_to_string( "7.txt" ) {
    let mut chars: HashSet<u8> = HashSet::from_iter( BASE64CHARS.to_vec() );
    chars.insert( b'=' );
    let txt = txt.as_bytes().into_iter().filter( |c| chars.contains(c) ).map(|c|*c).collect::<Vec<u8>>();
    let mut bytes = from_base64( &txt );

    let key = "YELLOW SUBMARINE".as_bytes();
    let aes_ctx = AES_ctx::New( &key );

    AES_ECB_decrypt( &aes_ctx, &mut bytes );

    let plain = str::from_utf8( &bytes ).unwrap();
    println!( "{plain}")
  }
}
