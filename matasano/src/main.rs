mod set1;
mod set2;

use set2::AES_ECB_Encryptor;
use set2::get_block_size;
use set2::decrypt_sufix;
use utils::contains_duplicate;
use utils::from_base64;
use aes::AES_BLOCKLEN;

fn print_array( array: &[u8] ) {
  for b in array {
    print!( "{}, ", b );
  }
  println!();
}

fn main() {

  println!( "There we go again ...");

  let plain = from_base64( "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".as_bytes() );
  println!( "{}", String::from_utf8_lossy( &plain ) );

  let oracle = AES_ECB_Encryptor::new();
  let block_size = get_block_size( &oracle );
  assert_eq!( block_size, AES_BLOCKLEN );
  let encrypted = oracle.encrypt( &[0; 3 * AES_BLOCKLEN] );
  let is_ecb = contains_duplicate( &encrypted, block_size );
  assert!( is_ecb );

  let result = decrypt_sufix(&oracle, block_size);

  println!( "{}", String::from_utf8_lossy( &result ) );

  println!( "The end!" );
}
