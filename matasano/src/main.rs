mod set1;
mod set2;

use itertools::Itertools;
use set2::AES_ECB_Encryptor;
use set2::get_block_size;
use set2::parse;
use set2::encode;
use set2::get_prefix_len;
use set2::Profile_Encryptor;
use utils::contains_duplicate;
use utils::from_base64;
use aes::AES_BLOCKLEN;
use set2::get_encrypted_block;
use set2::Oracle;
use set2::get_padcnt;

fn print_array( array: &[u8] ) {
  for b in array {
    print!( "{}, ", b );
  }
  println!();
}

fn main() {

  println!( "There we go again ...");

  println!( "The end!" );
}
