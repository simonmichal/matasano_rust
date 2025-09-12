mod set1;
mod set2;
mod set3;

use std::collections::HashSet;
use std::io::Read;
use std::fs;

use itertools::Itertools;
use set2::AES_ECB_Encryptor;
use set2::AES_CBC_Encryptor;
use set2::get_block_size;
use set2::parse;
use set2::encode;
use set2::get_prefix_len;
use set2::Profile_Encryptor;
use utils::{contains_duplicate, get_key, get_key_sizes, get_random_block};
use utils::from_base64;
use aes::AES_BLOCKLEN;
use set2::get_encrypted_block;
use set2::Oracle;
use set2::get_padcnt;
use utils::pkcs7_padding;
use utils::xor_bytes;
use set3::Token_Encryptor;
use set3::get_padding_len;
use set3::find_byte;
use set3::get_block_dec;

use aes::AES_ctx;
use aes::AES_CTR_transform_buffer;

use rand::{distributions::Standard, Rng};
use crate::set1::repeating_xor;

fn print_array(array: &[u8] ) {
  for b in array {
    print!( "{}, ", b );
  }
  println!();
}

fn recover_keystream(cts: &[Vec<u8>]) -> Vec<u8> {
  let max_len = cts.iter().map(|c| c.len()).max().unwrap_or(0);
  let mut ks = vec![0u8; max_len];

  for i in 0..max_len {
    // Collect i-th column bytes
    let column: Vec<u8> = cts
        .iter()
        .filter_map(|c| if i < c.len() { Some(c[i]) } else { None })
        .collect();

    if column.is_empty() {
      continue;
    }
    (_, ks[i]) = get_key(&column);
  }
  ks
}

fn main() {

  let LINES = [
    b"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==".to_vec(),
    b"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=".to_vec(),
    b"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==".to_vec(),
    b"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=".to_vec(),
    b"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk".to_vec(),
    b"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==".to_vec(),
    b"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=".to_vec(),
    b"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==".to_vec(),
    b"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=".to_vec(),
    b"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl".to_vec(),
    b"VG8gcGxlYXNlIGEgY29tcGFuaW9u".to_vec(),
    b"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==".to_vec(),
    b"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=".to_vec(),
    b"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==".to_vec(),
    b"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=".to_vec(),
    b"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=".to_vec(),
    b"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==".to_vec(),
    b"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==".to_vec(),
    b"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==".to_vec(),
    b"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==".to_vec(),
    b"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==".to_vec(),
    b"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==".to_vec(),
    b"U2hlIHJvZGUgdG8gaGFycmllcnM/".to_vec(),
    b"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=".to_vec(),
    b"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=".to_vec(),
    b"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=".to_vec(),
    b"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=".to_vec(),
    b"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==".to_vec(),
    b"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==".to_vec(),
    b"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=".to_vec(),
    b"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==".to_vec(),
    b"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu".to_vec(),
    b"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=".to_vec(),
    b"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs".to_vec(),
    b"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=".to_vec(),
    b"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0".to_vec(),
    b"SW4gdGhlIGNhc3VhbCBjb21lZHk7".to_vec(),
    b"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=".to_vec(),
    b"VHJhbnNmb3JtZWQgdXR0ZXJseTo=".to_vec(),
    b"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=".to_vec()
  ];
  let common_len = LINES.iter().map(|c| c.len()).min().unwrap_or(0);
  let key = get_random_block();
  let cipher_txt = LINES.iter()
      .map(|l| from_base64( &l ))
      .map(|plain| {
        let mut buf = plain.to_vec();
        AES_CTR_transform_buffer( &mut buf, &key, 0 );
        buf
      })
      .collect::<Vec<_>>();

  let keystream = recover_keystream( &cipher_txt );
  for (i, cipher) in cipher_txt.iter().enumerate() {
    let mut plain = repeating_xor( cipher, &keystream );
    let mut expected = from_base64( &LINES[i] );
    plain.truncate( common_len );
    expected.truncate( common_len );
    println!("plain = {}", String::from_utf8_lossy( &plain ) );
    println!("expected = {}", String::from_utf8_lossy( &expected ) );
    assert_eq!( plain, expected );
  }
}
