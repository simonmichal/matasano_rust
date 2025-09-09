use itertools::Itertools;
use rand::{distributions::{Alphanumeric, Standard}, Rng};
use aes::AES_BLOCKLEN;
use aes::AES_ctx;
use aes::AES_CBC_encrypt_buffer;
use aes::AES_CBC_decrypt_buffer;
use aes::AES_CTR_transform_buffer;
use utils::{from_base64, pkcs7_padding, pkcs7_padding_valid, pkcs7_padding_len};
use utils::rate_bytes;

fn get_token() -> Vec<u8> {
  let TOKENS : [Vec<u8>; 10] = [
    b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=".to_vec(),
    b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=".to_vec(),
    b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==".to_vec(),
    b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==".to_vec(),
    b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl".to_vec(),
    b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==".to_vec(),
    b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==".to_vec(),
    b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=".to_vec(),
    b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=".to_vec(),
    b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93".to_vec()
  ];
  from_base64( &TOKENS[rand::thread_rng().gen_range(0..10)] )
}

const FIXED_NONCE: u64 = 0;

pub struct CTR_Encryptor {
  key: Vec<u8>
}

impl CTR_Encryptor {
  pub fn new() -> CTR_Encryptor {
    CTR_Encryptor {
      key: rand::thread_rng().sample_iter( &Standard ).take( AES_BLOCKLEN ).collect()
    }
  }

  pub fn encrypt_fixed_nonce( &self, bytes: &[u8] ) -> Vec<u8> {
    let mut buf = bytes.to_vec();
    AES_CTR_transform_buffer( &mut buf, &self.key, FIXED_NONCE );
    buf
  }

  pub fn decrypt_fixed_nonce( &self, bytes: &[u8] ) -> Vec<u8> {
    // CTR is symmetric
    let mut buf = bytes.to_vec();
    AES_CTR_transform_buffer( &mut buf, &self.key, FIXED_NONCE );
    buf
  }
}

fn challenge19_b64_lines() -> Vec<Vec<u8>> {
  vec![
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
    b"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=".to_vec(),
  ]
}

pub fn challenge19_ciphertexts() -> Vec<Vec<u8>> {
  let enc = CTR_Encryptor::new();
  let lines_b64 = challenge19_b64_lines();
  lines_b64.into_iter()
    .map(|l| from_base64( &l ))
    .map(|plain| enc.encrypt_fixed_nonce( &plain ))
    .collect()
}

fn recover_keystream_columnwise( cts: &[Vec<u8>] ) -> Vec<u8> {
  let max_len = cts.iter().map(|v| v.len()).max().unwrap_or(0);
  let mut keystream = vec![0u8; max_len];
  for i in 0 .. max_len {
    let column: Vec<u8> = cts.iter().filter_map(|ct| ct.get(i).copied()).collect();
    if column.is_empty() { continue; }
    let mut best_score = i32::MIN;
    let mut best_k = 0u8;
    for k in 0u8 ..= u8::MAX {
      let candidate_plain: Vec<u8> = column.iter().map(|b| b ^ k).collect();
      let score = rate_bytes( &candidate_plain );
      if score > best_score {
        best_score = score;
        best_k = k;
      }
    }
    keystream[i] = best_k;
  }
  keystream
}

fn decrypt_with_keystream( cts: &[Vec<u8>], ks: &[u8] ) -> Vec<Vec<u8>> {
  cts.iter().map(|ct| ct.iter().enumerate().map(|(i, &c)| c ^ ks[i]).collect()).collect()
}

pub fn challenge19_break() -> Vec<Vec<u8>> {
  let cts = challenge19_ciphertexts();
  let ks = recover_keystream_columnwise( &cts );
  decrypt_with_keystream( &cts, &ks )
}

pub struct Token_Encryptor {
  key: Vec<u8>,
  iv: Vec<u8>,
  token: Vec<u8>
}

impl Token_Encryptor {

  pub fn new() -> Token_Encryptor {
    Token_Encryptor {
      key: rand::thread_rng().sample_iter( &Standard ).take( AES_BLOCKLEN ).collect(),
      iv: rand::thread_rng().sample_iter( &Standard ).take( AES_BLOCKLEN ).collect(),
      token: get_token()
    }
  }

  pub fn get_token_dec( &self ) -> Vec<u8> {
    self.token.clone()
  }

  pub fn get_token( &self ) -> ( Vec<u8>, Vec<u8> ) {
    let mut result = self.token.clone();
    pkcs7_padding( &mut result, AES_BLOCKLEN );
    let mut aes_ctx = AES_ctx::NewWithIv( &self.key, &self.iv );
    AES_CBC_encrypt_buffer( &mut aes_ctx, &mut result );
    let iv = self.iv.clone();
    ( result, iv )
  }

  pub fn decrypt( &self, token: &[u8], iv: &[u8] ) -> Vec<u8> {
    let mut bytes = token.to_vec();
    let mut aes_ctx = AES_ctx::NewWithIv( &self.key, &iv );
    AES_CBC_decrypt_buffer( &mut aes_ctx, &mut bytes );
    bytes
  }

  pub fn padding_valid( &self, token: &[u8], iv: &[u8] ) -> bool {
    let mut bytes = token.to_vec();
    let mut aes_ctx = AES_ctx::NewWithIv( &self.key, &iv );
    AES_CBC_decrypt_buffer( &mut aes_ctx, &mut bytes );
    pkcs7_padding_valid( &bytes )
  }

  fn padding_len( &self, token: &[u8], iv: &[u8] ) -> usize {
    let mut bytes = token.to_vec();
    let mut aes_ctx = AES_ctx::NewWithIv( &self.key, &iv );
    AES_CBC_decrypt_buffer( &mut aes_ctx, &mut bytes );
    pkcs7_padding_len( &bytes )
  }
}

fn test_ith( i: usize, b: u8, token: &[u8], iv: &[u8], oracle: &Token_Encryptor ) -> bool {
  let blkcnt = token.len() / AES_BLOCKLEN;
  let mut token = token.to_vec();
  let mut iv = iv.to_vec();
  // modify i-th byte of the second last block
  if blkcnt == 1 {
    iv[i] ^= b;
  } else {
    let idx = ( blkcnt - 2 ) * AES_BLOCKLEN;
    token[idx + i] ^= b;
  }
  oracle.padding_valid( &token, &iv )
}

pub fn get_padding_len( token: &[u8], iv: &[u8], oracle: &Token_Encryptor ) -> usize {
  for i in 0 .. AES_BLOCKLEN {
    let fst = test_ith( i, b'\xff', token, iv, oracle );
    let snd = test_ith( i, b'\x11', token, iv, oracle );
    if !fst || !snd { return AES_BLOCKLEN - i; }
  }
  0
}

pub fn find_byte( iv: &mut [u8], block: &[u8], oracle: &Token_Encryptor, padlen: usize ) -> u8 {
  let padchar = ( padlen + 1 ) as u8;
  if padlen > 0 {
    let b = ( padlen as u8 ) ^ padchar;
    iv.iter_mut().rev().take( padlen ).for_each( |byte| *byte ^= b );
  }
  let mut result = 0u8;
  let mut found = false;
  for b in 0u8 ..= u8::MAX {
    let mut iv = iv.to_vec();
    iv[AES_BLOCKLEN - padlen - 1] ^= b;
    if oracle.padding_valid( &block, &iv ) {
      result = b;
      found = true;
      break;
    }
  }
  assert!( found ); // --
  iv[AES_BLOCKLEN - padlen - 1] ^= result;
  result ^ padchar
}

pub fn get_block_dec( iv: &[u8], block: &[u8], oracle: &Token_Encryptor, mut padlen: usize ) -> Vec<u8> {
  let mut result = Vec::new();
  let mut iv = iv.to_vec();
  for _ in 0 .. AES_BLOCKLEN - padlen {
    let byte = find_byte( &mut iv, &block, &oracle, padlen );
    padlen += 1;
    result.push( byte );
  }
  result.reverse();
  result
}

#[cfg(test)]
mod test {

  use crate::set3::get_padding_len;
  use super::Token_Encryptor;
  use super::get_block_dec;
  use aes::AES_BLOCKLEN;
  use aes::AES_CTR_transform_buffer;
  use utils::from_base64;

  #[test]
  fn challange17a() {
    let oracle = Token_Encryptor::new();
    let ( mut token, mut iv ) = oracle.get_token();
    assert!( oracle.padding_valid( &token, &iv ) );

    let len = get_padding_len( &token, &iv, &oracle );
    let expected = oracle.padding_len( &token, &iv );
    assert_eq!( len, expected );
  }

  #[test]
  fn challange17b() {
    let oracle = Token_Encryptor::new();
    let ( token, iv ) = oracle.get_token();  
    let blks = token.chunks( AES_BLOCKLEN ).collect::<Vec<_>>();
    let blkcnt = blks.len();
    let mut ivs = vec![iv];
    ivs.append( &mut blks.iter().take( blkcnt - 1 ).map( |chunk| chunk.to_vec() ).collect::<Vec<_>>() );

    let mut result = Vec::new();
    for i in 0 .. blkcnt - 1 {
      result.append( &mut get_block_dec( &ivs[i], &blks[i], &oracle, 0 ) );
    }
    let padlen = get_padding_len( &blks[blkcnt - 1], &ivs[blkcnt - 1], &oracle );
    result.append( &mut get_block_dec( &ivs[blkcnt - 1], &blks[blkcnt - 1], &oracle, padlen ) );

    let expected = oracle.get_token_dec();
    assert_eq!( result, expected );
  }

  #[test]
  fn challange18() {
    let mut bytes = from_base64( b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==" );
    let key = b"YELLOW SUBMARINE".to_vec();
    let nonce = 0u64;
    AES_CTR_transform_buffer( &mut bytes, &key, 0 );
    let expected = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ";
    assert_eq!( bytes, expected );
  }
}