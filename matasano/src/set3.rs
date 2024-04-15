use itertools::Itertools;
use rand::{distributions::{Alphanumeric, Standard}, Rng};
use aes::AES_BLOCKLEN;
use aes::AES_ctx;
use aes::AES_CBC_encrypt_buffer;
use aes::AES_CBC_decrypt_buffer;
use utils::{from_base64, pkcs7_padding, pkcs7_padding_valid, pkcs7_padding_len};

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
}