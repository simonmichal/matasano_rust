use std::collections::HashMap;

use rand::{distributions::{Alphanumeric, Standard}, Rng};
use aes::{AES_ECB_decrypt_buffer, AES_ctx};
use aes::AES_BLOCKLEN;
use aes::AES_ECB_encrypt_buffer;
use aes::AES_CBC_encrypt_buffer;
use utils::{contains_duplicate, from_base64};
use itertools::Itertools;

fn pkcs7_padding( block: &mut Vec<u8>, size: usize ) {
  if block.len() % size == 0 { return; }
  let val: u8 = ( size - block.len() % size ) as u8;
  for _ in 0 .. val {
    block.push( val );
  }
}

fn get_random_buff() -> Vec<u8> {
  let len = rand::thread_rng().gen_range( 5..11 );
  rand::thread_rng().sample_iter( &Standard ).take( len ).collect()
}

fn get_random_block() -> Vec<u8> {
  rand::thread_rng().sample_iter( &Standard ).take( AES_BLOCKLEN ).collect()
}

pub fn random_encrypt( bytes: &[u8], ecb: &mut bool ) -> Vec<u8> {
  let mut result = get_random_buff(); // prefix
  result.extend_from_slice( bytes );
  result.append( &mut get_random_buff() ); // sufix
  pkcs7_padding( &mut result, AES_BLOCKLEN );
  let key = get_random_block();
  if rand::random::<bool>() {
    let mut aes_ctx = AES_ctx::New( &key );
    AES_ECB_encrypt_buffer( &mut aes_ctx, &mut result );
    *ecb = true;
  } else {
    let iv = get_random_block();
    let mut aes_ctx = AES_ctx::NewWithIv( &key, &iv );
    AES_CBC_encrypt_buffer( &mut aes_ctx, &mut result );
    *ecb = false;
  }
  result
}

pub trait Oracle {
  fn encrypt( &self, bytes: &[u8] ) -> Vec<u8>;
  fn decrypt( &self, bytes: &[u8] ) -> Vec<u8>;
}

pub struct AES_ECB_Encryptor {
  key:    Vec<u8>,
  sufix:  Vec<u8>
}

impl AES_ECB_Encryptor {
  pub fn new() -> AES_ECB_Encryptor {
    AES_ECB_Encryptor{
      key: rand::thread_rng().sample_iter( &Standard ).take( AES_BLOCKLEN ).collect(),
      sufix: from_base64( "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".as_bytes() )
    }
  }
}

impl Oracle for AES_ECB_Encryptor {
  fn encrypt( &self, bytes: &[u8] ) -> Vec<u8> {
    let mut result = Vec::with_capacity( bytes.len() + self.sufix.len() );
    result.extend_from_slice( bytes );
    result.extend_from_slice( &self.sufix );
    pkcs7_padding( &mut result, AES_BLOCKLEN );
    let mut aes_ctx = AES_ctx::New( &self.key );
    AES_ECB_encrypt_buffer( &mut aes_ctx, &mut result );
    result
  }

  fn decrypt( &self, bytes: &[u8] ) -> Vec<u8> {
    let mut result = bytes.to_vec();
    let mut aes_ctx = AES_ctx::New( &self.key );
    AES_ECB_decrypt_buffer( &mut aes_ctx, &mut result );
    result
  }
}

pub fn get_block_size( oracle: &AES_ECB_Encryptor ) -> usize {
  let mut buffer = Vec::new();
  let mut encrypted = oracle.encrypt( &buffer );
  let mut initlen = encrypted.len();
  let mut enclen  = encrypted.len();
  // find 1st block boundary
  while enclen == initlen {
    buffer.push( 0 );
    encrypted = oracle.encrypt( &buffer );
    enclen = encrypted.len();
  }
  initlen = enclen;
   // we crossed the block boundary so we have already 1 byte in the new block
   // and we will be looping until we have 1 byte in the subsequent block
  while enclen == initlen {
    buffer.push( 0 );
    encrypted = oracle.encrypt( &buffer );
    enclen = encrypted.len();
  }
  enclen - initlen
}

pub fn decrypt_sufix( oracle: &AES_ECB_Encryptor, block_size: usize ) -> Vec<u8> {

  let sufix = oracle.encrypt( &Vec::new() );
  let blkcnt = sufix.len() / block_size;

  let mut alphanum = (b'a' .. b'z').collect_vec();
  alphanum.extend( ( b'A' .. b'Z' ).into_iter() );
  alphanum.extend( ( b'0' .. b'9' ).into_iter() );
  alphanum.append( &mut vec![b'.', b',', b'\'', b'!', b'"', b'?', b'(', b')', b':', b';', b' ', b'\t', b'\n', b'-'] );

  let mut result = Vec::new();
  for i in 1 ..= blkcnt {
    // one block
    for j in 1 ..= block_size {
      // one byte
      let mut incomplete = vec![b'A'; block_size - j];
      let mut fstblks = oracle.encrypt( &incomplete );
      fstblks.resize( block_size * i, 0 );
      let full = &mut incomplete;
      full.extend( result.iter() );
      for byte in alphanum.iter() {
        full.push( *byte );
        let mut encrypted = oracle.encrypt( &full );
        encrypted.resize( block_size * i, 0 );
        if encrypted == fstblks {
          result.push( *byte );
          break;
        }
        full.pop();
      }
    }
  }
  result
}

pub fn parse( s: &str ) -> Vec<(String, String)> {
  let pairs = s.split( '&' );
  let mut result = Vec::new();
  for pair in pairs {
    if let Some( idx ) = pair.find( '=' ) {
      let key = pair[0 .. idx].to_string();
      let val = pair[idx + 1 ..].to_string();
      result.push( ( key, val ) );
    }
  }
  result
}

pub fn encode( profile: &Vec<(String, String)> ) -> String {
  let mut result = String::new();
  for pair in profile.iter() {
    let key = pair.0.chars().filter( |&c|( c != '&' && c != '=' ) ).collect::<String>();
    let val = pair.1.chars().filter( |&c|( c != '&' && c != '=' ) ).collect::<String>();
    if !result.is_empty() { result.push( '&' ); }
    result.push_str( &key );
    result.push( '=' );
    result.push_str( &val );
  }
  result
}

pub struct Profile_Encryptor {
  key: Vec<u8>,
  sufix: Vec<(String, String)>
}

impl Profile_Encryptor {

  pub fn new() -> Profile_Encryptor {
    Profile_Encryptor {
      key: rand::thread_rng().sample_iter( &Standard ).take( AES_BLOCKLEN ).collect(),
      sufix: vec![( "uid".to_owned(), "10".to_owned() ), ( "role".to_owned(), "user".to_owned() )]
    }
  }

  pub fn profile_for( &self, email: &str ) -> Vec<u8> {
    let mut profile = vec![( "email".to_owned(), email.to_string() )];
    profile.append( &mut self.sufix.clone() );
    let encoded = encode( &profile );
    let mut result = encoded.as_bytes().to_vec();
    pkcs7_padding( &mut result, AES_BLOCKLEN );
    let mut aes_ctx = AES_ctx::New( &self.key );
    AES_ECB_encrypt_buffer( &mut aes_ctx, &mut result );
    result
  }
}

impl Oracle for Profile_Encryptor {
  fn encrypt( &self, bytes: &[u8] ) -> Vec<u8> {
    self.profile_for( &String::from_utf8_lossy( bytes ) )
  }

  fn decrypt( &self, bytes: &[u8] ) -> Vec<u8> {
    let mut result = bytes.to_vec();
    let mut aes_ctx = AES_ctx::New( &self.key );
    AES_ECB_decrypt_buffer( &mut aes_ctx, &mut result );
    result
  }
}

pub fn get_prefix_len( oracle: &Profile_Encryptor ) -> usize {
  let tripple_block = ['A'; AES_BLOCKLEN * 3];
  let encrypted = oracle.profile_for( &tripple_block.iter().collect::<String>() );
  let mut result = 0;
  if let Some( blkcnt ) = encrypted.chunks( AES_BLOCKLEN ).tuple_windows::<(_, _)>().position(|tpl|tpl.0 == tpl.1) {
    let len = blkcnt * AES_BLOCKLEN;
    let sufix_aligned = &encrypted[0 .. len];
    let mut bytecnt = 0;
    loop {
      let chars = vec!['A'; bytecnt];
      let enc = oracle.profile_for( &chars.iter().collect::<String>() );
      if sufix_aligned == &enc[0 .. sufix_aligned.len() ] { break; }
      bytecnt += 1;
    }
    result = len - bytecnt;
  }
  result
}

pub fn get_encrypted_block( oracle: &Profile_Encryptor, value: &str ) -> Vec<u8> {
  let prefix_len = get_prefix_len( oracle );
  let aligment_len = AES_BLOCKLEN - ( prefix_len % AES_BLOCKLEN );
  let mut input = vec![b'A'; aligment_len]; // align the prefix with block size
  let mut value = value.as_bytes().to_vec();
  pkcs7_padding( &mut value, AES_BLOCKLEN );
  input.append( &mut value );
  input.extend( value.iter() );
  let encrypted = oracle.encrypt( &input );
  encrypted[ prefix_len + aligment_len .. prefix_len + aligment_len + AES_BLOCKLEN].to_vec()
}

pub fn get_padcnt( oracle: &dyn Oracle, bytes: &[u8] ) -> usize {
  let mut buffer = bytes.to_vec();
  let mut encrypted = oracle.encrypt( &buffer );
  let initlen = encrypted.len();
  let mut enclen  = encrypted.len();
  // find 1st block boundary
  while enclen == initlen {
    buffer.push( 0 );
    encrypted = oracle.encrypt( &buffer );
    enclen = encrypted.len();
  }
  buffer.len() - bytes.len() - 1
}

#[cfg(test)]
mod test {
    use std::fs;
    use super::pkcs7_padding;
    use utils::BASE64CHARS;
    use std::collections::HashSet;
    use utils::from_base64;
    use aes::AES_CBC_decrypt_buffer;
    use aes::AES_ctx;
    use super::random_encrypt;
    use aes::AES_BLOCKLEN;
    use super::AES_ECB_Encryptor;
    use super::get_block_size;
    use super::decrypt_sufix;
    use super::parse;
    use super::encode;
    use utils::contains_duplicate;
    use super::get_prefix_len;
    use super::Profile_Encryptor;
    use super::Oracle;
    use super::get_encrypted_block;
    use super::get_padcnt;

  #[test]
  fn challange9() {
    let mut block = "YELLOW SUBMARINE".as_bytes().to_vec();
    pkcs7_padding( &mut block, 20 );
    let expected = vec![b'Y', b'E', b'L', b'L', b'O', b'W', b' ', b'S', b'U', b'B', b'M', b'A', b'R', b'I', b'N', b'E', 4u8, 4u8, 4u8, 4u8];
    assert_eq!( block, expected );
  }

  #[test]
  fn challange10() {
    if let Ok( txt ) = fs::read_to_string( "10.txt" ) {
      let mut chars: HashSet<u8> = HashSet::from_iter( BASE64CHARS.to_vec() );
      chars.insert( b'=' );
      let txt = txt.as_bytes().into_iter().filter( |c| chars.contains(c) ).map(|c|*c).collect::<Vec<u8>>();
      let mut bytes = from_base64( &txt );
      let key = "YELLOW SUBMARINE".as_bytes();
      let mut aes_ctx = AES_ctx::New( key );
      let mut buf = &mut bytes[0 .. 16];
      AES_CBC_decrypt_buffer( &mut aes_ctx, &mut bytes );
      let fstline = "I'm back and I'm ringin' the bell".to_owned();
      let txt = String::from_utf8_lossy( &bytes );
      assert_eq!( txt[..fstline.len()], fstline );
    }
  }

  #[test]
  fn challange11() {
    let plain = vec![0u8; 3 * AES_BLOCKLEN];
    let mut expected = false;
    let encrypted = random_encrypt( &plain, &mut expected );
    let ecb = encrypted[AES_BLOCKLEN .. 2 * AES_BLOCKLEN] == encrypted[2 * AES_BLOCKLEN .. 3 * AES_BLOCKLEN];
    assert_eq!( ecb, expected );
    assert_eq!( contains_duplicate( &encrypted, AES_BLOCKLEN ), ecb );
  }

  #[test]
  fn challange12() {
    let oracle = AES_ECB_Encryptor::new();
    let block_size = get_block_size( &oracle );
    assert_eq!( block_size, AES_BLOCKLEN );
    let encrypted = oracle.encrypt( &[0; 3 * AES_BLOCKLEN] );
    let is_ecb = contains_duplicate( &encrypted, block_size );
    assert!( is_ecb );
    let decrypted = decrypt_sufix( &oracle, block_size );
    let expected = from_base64( "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".as_bytes() );
    assert_eq!( decrypted, expected );
  }

  #[test]
  fn challange13a() {
    let cookie = "foo=bar&baz=qux&zap=zazzle".to_owned();
    let mut parsed = parse( &cookie );
    assert_eq!( parsed[0], ( "foo".to_owned(), "bar".to_owned() ) );
    assert_eq!( parsed[1], ( "baz".to_owned(), "qux".to_owned() ) );
    assert_eq!( parsed[2], ( "zap".to_owned(), "zazzle".to_owned() ) );
    parsed.push( ( "email".to_owned(), "foo@bar.com&role=admin".to_owned() ) );
    let encoded = encode( &parsed );
    let expected = "foo=bar&baz=qux&zap=zazzle&email=foo@bar.comroleadmin".to_owned();
    assert_eq!( encoded, expected );
  }

  #[test]
  fn challange13() {

    let oracle = Profile_Encryptor::new();
    let prefix_len = get_prefix_len( &oracle );
    assert_eq!( prefix_len, 6 );
  
    let adminblk = get_encrypted_block( &oracle, "admin" );
  
    let plain = oracle.decrypt( &adminblk );
    let expected = vec![b'a', b'd', b'm', b'i', b'n', 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11];
    assert_eq!( plain, expected );
  
    let mut email = "m@gmail.com".as_bytes().to_vec();
    let mut padcnt = get_padcnt( &oracle, &email );
    assert_eq!( padcnt, 14 );

    let usrpadcnt = AES_BLOCKLEN - "user".len();
    let mut email_prefix = Vec::new();
    while padcnt != usrpadcnt {
      email_prefix.push( b'm' );
      padcnt = if padcnt == 0 { AES_BLOCKLEN - 1 } else { padcnt - 1 };
    }
    email_prefix.append( &mut email );
    email = email_prefix;
    
    let mut encrypted = oracle.encrypt( &email );
    let plain = oracle.decrypt( &encrypted );
    let mut expected = "email=mmm@gmail.com&uid=10&role=user".as_bytes().to_vec();
    expected.append( &mut vec![12u8; 12] );
    assert_eq!( plain, expected );

    let enclen = encrypted.len();
    encrypted[enclen - AES_BLOCKLEN .. ].copy_from_slice( &adminblk ); // replace last block
    let plain = oracle.decrypt( &encrypted );
    let mut expected = "email=mmm@gmail.com&uid=10&role=admin".as_bytes().to_vec();
    expected.append( &mut vec![11u8; 11] );
    assert_eq!( plain, expected );
  }

}