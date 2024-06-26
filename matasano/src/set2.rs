use std::collections::HashMap;

use rand::{distributions::{Alphanumeric, Standard}, Rng};
use aes::AES_ctx;
use aes::AES_BLOCKLEN;
use aes::AES_ECB_encrypt_buffer;
use aes::AES_ECB_decrypt_buffer;
use aes::AES_CBC_encrypt_buffer;
use aes::AES_CBC_decrypt_buffer;
use utils::{contains_duplicate, from_base64, pkcs7_padding, pkcs7_padding_valid, pkcs7_padding_strip};
use itertools::Itertools;
use urlencoding::encode as urlencode;

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
  prefix: Vec<u8>,
  key:    Vec<u8>,
  sufix:  Vec<u8>
}

impl AES_ECB_Encryptor {
  pub fn new() -> AES_ECB_Encryptor {
    AES_ECB_Encryptor{
      prefix: Vec::new(),
      key: rand::thread_rng().sample_iter( &Standard ).take( AES_BLOCKLEN ).collect(),
      sufix: from_base64( "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".as_bytes() )
    }
  }

  pub fn with_prefix() -> AES_ECB_Encryptor {
    let prefix_len = rand::thread_rng().gen_range( 5..35 );
    AES_ECB_Encryptor{
      prefix: rand::thread_rng().sample_iter( &Standard ).take( prefix_len ).collect(),
      key: rand::thread_rng().sample_iter( &Standard ).take( AES_BLOCKLEN ).collect(),
      sufix: from_base64( "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".as_bytes() )
    }
  }
}

impl Oracle for AES_ECB_Encryptor {
  fn encrypt( &self, bytes: &[u8] ) -> Vec<u8> {
    let mut result = Vec::with_capacity( self.prefix.len() + bytes.len() + self.sufix.len() );
    result.extend_from_slice( &self.prefix );
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

pub fn get_prefix_len( oracle: &dyn Oracle, block_size: usize ) -> usize {
  let tripple_block = vec![b'A'; block_size * 3];
  let encrypted = oracle.encrypt( &tripple_block );
  let mut result = 0;
  if let Some( blkcnt ) = encrypted.chunks( block_size ).tuple_windows::<(_, _)>().position(|tpl|tpl.0 == tpl.1) {
    let len = blkcnt * block_size;
    let sufix_aligned = &encrypted[0 .. len];
    let mut bytecnt = 0;
    loop {
      let chars = vec![b'A'; bytecnt];
      let enc = oracle.encrypt( &chars );
      if sufix_aligned == &enc[0 .. sufix_aligned.len() ] { break; }
      bytecnt += 1;
    }
    result = len - bytecnt;
  }
  result
}

pub fn decrypt_sufix( oracle: &dyn Oracle, block_size: usize ) -> Vec<u8> {

  let mut prefix_len = get_prefix_len( oracle, block_size );
  let prefix_aligment = vec![b'B'; block_size - ( prefix_len % block_size )];
  prefix_len += prefix_aligment.len();

  let encrypted = oracle.encrypt( &prefix_aligment );
  let blkcnt = ( encrypted.len() - prefix_len ) / block_size;

  let mut alphanum = (b'a' .. b'z').collect_vec();
  alphanum.extend( ( b'A' .. b'Z' ).into_iter() );
  alphanum.extend( ( b'0' .. b'9' ).into_iter() );
  alphanum.append( &mut vec![b'.', b',', b'\'', b'!', b'"', b'?', b'(', b')', b':', b';', b' ', b'\t', b'\n', b'-'] );

  let mut result = Vec::new();
  for i in 1 ..= blkcnt {
    // one block
    for j in 1 ..= block_size {
      // one byte
      let mut incomplete = prefix_aligment.clone();
      incomplete.extend_from_slice( &vec![b'A'; block_size - j] );
      let mut encrypted = oracle.encrypt( &incomplete );
      let fstblks = &mut encrypted[prefix_len .. prefix_len + block_size * i];
      let full = &mut incomplete;
      full.extend( result.iter() );
      for byte in alphanum.iter() {
        full.push( *byte );
        let encrypted = oracle.encrypt( &full );
        let blks = &encrypted[prefix_len .. prefix_len + block_size * i];
        if blks == fstblks {
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

pub fn get_encrypted_block( oracle: &Profile_Encryptor, value: &str ) -> Vec<u8> {
  let prefix_len = get_prefix_len( oracle, AES_BLOCKLEN );
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
  buffer.len() - bytes.len()
}

pub struct AES_CBC_Encryptor {
  prefix: Vec<u8>,
  key:    Vec<u8>,
  iv:     Vec<u8>,
  sufix:  Vec<u8>
}

impl AES_CBC_Encryptor {
  pub fn new() -> AES_CBC_Encryptor {
    AES_CBC_Encryptor{
      prefix: b"comment1=cooking%20MCs;userdata=".to_vec(),
      key: rand::thread_rng().sample_iter( &Standard ).take( AES_BLOCKLEN ).collect(),
      iv: rand::thread_rng().sample_iter( &Standard ).take( AES_BLOCKLEN ).collect(),
      sufix: b";comment2=%20like%20a%20pound%20of%20bacon".to_vec()
    }
  }

  pub fn encrypt_userdata( &self, data: &str ) -> Vec<u8> {
    let encoded = urlencode( data ).into_owned();
    self.encrypt( encoded.as_bytes() )
  }

  pub fn is_admin( &self, encrypted: &[u8] ) -> bool {
    let decrypted = self.decrypt( encrypted );
    let admstr = b";admin=true;".to_vec();
    let pos = decrypted.windows( admstr.len() ).position(|win| win == admstr );
    pos.is_some()
  }
}

impl Oracle for AES_CBC_Encryptor {
  fn encrypt( &self, bytes: &[u8] ) -> Vec<u8> {
    let mut result = Vec::with_capacity( self.prefix.len() + bytes.len() + self.sufix.len() );
    result.extend_from_slice( &self.prefix );
    result.extend_from_slice( bytes );
    result.extend_from_slice( &self.sufix );
    pkcs7_padding( &mut result, AES_BLOCKLEN );
    let mut aes_ctx = AES_ctx::NewWithIv( &self.key, &self.iv );
    AES_CBC_encrypt_buffer( &mut aes_ctx, &mut result );
    result
  }

  fn decrypt( &self, bytes: &[u8] ) -> Vec<u8> {
    let mut result = bytes.to_vec();
    let mut aes_ctx = AES_ctx::NewWithIv( &self.key, &self.iv );
    AES_CBC_decrypt_buffer( &mut aes_ctx, &mut result );
    result
  }
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
    use super::pkcs7_padding_valid;
    use super::pkcs7_padding_strip;
    use super::AES_CBC_Encryptor;

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
    let prefix_len = get_prefix_len( &oracle, AES_BLOCKLEN );
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

  #[test]
  fn challange14() {
    let oracle = AES_ECB_Encryptor::with_prefix();
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
  fn challange15() {
    let mut valid = "ICE ICE BABY\x04\x04\x04\x04".as_bytes().to_vec();
    assert!( pkcs7_padding_valid( &valid ) );
    pkcs7_padding_strip( &mut valid );
    let expected = "ICE ICE BABY".as_bytes().to_vec();
    assert_eq!( valid, expected );

    let invalid = "ICE ICE BABY\x05\x05\x05\x05".as_bytes().to_vec();
    assert!( !pkcs7_padding_valid( &invalid ) );
    let invalid = "ICE ICE BABY\x01\x02\x03\x04".as_bytes().to_vec();
    assert!( !pkcs7_padding_valid( &invalid ) );
  }

  #[test]
  fn challange16() {
    let oracle = AES_CBC_Encryptor::new();
    let encrypted = oracle.encrypt( b"some random text" );
    let decrypted = oracle.decrypt( &encrypted );
    let mut expected = b"comment1=cooking%20MCs;userdata=some random text;comment2=%20like%20a%20pound%20of%20bacon".to_vec();
    pkcs7_padding( &mut expected, AES_BLOCKLEN );
    assert_eq!( decrypted, expected );

    let encrypted = oracle.encrypt_userdata( "some random text" );
    let decrypted = oracle.decrypt( &encrypted );
    let mut expected = b"comment1=cooking%20MCs;userdata=some%20random%20text;comment2=%20like%20a%20pound%20of%20bacon".to_vec();
    pkcs7_padding( &mut expected, AES_BLOCKLEN );
    assert_eq!( decrypted, expected );

    let encrypted = oracle.encrypt_userdata( "completediameter;admin=true;" );
    assert!( !oracle.is_admin( &encrypted ) );

    let mut encrypted = oracle.encrypt_userdata( "completediameterxxxxxxxxxxxx" );
    let bytes = b"xxxxxxxxxxxx".to_vec();
    let admin: Vec<u8> = b";admin=true;".to_vec();
    let flip = bytes.iter().zip( admin.iter() ).map(|(lhs, rhs)| *lhs ^ *rhs ).collect::<Vec<_>>();
    let prevblk = &mut encrypted[AES_BLOCKLEN * 2 .. AES_BLOCKLEN * 2 + flip.len()];
    prevblk.iter_mut().zip( flip.iter() ).for_each(|(lhs, rhs)| *lhs ^= *rhs );
    assert!( oracle.is_admin( &encrypted ) )
  }

}