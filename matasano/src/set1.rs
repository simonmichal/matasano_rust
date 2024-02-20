pub mod aes;

use std::collections::HashMap;
use std::collections::HashSet;
use hex::{self, ToHex};

pub static BASE64CHARS: [u8; 64] = [b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H',
                                b'I', b'J', b'K', b'L', b'M', b'N', b'O', b'P',
                                b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X',
                                b'Y', b'Z', b'a', b'b', b'c', b'd', b'e', b'f',
                                b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n',
                                b'o', b'p', b'q', b'r', b's', b't', b'u', b'v',
                                b'w', b'x', b'y', b'z', b'0', b'1', b'2', b'3',
                                b'4', b'5', b'6', b'7', b'8', b'9', b'+', b'/' ];

fn from_hex( hex: u8 ) -> Result<u8, String> {
  match hex {
    b'0' ..= b'9' => Ok( hex - b'0' ),
    b'a' ..= b'f' => Ok( hex - b'a' + 10u8 ),
    _ => Err( "Parsing error!".to_owned() )
  }
}

fn from_2hex( hbits: u8, lbits: u8 ) -> Result<u8, String> {
  let mut result: u8 = 0u8;
  if let Ok( aux ) = from_hex( hbits ) {
    result = aux;
    result = result << 4;
  }
  else { return Err( "Parsing error!".to_owned() ); }
  if let Ok( aux ) = from_hex( lbits ) {
    result = result | aux;
  }
  Ok( result )
}

fn bits4_to_hex( mut bits: u8 ) -> u8 {
  bits = bits & 0x0fu8;
  match bits {
    0u8 ..= 9u8 => bits + b'0' ,
    10u8 ..= 15u8 => bits - 10u8 + b'a',
    _ => panic!()
  }
}

fn byte_to_hex( bits: &u8 ) -> [u8; 2] {
  let mut bits = *bits;
  let mut result: [u8; 2] = [0u8, 0u8];
  result[1] = bits4_to_hex( bits );
  bits = bits >> 4;
  result[0] = bits4_to_hex( bits );
  result
}

fn to_hex( bytes: &[u8] ) -> Vec<u8> {
  bytes.iter().flat_map( byte_to_hex ).collect()
}

fn sextet2base64( sextet: &[u8] ) -> Result<Vec<u8>, String> {
  if sextet.len() < 6 {
    return Err( "Not enough characters".to_owned() );
  }
  if let ( Ok(v1), Ok(v2), Ok(v3) ) = ( from_2hex( sextet[0], sextet[1] ), 
                                                    from_2hex( sextet[2], sextet[3] ),
                                                    from_2hex( sextet[4], sextet[5] ) ) {
    let mut bits: u32 = v1 as u32;
    bits = ( bits << 8 ) | v2 as u32; 
    bits = ( bits << 8 ) | v3 as u32;

    let mut result = Vec::new();
    // 1st char
    let mut idx: usize = ( bits & 0x3f ) as usize;
    result.push( BASE64CHARS[idx] );
    // 2nd char
    bits = bits >> 6;
    idx = ( bits & 0x3f ) as usize;
    result.push( BASE64CHARS[idx] );
    // 3rd char
    bits = bits >> 6;
    idx = ( bits & 0x3f ) as usize;
    result.push( BASE64CHARS[idx] );
    // 4th char
    bits = bits >> 6;
    idx = ( bits & 0x3f ) as usize;
    result.push( BASE64CHARS[idx] );

    Ok( result.iter().map(|b|*b).rev().collect() )
  }
  else {
    Err( "Parsing error".to_owned() )
  }
}

pub fn hexstr2base64( hexstr: &[u8] ) -> Result<Vec<u8>, String> {
  let mut result = Vec::new();
  for i in (0 .. hexstr.len() ).step_by( 6 ) {

    if let Ok( mut b64str ) = sextet2base64(&hexstr[i .. ] ) {
      result.append( &mut b64str );
    }
    else {
      return Err( "Failed".to_owned() );
    }
  }
  Ok( result )
}

pub fn xor_bytes( lhs: &[u8], rhs: &[u8] ) -> Vec<u8> {
  lhs.iter().zip( rhs ).flat_map( |( lhs, rhs )| byte_to_hex( &( *lhs ^ rhs ) ) ).collect()
}

pub fn xor_hexstr( lhs: &[u8], rhs: &[u8] ) -> Result<Vec<u8>, String> {
  if lhs.len() != rhs.len() {
    return Err( "Length mismatch!".to_owned() );
  }

  if let ( Ok( lhs ), Ok( rhs ) ) = ( hex::decode( lhs ), hex::decode( rhs ) ) {
    Ok( xor_bytes( &lhs, &rhs ) )
  }
  else {
    Err( "Parsing error".to_owned() )
  }
}

pub fn rate_char( c : &u8 ) -> i32 {
  if c < &32u8 || c >= &127u8 {
    return -1000;
  }
  let c = c.to_ascii_uppercase() as char;
  if c.is_whitespace() {
    return 100;
  }
  if c.is_ascii_punctuation() {
    return -100;
  }
  match c {
    'E' => 195,
    'T' => 190,
    'A' => 180,
    'O' => 170,
    'I' => 160,
    'N' => 150,
    'S' => 140,
    'H' => 130,
    'R' => 125,
    'D' => 120,
    'L' => 115,
    'U' => 110,
    _ => 100
  }
}

pub fn rate_bytes( bytes: &[u8] ) -> i32 {
  bytes.iter().fold( 0, |acc, c| acc + rate_char( c ) )
}

pub fn xor( bytes: &[u8], key: u8 ) -> Vec<u8> {
  bytes.iter().map(|c| c ^ key ).collect()
}

pub fn get_key( bytes: &[u8] ) -> ( i32, u8 ) {

  let mut result = ( i32::MIN, 0u8 );
  for key in 0u8 .. 255 {
    let decrypted = xor( bytes, key );
    let score = rate_bytes( &decrypted );
    if score > result.0  {
      result = ( score, key );
    }
  }
  result
}

pub fn decrypt_hexstr( hexstr: &[u8] ) -> (Vec<u8>, i32) {
  if let Ok( bytes ) = hex::decode( hexstr ) {
    let ( score, key ) = get_key( &bytes );
    ( xor( &bytes, key ), score )
  } else {
    ( Vec::<u8>::new(), i32::MIN )
  }
}

pub fn  repeating_xor( bytes: &[u8], key: &[u8] ) -> Vec<u8> {
  bytes.iter().zip( key.iter().cycle() ).map( |( lhs, rhs )| *lhs ^ *rhs ).collect()
}

pub fn repeating_xor_hex( bytes: &[u8], key: &[u8] ) -> Vec<u8> {
  bytes.iter().zip( key.iter().cycle() ).
      flat_map( |( lhs, rhs )| byte_to_hex( &(*lhs ^ *rhs ) ) ).collect()
}

pub fn count_diff_bits( lhs: &u8, rhs: &u8 ) -> u8 {
  let mask = 0x01;
  let nor = lhs ^ rhs;
  ( 0 .. 8 ).into_iter().map(|shift| ( nor >> shift ) & mask ).sum()
}

pub fn hamming_distance( lhs: &[u8], rhs: &[u8] ) -> u32 {
  lhs.iter().zip( rhs.iter() ).map( |( lhs, rhs )| count_diff_bits( lhs, rhs ) as u32 ).sum()
}

pub fn rate_keysize( bytes: &[u8], size: usize ) -> f64 {

  let blocks = vec![&bytes[0 .. size], &bytes[size .. 2 * size],
                                &bytes[2 * size .. 3 * size], &bytes[3 * size .. 4 * size]];
  let mut sum = 0u32;
  let mut count = 0u32;
  for i in 0 .. 4 {
    for j in i + 1 .. 4 {
      sum += hamming_distance( blocks[i], blocks[j] );
      count += 1;
    }
  }
  sum as f64 / size as f64 / count as f64
}

pub fn get_key_sizes( bytes: &[u8] ) -> Vec<(f64, usize)> {
  ( 2 .. 41 ).into_iter().map(|i|( rate_keysize( bytes, i ), i ) ).collect()
}

pub fn quartet2bytes( quartet: &[u8] ) -> Vec<u8> {
  let to_bits: HashMap<u8, u32> = BASE64CHARS.iter().enumerate().map( |(i, c)|(*c, i as u32) ).collect::<HashMap<_, _>>();
  let mut cnt = 3;
  // 1st character
  let mut bits = to_bits[&quartet[0]];
  // 2nd character
  let v = to_bits[&quartet[1]];
  bits = bits << 6;
  bits = bits | v;
  // 3rd character
  if quartet[2] == b'=' { 
    bits = bits >> 2;
    cnt -= 1;
  }
  else {
    let v = to_bits[&quartet[2]];
    bits =  bits << 6;
    bits = bits | v;
  }
  // 4th character
  if quartet[3] == b'=' {
    bits = bits >> 2;
    cnt -= 1;
  }
  else {
    let v = to_bits[&quartet[3]];
    bits = bits << 6;
    bits = bits | v;
  }
  let mut bytes = vec![0, 0, 0];
  // convert into 3 bytes
  if cnt == 3 {
    bytes[2] = ( bits & 0xff ) as u8;
    bits = bits >> 8;
    cnt -= 1;
  }
  if cnt == 2 {
    bytes[1] = ( bits & 0xff ) as u8;
    bits = bits >> 8;
    cnt -= 1;
  }
  bytes[0] = bits as u8;
  bytes
}

pub fn from_base64( txt: &[u8] ) -> Vec<u8> { // TODO implement padding (=)
  let mut result = Vec::new();
  for i in ( 0 .. txt.len() ).step_by( 4 ) {
    let mut bytes = quartet2bytes( &txt[i ..] );
    result.append( &mut bytes );
  }
  result
}

pub fn base642hex( txt: &[u8] ) -> Vec<u8> {
  let mut result= Vec::new();
  for i in ( 0 .. txt.len() ).step_by( 4 ) {
    let mut bytes = quartet2bytes( &txt[i ..] );
    result.append( &mut to_hex(&mut bytes) );
  }
  result
}

pub fn break_repeating_xor_key( bytes: &[u8], nkeys: usize ) -> Vec<Vec<u8>> {
  let mut keysizes = get_key_sizes( bytes );
  keysizes.sort_by( |lhs, rhs| lhs.partial_cmp( rhs ).unwrap() );
  let mut keys = Vec::new();
  let size = keysizes[0].1;
  for ( _, size )  in keysizes.iter().take( nkeys ) {
    println!("key size = {}", size );
    let mut key = Vec::new();
    for n in 0 .. *size {
      let column = bytes[n ..].iter().step_by( *size ).map(|v|*v).collect::<Vec<_>>();
      let ( _, k ) = get_key( &column );
      key.push( k );
    }
    keys.push( key );
  }
  keys
}

pub fn contains_duplicate( line: &str ) -> bool {
  let mut v = line.as_bytes().chunks( 2 * aes::AES_KEYLEN ).collect::<Vec<&[u8]>>();
  let all = v.len();
  v.sort();
  v.dedup();
  let unique = v.len();
  all != unique
}

#[cfg(test)]
mod test {
  use std::collections::HashSet;
  use std::fs;
  use crate::set1::repeating_xor;
  use crate::set1::repeating_xor_hex;
  use crate::set1::hamming_distance;
  use crate::set1::hexstr2base64;
  use crate::set1::xor_hexstr;
  use crate::set1::decrypt_hexstr;
  use crate::set1::base642hex;
  use crate::set1::BASE64CHARS;
  use crate::set1::break_repeating_xor_key;
  use crate::set1::from_base64;
  use crate::set1::contains_duplicate;

  #[test]
  fn challange1() {

    let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".as_bytes();
    if let Ok( actual ) = hexstr2base64( "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".as_bytes() ) {
      assert_eq!( actual, expected );
    }
    else {
      assert!( false );
    }
  }

  #[test]
  fn challange2() {

    let expected = "746865206b696420646f6e277420706c6179".as_bytes();
    let lhs = "1c0111001f010100061a024b53535009181c".as_bytes();
    let rhs = "686974207468652062756c6c277320657965".as_bytes();
    if let Ok( actual ) = xor_hexstr( lhs, rhs ) {
      assert_eq!( actual, expected );
    }
    else {
      assert!( false );
    }
  }

  #[test]
  fn challange3() {
    let encrypted = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".as_bytes();
    let expected = "Cooking MC's like a pound of bacon".as_bytes();
    let decrypted = decrypt_hexstr( &encrypted );
    assert_eq!( decrypted.0, expected );
    assert!( decrypted.1 != i32::MIN );
  }

  #[test]
  fn challange4() {
    if let Ok( url ) = reqwest::blocking::get("https://cryptopals.com/static/challenge-data/4.txt") {
      if let Ok( body ) = url.text() {
        let expected = "Now that the party is jumping\n".as_bytes();
        let result = body.split( '\n' ).map( |encrypted| decrypt_hexstr( encrypted.as_bytes() ) ).max_by( |lhs, rhs| lhs.1.cmp( &rhs.1 ) );
        if let Some( result ) = result {
          assert_eq!( result.0, expected );
        }
        else {
          assert!( false );
        }
      }
      else {
        assert!( false );
      }
    }
    else {
      assert!( false );
    }
  }

  #[test]
  fn challange5() {
    let plain = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".as_bytes();
    let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".as_bytes();
    let key = "ICE".as_bytes();
    let encrypted = repeating_xor_hex( &plain, &key );
    assert_eq!( encrypted, expected );
  }

  #[test]
  fn challange6a() {
    let lhs = "this is a test".as_bytes();
    let rhs = "wokka wokka!!!".as_bytes();
    let expected = 37u32;
    assert_eq!( hamming_distance( lhs, rhs ), expected );
  }

  #[test]
  fn challange6b() {
    let expected = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".as_bytes();
    let actual = base642hex( "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".as_bytes() );
    assert_eq!( actual, expected );
  }

  #[test]
  fn challange6c() {
    if let Ok( txt ) = fs::read_to_string( "6.txt" ) {
      let mut chars: HashSet<u8> = HashSet::from_iter( BASE64CHARS.to_vec() );
      chars.insert( b'=' );
      let txt = txt.as_bytes().into_iter().filter( |c| chars.contains(c) ).map(|c|*c).collect::<Vec<u8>>();
      let bytes = from_base64( &txt );
      let keys = break_repeating_xor_key( &bytes, 1 );
      let expected_key = "Terminator X: Bring the noise".as_bytes();
      assert_eq!( keys[0], expected_key );
      let decrypted = repeating_xor( &bytes, &keys[0] );
      let first_line = "I'm back and I'm ringin' the bell".as_bytes();
      let line_len = first_line.len();
      assert_eq!( &decrypted[ .. line_len], first_line );
    }
  }

  use crate::set1::aes::AES_ECB_decrypt;
  use crate::set1::aes::AES_ctx;
  use std::str;

  #[test]
  fn challange7() {
    if let Ok( txt ) = fs::read_to_string( "7.txt" ) {
      let mut chars: HashSet<u8> = HashSet::from_iter( BASE64CHARS.to_vec() );
      chars.insert( b'=' );
      let txt = txt.as_bytes().into_iter().filter( |c| chars.contains(c) ).map(|c|*c).collect::<Vec<u8>>();
      let mut bytes = from_base64( &txt );
  
      let key = "YELLOW SUBMARINE".as_bytes();
      let aes_ctx = AES_ctx::New( &key );
  
      AES_ECB_decrypt( &aes_ctx, &mut bytes );
      if let Ok( plain ) = str::from_utf8( &bytes ) {
        let fstline = "I'm back and I'm ringin' the bell".to_owned();
        assert_eq!( plain[..fstline.len()], fstline );
      }
      else {
        assert!( false );
      }
    }
    else {
      assert!( false );
    }
  }

  #[test]
  fn challange8() {
    if let Ok( txt ) = fs::read_to_string( "8.txt" ) {
      let aes_ecb = txt.split( "\n" ).filter( |l|contains_duplicate(*l) ).collect::<Vec<_>>();
      let expected = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a".to_owned();
      assert_eq!( aes_ecb.len(), 1 );
      let line = aes_ecb[0];
      assert_eq!( line, expected );
    }
    else {
      assert!( false );
    }
  }
}


