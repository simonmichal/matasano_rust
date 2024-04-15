use std::collections::HashMap;
use itertools::Itertools;
use aes::AES_BLOCKLEN;

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

pub fn byte_to_hex( bits: &u8 ) -> [u8; 2] {
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
  let mut bytes = vec![0; cnt];
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

pub fn from_base64( txt: &[u8] ) -> Vec<u8> {
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

pub fn contains_duplicate( line: &[u8], key_size: usize ) -> bool {
  let mut v = line.chunks( key_size ).collect::<Vec<&[u8]>>();
  let all = v.len();
  v.sort();
  v.dedup();
  let unique = v.len();
  all != unique
}

pub fn pkcs7_padding( block: &mut Vec<u8>, size: usize ) {
  let mut val = ( size - block.len() % size ) as u8;
  for _ in 0 .. val {
    block.push( val );
  }
}

pub fn pkcs7_padding_valid( block: &Vec<u8> ) -> bool { // is this correct ???
  if let Some( &padcnt ) = block.last() {
    if block.len() < padcnt as usize { return false; }
    if padcnt < 1 || padcnt > AES_BLOCKLEN as u8 { return false; }
    block.iter().rev().take( padcnt as usize ).all_equal()
  }
  else { true }
}

pub fn pkcs7_padding_len( block: &Vec<u8> ) -> usize {
  if let Some( &padcnt ) = block.last() {
    padcnt as usize
  }
  else { 0 }
}

pub fn pkcs7_padding_strip( block: &mut Vec<u8> ) {
  if let Some( &padcnt ) = block.last() {
    let padcnt = padcnt as usize;
    if block.len() < padcnt { return; }
    if !block.iter().rev().take( padcnt ).all_equal() { return; }
    block.resize( block.len() - padcnt, 0 );
  }
}
