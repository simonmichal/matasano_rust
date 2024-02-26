fn pkcs7_padding( block: &mut Vec<u8>, size: usize ) {
  if block.len() >= size { return; }
  let val: u8 = ( size - block.len() ) as u8;
  for _ in 0 .. val {
    block.push( val );
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
      println!("{}", String::from_utf8_lossy( &bytes ) );
    }
  }
}