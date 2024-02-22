fn pkcs7_padding( block: &mut Vec<u8>, size: usize ) {
  if block.len() >= size { return; }
  let val: u8 = ( size - block.len() ) as u8;
  for _ in 0 .. val {
    block.push( val );
  }
}

#[cfg(test)]
mod test {
    use super::pkcs7_padding;

  #[test]
  fn challange9() {
    let mut block = "YELLOW SUBMARINE".as_bytes().to_vec();
    pkcs7_padding( &mut block, 20 );
    let expected = vec![b'Y', b'E', b'L', b'L', b'O', b'W', b' ', b'S', b'U', b'B', b'M', b'A', b'R', b'I', b'N', b'E', 4u8, 4u8, 4u8, 4u8];
    assert_eq!( block, expected );
  }
}