const Nb: usize = 4;
pub const AES_BLOCKLEN: usize = 16;

// AES256
// const Nk: u32 = 8;
// const Nr: u32 = 14;
// const AES_KEYLEN: usize = 32;
// const AES_keyExpSize: usize = 240;
// AES192
// const Nk: u32 = 6;
// const Nr: u32 = 12;
// const AES_KEYLEN: usize = 24;
// const AES_keyExpSize: usize = 208;
// AES128
const Nk: usize = 4;        // The number of 32 bit words in a key.
const Nr: usize = 10;       // The number of rounds in AES Cipher.
pub const AES_KEYLEN: usize = 16;
const AES_keyExpSize: usize = 176;

/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/

// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM - 
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
const sbox: [u8; 256] = [
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 ];

const rsbox: [u8; 256] = [
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d ];

// The round constant word array, Rcon[i], contains the values given by 
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
const Rcon: [u8; 11] = [
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 ];

/*
* Jordan Goulder points out in PR #12 (https://github.com/kokke/tiny-AES-C/pull/12),
* that you can remove most of the elements in the Rcon array, because they are unused.
*
* From Wikipedia's article on the Rijndael key schedule @ https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon
* 
* "Only the first some of these constants are actually used – up to rcon[10] for AES-128 (as 11 round keys are needed), 
*  up to rcon[8] for AES-192, up to rcon[7] for AES-256. rcon[0] is not used in AES algorithm."
*/


/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/

fn getSBoxValue( num: u8 ) -> u8 {
  return sbox[num as usize];
}

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
fn KeyExpansion( RoundKey: &mut[u8], Key: &[u8] ) {  
  // The first round key is the key itself.
  for i in 0 .. Nk {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  let mut k: usize = 0;
  let mut tempa = [0; 4];
  for i in Nk .. Nb * ( Nr + 1 ) {
    {
      k = (i - 1) * 4;
      tempa[0]=RoundKey[k + 0];
      tempa[1]=RoundKey[k + 1];
      tempa[2]=RoundKey[k + 2];
      tempa[3]=RoundKey[k + 3];

    }

    if i % Nk == 0 {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
      tempa.rotate_left( 1 );

      // SubWord() is a function that takes a four-byte input word and 
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }
// #if defined(AES256) && (AES256 == 1)
//     if (i % Nk == 4)
//     {
//       // Function Subword()
//       {
//         tempa[0] = getSBoxValue(tempa[0]);
//         tempa[1] = getSBoxValue(tempa[1]);
//         tempa[2] = getSBoxValue(tempa[2]);
//         tempa[3] = getSBoxValue(tempa[3]);
//       }
//     }
// #endif
    let j = i * 4; k=(i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

pub struct AES_ctx {
  pub RoundKey: [u8; AES_keyExpSize],
  Iv: [u8; AES_BLOCKLEN]
}

impl AES_ctx {
  pub fn New( key: &[u8] ) -> AES_ctx {
    let mut ctx = AES_ctx{ RoundKey: [0; AES_keyExpSize], Iv: [0; AES_BLOCKLEN] };
    KeyExpansion( &mut ctx.RoundKey, key );
    ctx
  }

  pub fn NewWithIv( key: &[u8], iv: &[u8] ) -> AES_ctx {
    let mut ctx = AES_ctx{ RoundKey: [0; AES_keyExpSize], Iv: [0; AES_BLOCKLEN] };
    KeyExpansion( &mut ctx.RoundKey, key );
    ctx.Iv.copy_from_slice( iv );
    ctx
  }
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
pub fn AddRoundKey( round: usize, block: &mut [u8], RoundKey: &[u8] ) {
  for i in 0 .. 4 {
    for j in 0 .. 4 {
      block[i * 4 + j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
pub fn SubBytes( block: &mut [u8] ) {
  for i in 0 .. 4 {
    for j in 0 .. 4 {
      block[j * 4 + i] = getSBoxValue( block[j * 4 + i] );
    }
  }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
pub fn ShiftRows( block: &mut [u8] ) {
  // Rotate first row 1 columns to left
  let temp= block[0 * 4 + 1];
  block[0 * 4 + 1] = block[1 * 4 + 1];
  block[1 * 4 + 1] = block[2 * 4 + 1];
  block[2 * 4 + 1] = block[3 * 4 + 1];
  block[3 * 4 + 1] = temp;

  // Rotate second row 2 columns to left  
  let temp= block[0 * 4 + 2];
  block[0 * 4 + 2] = block[2 * 4 + 2];
  block[2 * 4 + 2] = temp;

  let temp= block[1 * 4 + 2];
  block[1 * 4 + 2] = block[3 * 4 + 2];
  block[3 * 4 + 2] = temp;

  // Rotate third row 3 columns to left
  let temp= block[0 * 4 + 3];
  block[0 * 4 + 3] = block[3 * 4 + 3];
  block[3 * 4 + 3] = block[2 * 4 + 3];
  block[2 * 4 + 3] = block[1 * 4 + 3];
  block[1 * 4 + 3] = temp;
}

fn xtime( x: u8 ) -> u8 {
  (x<<1) ^ (((x>>7) & 1) * 0x1b)
}

// MixColumns function mixes the columns of the state matrix
pub fn MixColumns( block: &mut [u8] ) {
  let ( mut Tmp, mut Tm, mut t ) = ( 0u8, 0u8, 0u8 );
  for i in 0 .. 4 {
    t   = block[i * 4 + 0];
    Tmp = block[i * 4 + 0] ^ block[i * 4 + 1] ^ block[i * 4 + 2] ^ block[i * 4 + 3] ;
    Tm  = block[i * 4 + 0] ^ block[i * 4 + 1] ; Tm = xtime(Tm);  block[i * 4 + 0] ^= Tm ^ Tmp ;
    Tm  = block[i * 4 + 1] ^ block[i * 4 + 2] ; Tm = xtime(Tm);  block[i * 4 + 1] ^= Tm ^ Tmp ;
    Tm  = block[i * 4 + 2] ^ block[i * 4 + 3] ; Tm = xtime(Tm);  block[i * 4 + 2] ^= Tm ^ Tmp ;
    Tm  = block[i * 4 + 3] ^ t ;           Tm = xtime(Tm);  block[i * 4 + 3] ^= Tm ^ Tmp ;
  }
}

// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//       The compiler seems to be able to vectorize the operation better this way.
//       See https://github.com/kokke/tiny-AES-c/pull/34
fn Multiply( x: u8, y: u8 ) -> u8 {
  return ((y & 1) * x) ^
      ((y>>1 & 1) * xtime(x)) ^
      ((y>>2 & 1) * xtime(xtime(x))) ^
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))); /* this last call to xtime() can be omitted */
}

fn getSBoxInvert( num: usize ) -> u8 {
  return rsbox[num];
}

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
fn InvMixColumns( block: &mut [u8] ) {
  let ( mut a, mut b, mut c, mut d ) = ( 0u8, 0u8, 0u8, 0u8 );
  for i in 0 .. 4 {
    a = block[i * 4 + 0];
    b = block[i * 4 + 1];
    c = block[i * 4 + 2];
    d = block[i * 4 + 3];

    block[i * 4 + 0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    block[i * 4 + 1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    block[i * 4 + 2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    block[i * 4 + 3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
fn InvSubBytes( block: &mut [u8] ) {
  for i in 0 .. 4 {
    for j in 0 .. 4 {
      block[j * 4 + i] = getSBoxInvert( block[j * 4 + i] as usize );
    }
  }
}

fn InvShiftRows( block: &mut [u8] ) {
  // Rotate first row 1 columns to right  
  let mut temp = block[3 * 4 + 1];
  block[3 * 4 + 1] = block[2 * 4 + 1];
  block[2 * 4 + 1] = block[1 * 4 + 1];
  block[1 * 4 + 1] = block[0 * 4 + 1];
  block[0 * 4 + 1] = temp;

  // Rotate second row 2 columns to right 
  temp = block[0 * 4 + 2];
  block[0 * 4 + 2] = block[2 * 4 + 2];
  block[2 * 4 + 2] = temp;

  temp = block[1 * 4 + 2];
  block[1 * 4 + 2] = block[3 * 4 + 2];
  block[3 * 4 + 2] = temp;

  // Rotate third row 3 columns to right
  temp = block[0 * 4 + 3];
  block[0 * 4 + 3] = block[1 * 4 + 3];
  block[1 * 4 + 3] = block[2 * 4 + 3];
  block[2 * 4 + 3] = block[3 * 4 + 3];
  block[3 * 4 + 3] = temp;
}

// Cipher is the main function that encrypts the PlainText.
fn Cipher( block: &mut [u8], RoundKey: &[u8] ) {
  let round = 0u8;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey( 0, block, RoundKey );

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without MixColumns()
  for round in 1 ..=Nr {
    SubBytes( block );
    ShiftRows( block );
    if round == Nr { break; }
    MixColumns( block );
    AddRoundKey( round, block, RoundKey );
  }
  // Add round key to last round
  AddRoundKey( Nr, block, RoundKey );
}

fn InvCipher( block: &mut [u8], RoundKey: &[u8] ) {
  // Add the First round key to the state before starting the rounds.
  AddRoundKey( Nr, block, RoundKey );
  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without InvMixColumn()
  for round in ( 0 .. Nr ).rev() {
    InvShiftRows( block );
    InvSubBytes( block );
    AddRoundKey( round, block, RoundKey );
    if round == 0 { break; }
    InvMixColumns( block );
  }

}

// /*****************************************************************************/
// /* Public functions:                                                         */
// /*****************************************************************************/
pub fn AES_ECB_encrypt_buffer( ctx: &AES_ctx, buf: &mut [u8] ) {
  // The next function call decrypts the PlainText with the Key using AES algorithm.
  for i in 0 .. ( buf.len() / AES_KEYLEN ) {
    let idx = i * AES_KEYLEN;
    let block = &mut buf[idx .. idx + AES_KEYLEN];
    Cipher( block, &ctx.RoundKey );
  }
}

pub fn AES_ECB_decrypt_buffer( ctx: &AES_ctx, buf: &mut [u8] ) {
  // The next function call decrypts the PlainText with the Key using AES algorithm.
  for i in 0 .. ( buf.len() / AES_KEYLEN ) {
    let idx = i * AES_KEYLEN;
    let block = &mut buf[idx .. idx + AES_KEYLEN];
    InvCipher( block, &ctx.RoundKey );
  }
}

fn XorWithIv( buf: &mut [u8], Iv: &[u8] ) {
  for i in 0 .. AES_BLOCKLEN { // The block in AES is always 128bit no matter the key size
    buf[i] ^= Iv[i];
  }
}

pub fn AES_CBC_encrypt_buffer( ctx: &mut AES_ctx, buf: &mut [u8]) {
  let mut aux = ctx.Iv.clone();
  let mut Iv: &mut[u8] = &mut aux;
  let mut buf = buf;
  for _ in ( 0 .. buf.len() ).step_by( AES_BLOCKLEN ) {
    XorWithIv( buf, Iv );
    Cipher( buf, &ctx.RoundKey );
    ( Iv, buf ) = buf.split_at_mut(AES_BLOCKLEN);
  }  
  ctx.Iv.copy_from_slice( &Iv[0..AES_BLOCKLEN] );
}

pub fn AES_CBC_decrypt_buffer( ctx: &mut AES_ctx, buf: &mut [u8] ) {
  let mut storeNextIv = vec![0u8; AES_BLOCKLEN];
  let mut buf = buf;
  for _ in ( 0 .. buf.len() ).step_by( AES_BLOCKLEN ) {
    storeNextIv.copy_from_slice( &buf[0..AES_BLOCKLEN] );
    InvCipher( buf, &ctx.RoundKey );
    XorWithIv( buf, &ctx.Iv );
    ctx.Iv.copy_from_slice( &storeNextIv );
    buf = &mut buf[AES_BLOCKLEN..];
  }
}

use std::cmp::min;
fn xor_with( lhs: &mut [u8], rhs: &[u8] ) {
  for i in 0 .. min( lhs.len(), rhs.len() ) {
    lhs[i] ^= rhs[i];
  }
}

pub fn AES_CTR_transform_buffer( buf: &mut [u8], key: &[u8], nonce: u64 ) {
  let mut aes_ctx = AES_ctx::New( &key );
  for i in ( 0 .. buf.len() ).step_by( AES_BLOCKLEN ) {
    let mut keystrm: Vec<u8> = nonce.to_be_bytes().to_vec();
    let cnt = ( i as u64 ) / ( AES_BLOCKLEN as u64 );
    keystrm.extend( cnt.to_le_bytes() );
    Cipher( &mut keystrm, &aes_ctx.RoundKey );
    let end = min( i + AES_BLOCKLEN, buf.len() );
    xor_with( &mut buf[i .. end], &keystrm );
  }
}

#[cfg(test)]
mod test {

  use crate::AES_ctx;
  use crate::AES_keyExpSize;
  use crate::AddRoundKey;
  use crate::InvCipher;
use crate::SubBytes;
  use crate::ShiftRows;
  use crate::MixColumns;
  use crate::Cipher;
  use crate::AES_CBC_encrypt_buffer;
  use crate::AES_CBC_decrypt_buffer;
  use crate::AES_CTR_transform_buffer;

  #[test]
  fn RoundKeyTest() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let aes_ctx = AES_ctx::New( &key );
    let expected: [u8; AES_keyExpSize] = [89,  69,  76,  76,  79,   87,  32,  83,  85,  66,  77,  65,  82,  73,  78,  69,
                                          99,  106, 34,  76,  44,   61,  2,   31,  121, 127, 79,  94,  43,  54,  1,   27,
                                          100, 22,  141, 189, 72,   43,  143, 162, 49,  84,  192, 252, 26,  98,  193, 231,
                                          202, 110, 25,  31,  130,  69,  150, 189, 179, 17,  86,  65,  169, 115, 151, 166,
                                          77,  230, 61,  204, 207,  163, 171, 113, 124, 178, 253, 48,  213, 193, 106, 150,
                                          37,  228, 173, 207, 234,  71,  6,   190, 150, 245, 251, 142, 67,  52,  145, 24,
                                          29,  101, 0,   213, 247,  34,  6,   107, 97,  215, 253, 229, 34,  227, 108, 253,
                                          76,  53,  84,  70,  187,  23,  82,  45,  218, 192, 175, 200, 248, 35,  195, 53, 
                                          234, 27,  194,  7,   81,  12,  144, 42,  139, 204, 63,  226, 115, 239, 252, 215, 
                                          46,  171, 204, 136, 127, 167,  92,  162, 244, 107, 99,  64,  135, 132, 159, 151,
                                          71,  112, 68,  159, 56,  215,  24,  61,  204, 188, 123, 125, 75,  56,  228, 234];
    assert_eq!( aes_ctx.RoundKey, expected );
  }

  #[test]
  fn AddRoundKeyTest() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let aes_ctx = AES_ctx::New( &key );
    let mut block = "0123456789abcdef".as_bytes().to_vec();
    let expected: Vec<u8> = vec![105, 116, 126, 127, 123, 98, 22, 100, 109, 123, 44, 35, 49, 45, 43, 35];
    AddRoundKey( 0, &mut block, &aes_ctx.RoundKey );
    assert_eq!( block, expected );
  }

  #[test]
  fn SubBytesTest() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let aes_ctx = AES_ctx::New( &key );
    let mut block = "0123456789abcdef".as_bytes().to_vec();
    let expected: Vec<u8> = vec![4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 239, 170, 251, 67, 77, 51];
    SubBytes( &mut block );
    assert_eq!( block, expected );
  }

  #[test]
  fn ShiftRowsTest() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let aes_ctx = AES_ctx::New( &key );
    let mut block = "0123456789abcdef".as_bytes().to_vec();
    let expected: Vec<u8> = vec![48, 53, 97, 102, 52, 57, 101, 51, 56, 100, 50, 55, 99, 49, 54, 98];
    ShiftRows( &mut block );
    assert_eq!( block, expected );
  }

  #[test]
  fn MixColumnsTest() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let aes_ctx = AES_ctx::New( &key );
    let mut block = "0123456789abcdef".as_bytes().to_vec();
    let expected: Vec<u8> = vec![50, 55, 48, 53, 54, 51, 52, 49, 56, 139, 101, 212, 105, 98, 103, 104];
    MixColumns( &mut block );
    assert_eq!( block, expected );
  }

  #[test]
  fn CipherTest() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let aes_ctx = AES_ctx::New( &key );
    let mut block = "0123456789abcdef".as_bytes().to_vec();
    let plain = "0123456789abcdef".as_bytes().to_vec();
    let expected: Vec<u8> = vec![32, 30, 128, 47, 123, 106, 206, 111, 108, 208, 167, 67, 186, 120, 174, 173];
    Cipher( &mut block, &aes_ctx.RoundKey );
    assert_eq!( block, expected );
    InvCipher( &mut block, &aes_ctx.RoundKey );
    assert_eq!( block, plain );
  }

  #[test]
  fn AES_CBC_Test() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let mut aes_ctx = AES_ctx::New( &key );
    let mut buf = "0123456789abcdef0123456789abcdef".as_bytes().to_vec();
    let expected: Vec<u8> = vec![32,  30,  128, 47,  123, 106, 206, 111,
                                 108, 208, 167, 67,  186, 120, 174, 173,
                                 74,  49,  133, 217, 91,  1,   220, 189,
                                 47,  33,  227, 59,  118, 130, 78,  109];
    AES_CBC_encrypt_buffer( &mut aes_ctx, &mut buf );
    assert_eq!( buf, expected );

    let plain = "0123456789abcdef0123456789abcdef".as_bytes().to_vec();
    aes_ctx.Iv.fill(0);
    AES_CBC_decrypt_buffer( &mut aes_ctx, &mut buf );
    assert_eq!( buf, plain );

  }

  #[test]
  fn AES_CTR_transform_buffer_Test() {
    let mut bytes = b"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCC".to_vec();
    let key = b"YELLOW SUBMARINE".to_vec();
    let nonce = 0u64;
    AES_CTR_transform_buffer( &mut bytes, &key, 0 );
    let expected = [55, 144, 138, 10, 238, 227, 7, 163, 162, 238, 66, 28, 45, 82, 130, 51, 144, 174, 46, 158, 218, 47, 80, 156, 141, 152, 93, 209, 237, 172, 49, 90, 110, 227, 205];
    assert_eq!( bytes, expected );
    AES_CTR_transform_buffer( &mut bytes, &key, 0 );
    let expected = b"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCC".to_vec();
    assert_eq!( bytes, expected );
  }
}