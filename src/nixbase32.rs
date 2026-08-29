//! Nix's nonstandard base32: the alphabet omits e o t u, and bits are consumed from the LOW end of
//! the byte array upward while characters are emitted high-position-first — i.e. the FIRST character
//! of the string carries the HIGHEST bits. Faithful port of nix/src/libutil/hash.cc.

const ALPHABET: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

/// Number of base32 characters needed for `n` bytes.
pub const fn encoded_len(n: usize) -> usize {
    if n == 0 { 0 } else { (n * 8 - 1) / 5 + 1 }
}

pub fn encode(bytes: &[u8]) -> String {
    let len = encoded_len(bytes.len());
    let mut s = String::with_capacity(len);
    for n in (0..len).rev() {
        let b = n * 5;
        let i = b / 8;
        let j = b % 8;
        let lo = bytes[i] as u16 >> j;
        let hi = if i + 1 < bytes.len() { (bytes[i + 1] as u16) << (8 - j) } else { 0 };
        s.push(ALPHABET[((lo | hi) & 0x1f) as usize] as char);
    }
    s
}

/// Decode into exactly `out_len` bytes. Returns None on bad length, bad character, or nonzero
/// spill past the final byte (i.e. the string does not denote an `out_len`-byte value).
pub fn decode(s: &str, out_len: usize) -> Option<Vec<u8>> {
    if s.len() != encoded_len(out_len) {
        return None;
    }
    let mut out = vec![0u8; out_len];
    for (pos, ch) in s.bytes().enumerate() {
        let n = s.len() - 1 - pos;
        let digit = ALPHABET.iter().position(|&c| c == ch)? as u16;
        let b = n * 5;
        let i = b / 8;
        let j = b % 8;
        let full = digit << j;
        out[i] |= (full & 0xff) as u8;
        let hi = (full >> 8) as u8;
        if i + 1 < out_len {
            out[i + 1] |= hi;
        } else if hi != 0 {
            return None;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors generated with the real `nix hash convert` on this machine.
    const V: &[(&str, &str)] = &[
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73",
        ),
        (
            "8388b2964cf255ccd6dfe853647927b7a44d3bd583175f932b9955c54d866239",
            "0fb2hr6wamcr5f9my5w3slxlv95p4xwn8lz8vzbcqmgj9jbb5243",
        ),
    ];

    #[test]
    fn encode_matches_nix() {
        for (hexs, b32) in V {
            let bytes = hex::decode(hexs).unwrap();
            assert_eq!(encode(&bytes), *b32);
        }
    }

    #[test]
    fn decode_roundtrip() {
        for (hexs, b32) in V {
            let bytes = hex::decode(hexs).unwrap();
            assert_eq!(decode(b32, 32).unwrap(), bytes);
        }
        assert_eq!(decode("zz", 1), None); // spill past final byte
        assert_eq!(decode("abc", 32), None); // wrong length
        assert_eq!(decode("0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9ce3", 32), None); // 'e' not in alphabet
    }

    #[test]
    fn lengths() {
        assert_eq!(encoded_len(32), 52);
        assert_eq!(encoded_len(20), 32); // store path hash part
    }
}
