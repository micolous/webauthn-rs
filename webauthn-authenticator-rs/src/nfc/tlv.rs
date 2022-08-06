pub(crate) struct CompactTlv<'a> {
    it: std::slice::Iter<'a, u8>
}

impl CompactTlv<'_> {
    pub fn new(tlv: &[u8]) -> CompactTlv {
        // Skip null bytes at the start
        let mut i = 0;
        loop {
            if i >= tlv.len() || tlv[i] != 0 {
                break;
            }
            i += 1;
        }

        let it = (&tlv[i..]).iter();
        CompactTlv { it }
    }
}

impl Iterator for CompactTlv<'_> {
    type Item = (u8, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        let tl = self.it.next()?;
        let tag = tl >> 4;
        let len = tl & 0xf;

        let mut v: Vec<u8> = Vec::with_capacity(len as usize);
        for _ in 0..len {
            let i = self.it.next()?;
            v.push(*i);
        }
        
        Some((tag, v))
    }
}
