use webauthn_authenticator_rs::nfc::*;

#[derive(Debug)]
enum TestResult {
    Skipped,
    Pass,
    Fail,
}

type Test = fn(&NFCCard) -> TestResult;

/// For cards which declare support for extended Lc/Le, check that they actually
/// support it.
fn test_extended_lc(card: &NFCCard) -> TestResult {
    if card.atr.extended_lc != Some(true) {
        return TestResult::Skipped;
    }

    // Test with Le = 256 in extended mode
    let resp = card
        .transmit(&select_by_df_name(&APPLET_DF), ISO7816LengthForm::ExtendedOnly)
        .expect("Failed to select applet");

    // Check error codes
    if resp.is_ok() {
        TestResult::Pass
    } else {
        TestResult::Fail
    }
}

/// Checks whether the card is checking the provided AID length when testing
/// against its own applet, by selecting applets with extra bytes after the real
/// AID.
/// 
/// Yubikey 5 NFC fails this test.
fn test_incorrect_aid(card: &NFCCard) -> TestResult {
    // Prepare a buffer with extra junk
    let mut aid = Vec::with_capacity(255);
    aid.extend_from_slice(&APPLET_DF);
    while aid.len() < aid.capacity() {
        aid.push(0xFF);
    }

    for l in APPLET_DF.len() + 1..aid.capacity() {
        let resp = card
            .transmit(&select_by_df_name(&aid[..l]), ISO7816LengthForm::ShortOnly)
            .expect("Failed to select applet");

        if resp.is_ok() {
            return TestResult::Fail
        }
    }

    TestResult::Pass
}

fn test_select_zero_ne(card: &NFCCard) -> TestResult {
    let mut req = select_by_df_name(&APPLET_DF);
    req.ne = 0;
    let resp = card
            .transmit(&req, ISO7816LengthForm::ShortOnly)
            .expect("Failed to select applet");
        
    if !resp.is_success() {
        // We should always get an "OK" response...
        return TestResult::Fail;
    }

    if resp.data.len() > 0 {
        // We got some data back.
        // This suggests the card is reading the command buffer out of bounds.
        return TestResult::Fail;
    }

    // Repeat with correct length
    req.ne = resp.bytes_available();
    let resp = card
            .transmit(&req, ISO7816LengthForm::ShortOnly)
            .expect("Failed to select applet");

    if !resp.is_ok() {
        // Correct Ne should have worked?
        return TestResult::Fail;
    }

    if req.ne as usize != resp.data.len() {
        // Incorrect extra bytes
        TestResult::Fail
    } else {
        TestResult::Pass
    }
}

fn test_select_truncation(card: &NFCCard) -> TestResult {
    let mut req = select_by_df_name(&APPLET_DF);
    let mut true_len: u16 = 0;

    for ne in 1..256 {
        req.ne = ne;
        let resp = card
            .transmit(&req, ISO7816LengthForm::ShortOnly)
            .expect("Failed to select applet");
        
        if !resp.is_success() {
            // We should always get an "OK" response...
            return TestResult::Fail;
        }

        if resp.data.len() > ne.into() {
            // Limit
            return TestResult::Fail;
        }

        if resp.bytes_available() > 0 {
            if true_len == 0 {
                true_len = ne + resp.bytes_available();
            } else if true_len != ne + resp.bytes_available() {
                // changed mind
                return TestResult::Fail;
            }
        } else {
            // We reached the end
            break;
        }
        
    }
    
    TestResult::Pass
}


fn test_card(card: NFCCard) {
    info!("Card detected ...");
    // Check that we're not a storage card
    if card.atr.storage_card {
        panic!("Detected storage card - only FIDO2 tokens are supported");
    }

    const TESTS: [(&str, Test); 4] = [
        ("Select applet with extended Lc/Le", test_extended_lc),
        ("Select incorrect applet AID", test_incorrect_aid),
        ("Select with zero Ne", test_select_zero_ne),
        ("Select with truncated Ne", test_select_truncation),
    ];
    
    for (name, testfn) in &TESTS {
        println!("Test: {}", name);
        let res = testfn(&card);
        println!("  Result: {:?}", res);
    }
}


pub(crate) fn main() {
    let mut reader = NFCReader::default();
    info!("Using reader: {:?}", reader);

    let card = reader.wait_for_card().expect("Error getting card");
    test_card(card);
}
