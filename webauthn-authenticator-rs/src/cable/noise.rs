use openssl::{
    ec::{EcGroup, EcKey, PointConversionForm, EcKeyRef, EcPoint},
    nid::Nid,
    pkey::{Private, PKey}, bn::{BigNumContext, BigNum}, pkey_ctx::PkeyCtx,
};
use snow::{
    params::{
        CipherChoice, DHChoice, HandshakeChoice, HandshakeModifier, HandshakeModifierList,
        HandshakePattern, HashChoice, NoiseParams,
    },
    resolvers::{BoxedCryptoResolver, CryptoResolver, DefaultResolver, FallbackResolver},
    types::Dh,
};

use crate::ctap2::regenerate;

pub fn get_params() -> NoiseParams {
    NoiseParams {
        // P256 is not Noise spec compliant?
        name: String::from("Noise_KNpsk0_P256_AESGCM_SHA256"),
        base: snow::params::BaseChoice::Noise,
        handshake: HandshakeChoice {
            pattern: HandshakePattern::KN,
            modifiers: HandshakeModifierList {
                list: vec![HandshakeModifier::Psk(0)],
            },
        },
        // FAKE
        dh: DHChoice::Curve25519,
        cipher: CipherChoice::AESGCM,
        hash: HashChoice::SHA256,
    }
}

pub fn get_resolver() -> BoxedCryptoResolver {
    Box::new(FallbackResolver::new(
        Box::new(CableNoiseResolver),
        Box::new(DefaultResolver::default()),
    ))
}

#[derive(Default)]
pub struct CableNoiseResolver;

impl CryptoResolver for CableNoiseResolver {
    fn resolve_rng(&self) -> Option<Box<dyn snow::types::Random>> {
        None
    }

    fn resolve_dh(&self, _choice: &DHChoice) -> Option<Box<dyn snow::types::Dh>> {
        Some(Box::new(DhP256::default()))
    }

    fn resolve_hash(
        &self,
        _choice: &snow::params::HashChoice,
    ) -> Option<Box<dyn snow::types::Hash>> {
        None
    }

    fn resolve_cipher(
        &self,
        _choice: &snow::params::CipherChoice,
    ) -> Option<Box<dyn snow::types::Cipher>> {
        None
    }
}

struct DhP256 {
    private_key: EcKey<Private>,
    public_key_bytes: Vec<u8>,
    private_key_der: Vec<u8>,
}

impl Default for DhP256 {
    fn default() -> Self {
        let private_key = regenerate().unwrap();
        Self {
            public_key_bytes: get_public_key_bytes(&private_key),
            private_key_der: private_key.private_key_to_der().unwrap(),
            private_key,
        }
    }
}

fn get_public_key_bytes(private_key: &EcKeyRef<Private>) -> Vec<u8> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    private_key.public_key().to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx).unwrap()
}

impl Dh for DhP256 {
    fn name(&self) -> &'static str {
        "P256"
    }

    fn pub_len(&self) -> usize {
        1 + 32 + 32
    }

    fn priv_len(&self) -> usize {
        121
    }

    fn set(&mut self, privkey: &[u8]) {
        self.private_key = EcKey::private_key_from_der(privkey).unwrap();
        self.public_key_bytes = get_public_key_bytes(&self.private_key.as_ref());
        self.private_key_der = self.private_key.private_key_to_der().unwrap();
    }

    fn generate(&mut self, _rng: &mut dyn snow::types::Random) {
        self.private_key = regenerate().unwrap();
        self.public_key_bytes = get_public_key_bytes(&self.private_key.as_ref());
        self.private_key_der = self.private_key.private_key_to_der().unwrap();
    }

    fn pubkey(&self) -> &[u8] {
        &self.public_key_bytes
    }

    fn privkey(&self) -> &[u8] {
        &self.private_key_der
    }

    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), snow::Error> {
        // Key derivation is whacky
        // out = shared_key_ee, then shared_key_se
        // Noise states pubkey and out are both DHLEN bytes:
        // https://noiseprotocol.org/noise.html#dh-functions
        // However caBLE wants pubkey = 65 bytes, out = 32 bytes
        // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake.cc;l=945-950;drc=38321ee39cd73ac2d9d4400c56b90613dee5fe29

        trace!("dh: pubkey({} bytes), out({} bytes)", pubkey.len(), out.len());
        // TODO: error handling
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let point = EcPoint::from_bytes(&group, pubkey, &mut ctx).unwrap();
        let pubkey = EcKey::from_public_key(&group, &point).unwrap();
        let pubkey = PKey::from_ec_key(pubkey).unwrap();
        let pkey = PKey::from_ec_key(self.private_key.to_owned()).unwrap();

        let mut ctx = PkeyCtx::new(&pkey).unwrap();
        ctx.derive_init().unwrap();
        ctx.derive_set_peer(&pubkey).unwrap();
        let len = ctx.derive(Some(out)).unwrap();
        trace!("derived key length: {}", len);
        //assert_eq!(self.pub_len(), len);
        // This is greater than MAXDHLEN in snow so doesn't work
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use snow::Builder;

    use super::*;
    #[test]
    fn a() {
        let _ = tracing_subscriber::fmt::try_init();
        let builder = Builder::with_resolver(get_params(), get_resolver());
        let static_key = builder.generate_keypair().unwrap().private;

        let mut noise = builder
            .prologue(&[1])
            .local_private_key(&static_key)
            .psk(0, &[0; 32])
            .build_initiator()
            .unwrap();

        let mut message = [0; 65535];
        let len = noise.write_message(&[], &mut message).unwrap();

        trace!(">>> {:02x?}", &message[..len])
    }
}
