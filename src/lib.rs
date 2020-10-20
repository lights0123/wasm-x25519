use rand::rngs::OsRng;
use std::str::from_utf8;
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "[string, string]")]
    pub type KeyPair;
}

const KEY_SIZE: usize = 32;
const KEY_SIZE_BASE64: usize = KEY_SIZE * 4 / 3 + 4;

fn b64_encode<'a>(input: &[u8], out: &'a mut [u8]) -> &'a mut [u8] {
    let written = base64::encode_config_slice(input, base64::STANDARD, out);
    &mut out[..written]
}

#[wasm_bindgen]
pub fn generate_keypair() -> KeyPair {
    let secret = StaticSecret::new(OsRng);
    let public = PublicKey::from(&secret);
    let mut secret_b64 = [0; KEY_SIZE_BASE64];
    let mut public_b64 = [0; KEY_SIZE_BASE64];
    let secret_b64 = from_utf8(b64_encode(&secret.to_bytes(), &mut secret_b64)).unwrap();
    let public_b64 = from_utf8(b64_encode(&public.to_bytes(), &mut public_b64)).unwrap();
    let ret = js_sys::Array::new_with_length(2);
    ret.set(0, secret_b64.into());
    ret.set(1, public_b64.into());
    JsValue::from(ret).into()
}
