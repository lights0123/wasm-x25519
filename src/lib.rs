use js_sys::{Error as JsError, JsString};
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

fn b64_decode(input: &[u8], out: &mut [u8]) -> Result<usize, base64::DecodeError> {
    base64::decode_config_slice(input, base64::STANDARD, out)
}

fn encode_key(secret: &[u8]) -> JsString {
    let mut encoded = [0; KEY_SIZE_BASE64];
    from_utf8(b64_encode(secret, &mut encoded)).unwrap().into()
}

#[wasm_bindgen(catch)]
pub fn diffie_hellman(secret_key: &str, public_key: &str) -> Result<JsString, JsValue> {
    let mut secret = [0; KEY_SIZE];
    let mut public = [0; KEY_SIZE];
    let _ = b64_decode(secret_key.as_bytes(), &mut secret).map_err(|_| JsError::new("Base64"))?;
    let _ = b64_decode(public_key.as_bytes(), &mut public).map_err(|_| JsError::new("Base64"))?;
    let secret = StaticSecret::from(secret);
    let public = PublicKey::from(public);
    Ok(encode_key(&secret.diffie_hellman(&public).to_bytes()))
}

#[wasm_bindgen]
pub fn generate_keypair() -> KeyPair {
    let secret = StaticSecret::new(OsRng);
    let public = PublicKey::from(&secret);
    let ret = js_sys::Array::new_with_length(2);
    ret.set(0, encode_key(&secret.to_bytes()).into());
    ret.set(1, encode_key(&public.to_bytes()).into());
    JsValue::from(ret).into()
}
