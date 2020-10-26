use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
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

/// Calculate a shared secret from one party's secret key and another party's public key.
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
pub fn base64_encode(data: &[u8]) -> String {
    base64::encode(data)
}

#[wasm_bindgen(catch)]
pub fn base64_decode(data: &str) -> Result<Box<[u8]>, JsValue> {
    base64::decode(data)
        .map_err(|_| JsError::new("Base64").into())
        .map(Vec::into_boxed_slice)
}

/// Generates a pair of `x25519` keys.
///
/// # Returns
///
/// * `keypair`: `x25519` key pair `[private, public]`.
///
#[wasm_bindgen]
pub fn generate_keypair() -> KeyPair {
    let secret = StaticSecret::new(OsRng);
    let public = PublicKey::from(&secret);
    let ret = js_sys::Array::new_with_length(2);
    ret.set(0, encode_key(&secret.to_bytes()).into());
    ret.set(1, encode_key(&public.to_bytes()).into());
    JsValue::from(ret).into()
}

/// Derives `x25519` public key from a private key.
///
/// # Inputs
///
/// * `secret_key`: `x25519` private key.
///
/// # Returns
///
/// * `public_key`: `x25519` public key.
///
#[wasm_bindgen]
pub fn derive_public(secret_key: &str) -> Result<JsString, JsValue> {
    let mut secret = [0; KEY_SIZE];
    let _ = b64_decode(secret_key.as_bytes(), &mut secret).map_err(|_| JsError::new("Base64"))?;
    let secret = StaticSecret::from(secret);
    let public = PublicKey::from(&secret);
    Ok(encode_key(&public.to_bytes()))
}

/// Converts `ed25519` public key to `x25519` public key.
///
/// # Inputs
///
/// * `public_key`: `ed25519` public key.
///
/// # Returns
///
/// * `public_key`: `x25519` public key.
///
#[wasm_bindgen]
pub fn decompress_public(public_key: &str) -> Result<JsString, JsValue> {
    let mut public = [0; KEY_SIZE];
    let _ = b64_decode(public_key.as_bytes(), &mut public).map_err(|_| JsError::new("Base64"))?;
    let compressed = CompressedEdwardsY::from_slice(&public[..]);
    let public = compressed
        .decompress()
        .ok_or_else(|| JsError::new("Base64"))?
        .to_montgomery();
    Ok(encode_key(&public.to_bytes()))
}

/// Converts `x25519` public key to `ed25519` public key.
///
/// # Inputs
///
/// * `public_key`: `x25519` public key.
/// * `sign`: a `u8` donating the desired sign of the resulting
///   `EdwardsPoint`.  `0` denotes positive and `1` negative.
///
/// # Returns
///
/// * `public_key`: `ed25519` public key.
///
#[wasm_bindgen]
pub fn compress_public(public_key: &str, sign: u8) -> Result<JsString, JsValue> {
    let mut public = [0; KEY_SIZE];
    let _ = b64_decode(public_key.as_bytes(), &mut public).map_err(|_| JsError::new("Base64"))?;
    let public = MontgomeryPoint(public)
        .to_edwards(sign)
        .ok_or_else(|| JsError::new("Montgomery Point"))?
        .compress();
    Ok(encode_key(&public.to_bytes()))
}
