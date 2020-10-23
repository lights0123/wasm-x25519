//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &JsValue);
}

#[wasm_bindgen_test]
fn pass() {
    log(&wasm_x25519::generate_keypair());
}

#[wasm_bindgen_test]
fn base64() {
    let x = &[1, 5, 176, 51][..];
    assert_eq!(
        &wasm_x25519::base64_decode(&wasm_x25519::base64_encode(x)).unwrap()[..],
        x
    );
}
