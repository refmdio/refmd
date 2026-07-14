use std::{cell::RefCell, collections::HashMap};

use wasm_bindgen::prelude::*;

use crate::hpke;

thread_local! {
    static SENDER_CONTEXTS: RefCell<SenderContexts> = RefCell::new(SenderContexts::default());
}

#[derive(Default)]
struct SenderContexts {
    next_handle: u32,
    contexts: HashMap<u32, hpke::SenderSetup>,
}

#[wasm_bindgen]
pub fn refmd_hpke_generate_key_material() -> Result<Vec<u8>, JsValue> {
    let material = hpke::generate_key_material().map_err(JsValue::from_str)?;
    let mut output = Vec::with_capacity(
        hpke::PRIVATE_KEY_BYTES + hpke::X25519_PRIVATE_KEY_BYTES + hpke::PUBLIC_KEY_BYTES,
    );
    output.extend_from_slice(&material.private_key);
    output.extend_from_slice(&material.x25519_private_key);
    output.extend_from_slice(&material.public_key);
    Ok(output)
}

#[wasm_bindgen]
pub fn refmd_hpke_derive_key_material(private_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let material = hpke::derive_key_material(private_key).map_err(JsValue::from_str)?;
    let mut output = Vec::with_capacity(hpke::X25519_PRIVATE_KEY_BYTES + hpke::PUBLIC_KEY_BYTES);
    output.extend_from_slice(&material.x25519_private_key);
    output.extend_from_slice(&material.public_key);
    Ok(output)
}

#[wasm_bindgen]
pub fn refmd_hpke_setup_sender(public_key: &[u8], info: &[u8]) -> Result<Vec<u8>, JsValue> {
    let setup = hpke::setup_sender(public_key, info).map_err(JsValue::from_str)?;
    SENDER_CONTEXTS.with(|state| {
        let mut state = state.borrow_mut();
        let handle = state.insert(setup).map_err(JsValue::from_str)?;
        let encapsulated_key = &state.contexts[&handle].encapsulated_key;
        let mut output = Vec::with_capacity(4 + hpke::ENCAPSULATED_KEY_BYTES);
        output.extend_from_slice(&handle.to_le_bytes());
        output.extend_from_slice(encapsulated_key);
        Ok(output)
    })
}

#[wasm_bindgen]
pub fn refmd_hpke_sender_seal(
    handle: u32,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, JsValue> {
    SENDER_CONTEXTS.with(|state| {
        let mut setup = state
            .borrow_mut()
            .contexts
            .remove(&handle)
            .ok_or_else(|| JsValue::from_str("hpke_sender_context_invalid"))?;
        setup
            .context
            .seal(aad, plaintext)
            .map_err(|_| JsValue::from_str("hpke_seal_failed"))
    })
}

#[wasm_bindgen]
pub fn refmd_hpke_discard_sender(handle: u32) -> bool {
    SENDER_CONTEXTS.with(|state| state.borrow_mut().contexts.remove(&handle).is_some())
}

#[wasm_bindgen]
pub fn refmd_hpke_open(
    private_key: &[u8],
    encapsulated_key: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, JsValue> {
    hpke::open(private_key, encapsulated_key, info, aad, ciphertext).map_err(JsValue::from_str)
}

impl SenderContexts {
    fn insert(&mut self, setup: hpke::SenderSetup) -> Result<u32, &'static str> {
        for _ in 0..u32::MAX {
            self.next_handle = self.next_handle.wrapping_add(1);
            if self.next_handle != 0 && !self.contexts.contains_key(&self.next_handle) {
                let handle = self.next_handle;
                self.contexts.insert(handle, setup);
                return Ok(handle);
            }
        }
        Err("hpke_sender_context_exhausted")
    }
}
