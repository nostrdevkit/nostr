// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Nostr Browser signer implementation (NIP-07).
//!
//! `window.nostr` capability for web browsers.
//!
//! <https://github.com/nostr-protocol/nips/blob/master/07.md>

#![cfg_attr(test, allow(missing_docs))]
#![cfg_attr(not(test), warn(missing_docs))]
#![warn(rustdoc::bare_urls)]
#![doc = include_str!("../README.md")]
// Crate available only for WASM
#![cfg(target_family = "wasm")]

use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};

use js_sys::{Array, Function, JsString, Object, Promise, Reflect};
use nostr::prelude::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::Window;

pub mod error;
pub mod prelude;

use self::error::Error;

const GET_PUBLIC_KEY: &str = "getPublicKey";
const SIGN_EVENT: &str = "signEvent";
const NIP04: &str = "nip04";
const NIP44: &str = "nip44";
const ENCRYPT: &str = "encrypt";
const DECRYPT: &str = "decrypt";

enum CallFunc<'a> {
    Call0,
    Call1(&'a JsValue),
    Call2(&'a JsValue, &'a JsValue),
}

struct SendWasmFuture<F> {
    inner: F,
}

// The browser signer is only compiled for wasm. JS promises are driven by the
// browser event loop, and the wrapped future must not be polled concurrently.
unsafe impl<F> Send for SendWasmFuture<F> {}

impl<F> Future for SendWasmFuture<F>
where
    F: Future,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // We only project the pinned field; the inner future is never moved.
        unsafe { self.map_unchecked_mut(|this| &mut this.inner) }.poll(cx)
    }
}

fn boxed_send<'a, F>(future: F) -> Pin<Box<dyn Future<Output = F::Output> + Send + 'a>>
where
    F: Future + 'a,
{
    Box::pin(SendWasmFuture { inner: future })
}

/// Signer for interaction with browser extensions (ex. Alby)
///
/// Browser extensions: <https://github.com/aljazceru/awesome-nostr#nip-07-browser-extensions>
///
/// <https://github.com/nostr-protocol/nips/blob/master/07.md>
#[derive(Debug, Clone)]
pub struct BrowserSigner {
    /// `window.nostr` object
    nostr_obj: Object,
}

unsafe impl Send for BrowserSigner {}

unsafe impl Sync for BrowserSigner {}

impl BrowserSigner {
    /// Compose new NIP07 Signer
    pub fn new() -> Result<Self, Error> {
        let window: Window = web_sys::window().ok_or_else(Error::no_global_window_object)?;
        let namespace: JsValue = Reflect::get(&window, &JsValue::from_str("nostr"))
            .map_err(|_| Error::namespace_not_found("nostr"))?;
        let nostr_obj: Object = namespace
            .dyn_into()
            .map_err(|_| Error::namespace_not_found("nostr"))?;
        Ok(Self { nostr_obj })
    }

    fn get_func(&self, obj: &Object, name: &str) -> Result<Function, Error> {
        let val: JsValue = Reflect::get(obj, &JsValue::from_str(name))
            .map_err(|_| Error::namespace_not_found(name))?;
        val.dyn_into().map_err(|_| Error::namespace_not_found(name))
    }

    fn get_sub_obj(&self, super_obj: &Object, name: &str) -> Result<Object, Error> {
        let namespace: JsValue = Reflect::get(super_obj, &JsValue::from_str(name))
            .map_err(|_| Error::namespace_not_found(name))?;
        namespace
            .dyn_into()
            .map_err(|_| Error::namespace_not_found(name))
    }

    /// Get value from object key
    #[inline]
    fn get_value_by_key(&self, obj: &Object, key: &str) -> Result<JsValue, Error> {
        Reflect::get(obj, &JsValue::from_str(key)).map_err(|_| Error::object_key_not_found(key))
    }

    async fn call_func<T>(&self, obj: &Object, name: &str, args: CallFunc<'_>) -> Result<T, Error>
    where
        T: JsCast,
    {
        let func: Function = self.get_func(obj, name)?;
        let temp: JsValue = match args {
            CallFunc::Call0 => func.call0(obj)?,
            CallFunc::Call1(arg) => func.call1(obj, arg)?,
            CallFunc::Call2(arg1, arg2) => func.call2(obj, arg1, arg2)?,
        };
        let promise: Promise = Promise::resolve(&temp);
        let result: JsValue = JsFuture::from(promise).await?;

        result.dyn_into().map_err(|_| Error::type_mismatch())
    }

    /// Get Public Key
    async fn _get_public_key(&self) -> Result<PublicKey, Error> {
        let public_key: JsString = self
            .call_func(&self.nostr_obj, GET_PUBLIC_KEY, CallFunc::Call0)
            .await?;
        let public_key: String = public_key.into();
        Ok(PublicKey::from_hex(&public_key)?)
    }

    async fn _sign_event(&self, unsigned: UnsignedEvent) -> Result<Event, Error> {
        let unsigned_obj = Object::new();

        let tags: Array = unsigned
            .tags
            .iter()
            .map(|t| t.iter().map(JsValue::from_str).collect::<Array>())
            .collect();

        if let Some(id) = unsigned.id {
            Reflect::set(&unsigned_obj, &JsValue::from_str("id"), &id.to_hex().into())?;
        }

        Reflect::set(
            &unsigned_obj,
            &JsValue::from_str("pubkey"),
            &unsigned.pubkey.to_hex().into(),
        )?;

        Reflect::set(
            &unsigned_obj,
            &JsValue::from_str("created_at"),
            &(unsigned.created_at.as_secs() as f64).into(),
        )?;

        Reflect::set(
            &unsigned_obj,
            &JsValue::from_str("kind"),
            &(unsigned.kind.as_u16() as f64).into(),
        )?;

        Reflect::set(&unsigned_obj, &JsValue::from_str("tags"), &tags.into())?;

        Reflect::set(
            &unsigned_obj,
            &JsValue::from_str("content"),
            &unsigned.content.as_str().into(),
        )?;

        let event_obj: Object = self
            .call_func(&self.nostr_obj, SIGN_EVENT, CallFunc::Call1(&unsigned_obj))
            .await?;

        // Extract signature from event object
        let sig: String = self
            .get_value_by_key(&event_obj, "sig")?
            .as_string()
            .ok_or_else(Error::type_mismatch)?;
        let sig: Signature = Signature::from_str(&sig)?;

        // Add signature
        Ok(unsigned.add_signature(sig)?)
    }

    async fn encryption_decryption(
        &self,
        namespace: &str,
        func_name: &str,
        public_key: &PublicKey,
        content: &str,
    ) -> Result<String, Error> {
        let sub_obj: Object = self.get_sub_obj(&self.nostr_obj, namespace)?;
        let pk: JsValue = JsValue::from_str(&public_key.to_hex());
        let content: JsValue = JsValue::from_str(content);
        let result: JsString = self
            .call_func(&sub_obj, func_name, CallFunc::Call2(&pk, &content))
            .await?;
        Ok(result.into())
    }
}

impl AsyncGetPublicKey for BrowserSigner {
    type Error = Error;

    #[inline]
    fn get_public_key_async(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<PublicKey, Self::Error>> + Send + '_>> {
        boxed_send(async move { self._get_public_key().await })
    }
}

impl AsyncSignEvent for BrowserSigner {
    type Error = Error;

    #[inline]
    fn sign_event_async(
        &self,
        unsigned: UnsignedEvent,
    ) -> Pin<Box<dyn Future<Output = Result<Event, Self::Error>> + Send + '_>> {
        boxed_send(async move { self._sign_event(unsigned).await })
    }
}

impl AsyncNip04 for BrowserSigner {
    type Error = Error;

    fn nip04_encrypt_async<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, Self::Error>> + Send + 'a>> {
        boxed_send(async move {
            self.encryption_decryption(NIP04, ENCRYPT, public_key, content)
                .await
        })
    }

    fn nip04_decrypt_async<'a>(
        &'a self,
        public_key: &'a PublicKey,
        encrypted_content: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, Self::Error>> + Send + 'a>> {
        boxed_send(async move {
            self.encryption_decryption(NIP04, DECRYPT, public_key, encrypted_content)
                .await
        })
    }
}

impl AsyncNip44 for BrowserSigner {
    type Error = Error;

    fn nip44_encrypt_async<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, Self::Error>> + Send + 'a>> {
        boxed_send(async move {
            self.encryption_decryption(NIP44, ENCRYPT, public_key, content)
                .await
        })
    }

    fn nip44_decrypt_async<'a>(
        &'a self,
        public_key: &'a PublicKey,
        payload: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, Self::Error>> + Send + 'a>> {
        boxed_send(async move {
            self.encryption_decryption(NIP44, DECRYPT, public_key, payload)
                .await
        })
    }
}
