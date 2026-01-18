#![no_std]
#![feature(
    const_slice_from_raw_parts_mut,
    const_type_id,
    const_trait_impl,
    const_for,
    const_type_name
)]
#![allow(mutable_transmutes)]

extern crate alloc;

use core::{any::type_name, mem};

use alloc::{sync::Arc, vec::Vec};
use spin::RwLock;

#[derive(Debug)]
#[repr(transparent)]
pub struct EncBox<T: Clone> {
    data: Option<Arc<RwLock<T>>>,
}

#[derive(Debug)]
#[repr(transparent)]
pub struct EncVec<T: Clone> {
    data: Vec<T>,
}

impl<T: Clone> Clone for EncBox<T> {
    fn clone(&self) -> Self {
        if let Some(x) = &self.data {
            Self {
                data: Some(Arc::clone(x)),
            }
        } else {
            Self { data: None }
        }
    }
}

unsafe impl<T: Copy> Send for EncBox<T> {}
unsafe impl<T: Clone> Sync for EncBox<T> {}

impl<T: Clone> Drop for EncBox<T> {
    // decrypt data before dropping or we will be calling Drop on an invalid object
    #[inline(always)]
    fn drop(&mut self) {
        crypt(&Self::key(), &mut *self.data.as_ref().unwrap().write());
    }
}

impl<T: Clone> Drop for EncVec<T> {
    // decrypt data before dropping or we will be calling Drop on an invalid object
    #[inline(always)]
    fn drop(&mut self) {
        crypt_bytes(&Self::key(), unsafe {
            core::slice::from_raw_parts_mut(
                self.data.as_mut_ptr() as *mut u8,
                size_of_val(&self.data[..]),
            )
        });
    }
}

#[inline(always)]
const fn crypt<T>(key: &[u8; 16], obj: &mut T) {
    let obj =
        unsafe { core::slice::from_raw_parts_mut(obj as *mut _ as *mut u8, mem::size_of::<T>()) };

    let mut i = 0;

    while i < obj.len() {
        obj[i] ^= key[i % key.len()];
        i += 1;
    }
}

#[inline(always)]
const fn crypt_bytes(key: &[u8; 16], obj: &mut [u8]) {
    let mut i = 0;

    while i < obj.len() {
        obj[i] ^= key[i % key.len()];
        i += 1;
    }
}

impl<T: Clone> EncVec<T> {
    #[inline(always)]
    const fn key() -> [u8; 16] {
        const_fnv1a_hash::fnv1a_hash_str_128(type_name::<T>()).to_ne_bytes()
    }

    pub fn current_key(&self) -> [u8; 16] {
        Self::key()
    }

    pub const fn empty() -> Self {
        Self { data: Vec::new() }
    }

    #[inline(always)]
    pub fn new(mut obj: Vec<T>) -> Self {
        crypt_bytes(&Self::key(), unsafe {
            core::slice::from_raw_parts_mut(obj.as_mut_ptr() as *mut u8, size_of_val(&obj[..]))
        });

        Self { data: obj }
    }

    #[inline(always)]
    pub fn as_vec(&self) -> Vec<T> {
        let mut output = self.data.clone();

        crypt_bytes(&Self::key(), unsafe {
            core::slice::from_raw_parts_mut(
                output.as_mut_ptr() as *mut u8,
                size_of_val(&output[..]),
            )
        });

        output
    }
}

impl<T: Clone> EncBox<T> {
    #[inline(always)]
    const fn key() -> [u8; 16] {
        const_fnv1a_hash::fnv1a_hash_str_128(type_name::<T>()).to_ne_bytes()
    }

    pub fn current_key(&self) -> [u8; 16] {
        Self::key()
    }

    pub const fn empty() -> Self {
        Self { data: None }
    }

    #[inline(always)]
    pub fn new(mut obj: T) -> Self {
        crypt(&Self::key(), &mut obj);

        Self {
            data: Some(Arc::new(RwLock::new(obj))),
        }
    }

    pub fn get(&self) -> T {
        let mut output = self.data.as_ref().unwrap().read().clone();

        crypt(&Self::key(), &mut output);

        output
    }

    pub fn set(&self, mut obj: T) -> Option<T> {
        crypt(&Self::key(), &mut obj);

        let has_value = self.data.is_some();

        if has_value {
            let mut x = self.data.as_ref().unwrap().write();
            mem::swap(&mut *x, &mut obj);
            crypt(&Self::key(), &mut obj);

            Some(obj)
        } else {
            unsafe {
                (*(self as *const Self as *mut Self)).data = Some(Arc::new(RwLock::new(obj)));
            }

            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Make sure getting current value and setting new value (storing old) works
    #[test]
    fn basic() {
        let data = EncBox::new([0i32; 4]);

        assert!(data.set([1, 2, 3, 4]) == Some([0, 0, 0, 0]));
        assert!(data.get() == [1, 2, 3, 4]);
    }

    // If we forcefully read the data, it shoudn't look correct,
    // make sure its only readable when from EncBox::get
    #[test]
    fn encrypted_in_memory() {
        let data = EncBox::new([1, 2, 3, 4]);

        assert!(*data.data.as_ref().unwrap().read() != [1, 2, 3, 4]);
        assert!(data.get() == [1, 2, 3, 4]);
        assert!(*data.data.as_ref().unwrap().read() != [1, 2, 3, 4]);
    }

    // Make sure encryption key is never the same
    #[test]
    fn keytest() {
        let (data1, data2) = (EncBox::new([1i32, 2, 3, 4]), EncBox::new([1i64, 2, 3, 4]));
        assert!(data1.current_key() != data2.current_key());
    }
}
