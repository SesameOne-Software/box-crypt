#![no_std]
#![feature(
    const_slice_from_raw_parts_mut,
    const_refs_to_cell,
    const_type_id,
    const_mut_refs,
    const_trait_impl,
    const_for,
    const_type_name,
    generic_const_exprs
)]
#![allow(mutable_transmutes)]

extern crate alloc;

use core::{
    any::type_name,
    hint::{self, black_box},
    mem::{self, transmute_copy},
};

use alloc::boxed::Box;

#[derive(Debug)]
pub struct EncBox<T: Copy> {
    reader_count: usize,
    writer_count: usize,
    data: Option<Box<T>>,
}

unsafe impl<T: Copy> Send for EncBox<T> {}
unsafe impl<T: Copy> Sync for EncBox<T> {}

impl<T: Copy> Drop for EncBox<T> {
    // decrypt data before dropping or we will be calling Drop on an invalid object
    fn drop(&mut self) {
        if let Some(data) = &mut self.data {
            crypt(&Self::key(), data.as_mut());
        }
    }
}

const fn crypt<T>(key: &[u8; 16], obj: &mut T) {
    let obj =
        unsafe { core::slice::from_raw_parts_mut(obj as *mut _ as *mut u8, mem::size_of::<T>()) };

    let mut i = 0;

    while i < obj.len() {
        obj[i] ^= key[i % key.len()];
        i += 1;
    }
}

impl<T: Copy> EncBox<T> {
    #[inline(always)]
    const fn key() -> [u8; 16] {
        const_fnv1a_hash::fnv1a_hash_str_128(type_name::<T>()).to_ne_bytes()
    }

    pub fn current_key(&self) -> [u8; 16] {
        Self::key()
    }

    pub const fn empty() -> Self {
        Self {
            reader_count: 0,
            writer_count: 0,
            data: None,
        }
    }

    #[inline(always)]
    pub fn new(mut obj: T) -> Self {
        crypt(&Self::key(), &mut obj);

        Self {
            reader_count: 0,
            writer_count: 0,
            data: Some(Box::new(obj)),
        }
    }

    pub fn get(&self) -> T {
        let writer_count = unsafe {
            (&self.writer_count as *const usize as *mut usize)
                .as_mut()
                .unwrap()
        };

        let reader_count = unsafe {
            (&self.reader_count as *const usize as *mut usize)
                .as_mut()
                .unwrap()
        };

        // dont read while writing
        // but we can have multiple readers at the same time
        black_box(while *writer_count != 0 {
            hint::spin_loop();
        });

        *reader_count += 1;
        let mut output = **self.data.as_ref().unwrap();
        *reader_count -= 1;

        crypt(&Self::key(), &mut output);

        output
    }

    pub fn set(&self, mut obj: T) -> Option<T> {
        let reader_count = unsafe {
            (&self.reader_count as *const usize as *mut usize)
                .as_mut()
                .unwrap()
        };

        let writer_count = unsafe {
            (&self.writer_count as *const usize as *mut usize)
                .as_mut()
                .unwrap()
        };

        crypt(&Self::key(), &mut obj);

        // no readers and no writers (allow only 1 writer at a time, this one)
        black_box(while *reader_count != 0 || *writer_count != 0 {
            hint::spin_loop();
        });

        let has_value = self.data.is_some();

        *writer_count += 1;
        if has_value {
            mem::swap(
                unsafe { core::mem::transmute::<&T, &mut T>(self.data.as_ref().unwrap()) },
                &mut obj,
            );
        } else {
            unsafe {
                (*(self as *const Self as *mut Self)).data = Some(Box::new(obj));
            }
        }
        *writer_count -= 1;

        if !has_value {
            None
        } else {
            crypt(&Self::key(), &mut obj);
            Some(obj)
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

        assert!(**data.data.as_ref().unwrap() != [1, 2, 3, 4]);
        assert!(data.get() == [1, 2, 3, 4]);
        assert!(**data.data.as_ref().unwrap() != [1, 2, 3, 4]);
    }

    // Make sure encryption key is never the same
    #[test]
    fn keytest() {
        let (data1, data2) = (EncBox::new([1i32, 2, 3, 4]), EncBox::new([1i64, 2, 3, 4]));
        assert!(data1.current_key() != data2.current_key());
    }
}
