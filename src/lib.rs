#![no_std]
#![feature(
    const_refs_to_cell,
    const_type_id,
    const_mut_refs,
    const_trait_impl,
    effects,
    const_for,
    const_type_name
)]

extern crate alloc;

use core::{
    any::type_name,
    hint::{self, black_box},
    mem::{self, transmute_copy},
};

pub struct EncBox<T> {
    reader_count: usize,
    writer_count: usize,
    data: T,
}

unsafe impl<T> Send for EncBox<T> {}
unsafe impl<T> Sync for EncBox<T> {}

impl<T> Drop for EncBox<T> {
    // decrypt data before dropping or we will be calling Drop on an invalid object
    fn drop(&mut self) {
        crypt(&self.key(), &mut self.data);
    }
}

#[inline(always)]
const fn crypt<T>(key: &[u8; 16], obj: &mut T) {
    let obj_size = mem::size_of::<T>();

    for i in 0..obj_size {
        let cur_byte = unsafe { (obj as *mut T as *mut u8).add(i) };

        unsafe {
            *cur_byte ^= key[i % key.len()];
        }
    }
}

impl<T> EncBox<T> {
    #[inline(always)]
    const fn key(&self) -> [u8; 16] {
        const_fnv1a_hash::fnv1a_hash_str_128(type_name::<T>()).to_ne_bytes()
    }

    #[inline(always)]
    pub const fn new(obj: T) -> Self {
        let mut value = Self {
            reader_count: 0,
            writer_count: 0,
            data: obj,
        };

        crypt(&value.key(), &mut value.data);

        value
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
        let mut output = unsafe { transmute_copy(&self.data) };
        *reader_count -= 1;

        crypt(&self.key(), &mut output);

        output
    }

    pub fn set(&self, mut obj: T) -> T {
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

        crypt(&self.key(), &mut obj);

        // no readers and no writers (allow only 1 writer at a time, this one)
        black_box(while *reader_count != 0 || *writer_count != 0 {
            hint::spin_loop();
        });

        *writer_count += 1;
        mem::swap(
            unsafe { (&self.data as *const T as *mut T).as_mut().unwrap() },
            &mut obj,
        );
        *writer_count -= 1;

        crypt(&self.key(), &mut obj);

        obj
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Make sure getting current value and setting new value (storing old) works
    #[test]
    fn basic() {
        let data = EncBox::new([0i32; 4]);

        assert!(data.set([1, 2, 3, 4]) == [0, 0, 0, 0]);
        assert!(data.get() == [1, 2, 3, 4]);
    }

    // If we forcefully read the data, it shoudn't look correct,
    // make sure its only readable when from EncBox::get
    #[test]
    fn encrypted_in_memory() {
        let data = EncBox::new([1, 2, 3, 4]);

        assert!(data.data != [1, 2, 3, 4]);
        assert!(data.get() == [1, 2, 3, 4]);
        assert!(data.data != [1, 2, 3, 4]);
    }

    // Make sure encryption key is never the same
    #[test]
    fn keytest() {
        let (data1, data2) = (EncBox::new([1i32, 2, 3, 4]), EncBox::new([1i64, 2, 3, 4]));
        assert!(data1.key() != data2.key());
    }
}
