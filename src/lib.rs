#![no_std]

extern crate alloc;

use core::{arch::x86_64::_rdtsc, hint, mem};

use alloc::boxed::Box;
use obfstr::random;

const KEY_LEN: usize = 16;

pub struct EncBox<T> {
    key: [u8; KEY_LEN],
    reader_count: usize,
    writer_count: usize,
    data: Box<T>,
}

unsafe impl<T> Send for EncBox<T> {}
unsafe impl<T> Sync for EncBox<T> {}

impl<T> Drop for EncBox<T> {
    // decrypt data before dropping or we will be calling Drop on an invalid object
    fn drop(&mut self) {
        crypt(&self.key, &mut *self.data);
    }
}

#[inline(always)]
fn crypt<T>(key: &[u8; KEY_LEN], obj: &mut T) {
    let obj_size = mem::size_of::<T>();

    for i in 0..obj_size {
        let cur_byte = unsafe { (obj as *mut T as *mut u8).add(i) };

        unsafe {
            *cur_byte = *cur_byte ^ key[i % KEY_LEN];
        }
    }
}

impl<T> EncBox<T> {
    #[inline(always)]
    pub fn new(mut obj: T) -> Self {
        let key = unsafe { mem::transmute([_rdtsc() ^ random!(u64), _rdtsc() ^ random!(u64)]) };

        crypt(&key, &mut obj);

        Self {
            key,
            reader_count: 0,
            writer_count: 0,
            data: Box::new(obj),
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
        while *writer_count != 0 {
            hint::spin_loop();
        }

        *reader_count += 1;
        let mut output = unsafe { (&*self.data as *const T).read() };
        *reader_count -= 1;

        crypt(&self.key, &mut output);

        output
    }

    pub fn set(&mut self, mut obj: T) -> T {
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

        crypt(&self.key, &mut obj);

        // no readers and no writers (allow only 1 writer at a time, this one)
        while *reader_count != 0 || *writer_count != 0 {
            hint::spin_loop();
        }

        *writer_count += 1;
        mem::swap(&mut *self.data, &mut obj);
        *writer_count -= 1;

        crypt(&self.key, &mut obj);

        obj
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Make sure getting current value and setting new value (storing old) works
    #[test]
    fn basic() {
        let mut data = EncBox::new([0i32; 4]);

        assert!(data.set([1, 2, 3, 4]) == [0, 0, 0, 0]);
        assert!(data.get() == [1, 2, 3, 4]);
    }

    // If we forcefully read the data, it shoudn't look correct,
    // make sure its only readable when from EncBox::get
    #[test]
    fn encrypted_in_memory() {
        let data = EncBox::new([1, 2, 3, 4]);

        assert!(*data.data != [1, 2, 3, 4]);
        assert!(data.get() == [1, 2, 3, 4]);
        assert!(*data.data != [1, 2, 3, 4]);
    }

    // Make sure encryption key is never the same
    #[test]
    fn keytest() {
        let data = [EncBox::new([1, 2, 3, 4]), EncBox::new([4, 3, 2, 1])];

        assert!(data[0].key != data[1].key);
    }
}
