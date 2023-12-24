#![no_std]
#![feature(thin_box, unchecked_math)]

extern crate alloc;

use alloc::boxed::ThinBox;
use core::{
    arch::x86_64::{_mm_pause, _rdtsc},
    mem,
    ptr::copy_nonoverlapping,
    sync::atomic::{AtomicBool, Ordering},
};

#[inline(always)]
fn rand64() -> u64 {
    unsafe {
        static mut RAND_GEN_LOCK: AtomicBool = AtomicBool::new(false);
        static mut RAND_NUM: u64 = 0;

        while !RAND_GEN_LOCK
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            _mm_pause();
        }

        let prev_rand_num = RAND_NUM;
        let _ = RAND_NUM.unchecked_mul(_rdtsc());
        RAND_NUM ^= prev_rand_num;
        let result = RAND_NUM;

        RAND_GEN_LOCK.store(false, Ordering::SeqCst);

        result
    }
}

#[repr(C, align(8))]
pub struct Box<T> {
    key: u64,
    inner: ThinBox<T>,
}

#[inline(always)]
pub fn xor_until_size<T>(x: &mut T, key: [u8; 8]) {
    // encrypt new value
    let mut size = mem::size_of_val(x);

    while size != 0 {
        let size_mod = size % mem::size_of_val(&key);

        match size_mod {
            0 => unsafe {
                let x = x as *mut T as usize + size - mem::size_of::<u64>();
                let x_val = (x as *mut u64).read_unaligned();
                (x as *mut u64).write_unaligned(x_val ^ u64::from_ne_bytes(key));
            },
            1 => unsafe {
                let x = x as *mut T as usize + size - mem::size_of::<u8>();
                let x_val = (x as *mut u8).read_unaligned();
                (x as *mut T as *mut u8).write_unaligned(x_val ^ key[0]);
            },
            2 => unsafe {
                let x = x as *mut T as usize + size - mem::size_of::<u16>();
                let x_val = (x as *mut T as *mut u16).read_unaligned();
                (x as *mut T as *mut u16)
                    .write_unaligned(x_val ^ u16::from_ne_bytes([key[0], key[1]]));
            },
            4 => unsafe {
                let x = x as *mut T as usize + size - mem::size_of::<u32>();
                let x_val = (x as *mut T as *mut u32).read_unaligned();
                (x as *mut T as *mut u32)
                    .write_unaligned(x_val ^ u32::from_ne_bytes([key[0], key[1], key[2], key[3]]));
            },
            // probably should panic
            _ => break,
        }

        size -= size_mod;
    }
}

impl<T> Box<T> {
    #[allow(unused_assignments)]
    #[inline(always)]
    pub fn new(mut value: T) -> Box<T> {
        // generate new key
        let key = rand64().to_ne_bytes();

        // encrypt inner box contents
        xor_until_size(&mut value, key);

        // store
        let result = Box {
            key: u64::from_ne_bytes(key),
            inner: {
                let mut inner = ThinBox::new(value);

                // encrypt inner box ptr
                xor_until_size(&mut inner, key);

                inner
            },
        };

        // zero memory on stack
        value = unsafe { mem::zeroed() };

        result
    }

    #[inline(always)]
    pub fn get(&self) -> T {
        // decrypt ptr
        let mut encrypted_ptr: usize = unsafe { mem::transmute_copy(&self.inner) };

        xor_until_size(&mut encrypted_ptr, self.key.to_ne_bytes());

        // decrypt data
        unsafe {
            let mut copy_buffer: T = mem::zeroed();
            copy_nonoverlapping(encrypted_ptr as *const T, &mut copy_buffer, 1);
            xor_until_size(&mut copy_buffer, self.key.to_ne_bytes());

            copy_buffer
        }
    }

    #[inline(always)]
    pub fn set(&self, mut value: T) {
        // decrypt ptr
        let mut encrypted_ptr: usize = unsafe { mem::transmute_copy(&self.inner) };

        xor_until_size(&mut encrypted_ptr, self.key.to_ne_bytes());

        // encrypt data
        unsafe {
            xor_until_size(&mut value, self.key.to_ne_bytes());
            copy_nonoverlapping(&value, encrypted_ptr as *mut T, 1);
        }
    }
}
