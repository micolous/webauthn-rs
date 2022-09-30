use std::marker::PhantomData;
use std::ops::Deref;
use std::pin::Pin;

use crate::error::WebauthnCError;

/// Smart pointer type to auto-[Drop] bare pointers we got from Windows' API,
/// establishing a strict lifetime for data that we need to tell Windows to
/// free.
///
/// All fields of this struct are considered private.
pub struct WinPtr<'a, T: 'a> {
    free: unsafe fn(*const T) -> (),
    ptr: *const T,
    phantom: PhantomData<&'a T>,
}

impl<'a, T> WinPtr<'a, T> {
    /// Creates a wrapper around a `*const T` Pointer to automatically call its
    /// `free` function when this struct is dropped.
    ///
    /// Returns `None` if `ptr` is null.
    /// 
    /// Unsafe if `ptr` is unaligned or does not point to `T`.
    pub unsafe fn new(ptr: *const T, free: unsafe fn(*const T) -> ()) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            // println!("new_ptr: r={:?}", ptr);
            Some(Self {
                free,
                ptr,
                phantom: PhantomData,
            })
        }
    }
}

impl<'a, T> Deref for WinPtr<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &(*self.ptr) }
    }
}

impl<'a, T> Drop for WinPtr<'a, T> {
    fn drop(&mut self) {
        // println!("free_ptr: r={:?}, {:?}", self._raw, std::ptr::addr_of!(self.ptr));
        unsafe { (self.free)(self.ptr) }
    }
}

/// Wrapper for native types of data we own (T) which represent some other type in the Win32 API (NativeType).
pub trait WinWrapper<T> {
    /// Type in the Win32 API which is being wrapped.
    type NativeType;
    /// Creates a new native structure
    fn new(rp: &T) -> Result<Pin<Box<Self>>, WebauthnCError>;
    /// Returns a pointer to the native structure
    fn native_ptr(&self) -> &Self::NativeType;
}
