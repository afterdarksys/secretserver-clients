//! Secret ownership for Rust tools. No existing Rust SDK is implied.
//! `SecretBytes` provides redaction/zeroization, not memory locking.
//! `GuardedSecret` adds native libsodium guards, verified locking, and no-access
//! protection between callbacks; it is not an encrypted enclave.
//!
//! A borrowed plaintext view cannot escape into safe Rust:
//! ```compile_fail
//! use secretserver_memory::SecretBytes;
//! let secret = SecretBytes::consume(vec![1, 2, 3]).unwrap();
//! let leaked = secret.with_bytes(|bytes| bytes);
//! println!("{:?}", leaked);
//! ```
use secrecy::{ExposeSecret, SecretBox};
use std::fmt;
use zeroize::Zeroizing;

pub const MAX_SECRET_SIZE: usize = 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidSize,
    ProtectionUnavailable,
    Closed,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidSize => "invalid secret size",
            Self::ProtectionUnavailable => "protected memory unavailable",
            Self::Closed => "secret is closed",
        })
    }
}
impl std::error::Error for Error {}

/// Heap secret with redacted Debug, no Clone/Serialize, and wiping on drop.
/// This is intentionally distinct from the guarded native type.
pub struct SecretBytes(SecretBox<[u8]>);
impl SecretBytes {
    pub fn consume(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_SECRET_SIZE {
            drop(Zeroizing::new(bytes));
            return Err(Error::InvalidSize);
        }
        // Finalize the allocation before copying secret bytes, so shrinking a
        // Vec into a Box cannot leave a secret in a freed old allocation.
        let bytes = Zeroizing::new(bytes);
        let mut owned = vec![0; bytes.len()].into_boxed_slice();
        owned.copy_from_slice(&bytes);
        Ok(Self(SecretBox::new(owned)))
    }
    /// Borrow for one operation. Deliberately copying the bytes defeats cleanup.
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(self.0.expose_secret())
    }
}
impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

#[cfg(feature = "guarded")]
mod guarded {
    use super::*;
    use libsodium_sys as sodium;
    use std::{ffi::c_void, marker::PhantomData, ptr::NonNull, rc::Rc, sync::OnceLock};
    static READY: OnceLock<bool> = OnceLock::new();

    /// Owned native allocation. Deliberately !Send/!Sync: protection changes and
    /// borrowed views cannot race across threads. Use a worker-owned handle.
    pub struct GuardedSecret {
        ptr: Option<NonNull<c_void>>,
        len: usize,
        _single_thread: PhantomData<Rc<()>>,
    }
    impl GuardedSecret {
        /// Consumes and wipes the incoming Vec even when allocation/locking fails.
        /// Earlier copies and Vec reallocation history cannot be erased here.
        pub fn consume(bytes: Vec<u8>) -> Result<Self, Error> {
            let bytes = Zeroizing::new(bytes);
            if bytes.is_empty() || bytes.len() > MAX_SECRET_SIZE {
                return Err(Error::InvalidSize);
            }
            // SAFETY: sodium_init is thread-safe; OnceLock retains only success.
            if !*READY.get_or_init(|| unsafe { sodium::sodium_init() >= 0 }) {
                return Err(Error::ProtectionUnavailable);
            }
            // SAFETY: length is bounded and non-zero; NULL is checked.
            let ptr = NonNull::new(unsafe { sodium::sodium_malloc(bytes.len()) })
                .ok_or(Error::ProtectionUnavailable)?;
            let mut secret = Self {
                ptr: Some(ptr),
                len: bytes.len(),
                _single_thread: PhantomData,
            };
            // sodium_malloc may return unlocked memory: explicitly require locking.
            // SAFETY: pointer and length identify this live writable allocation.
            unsafe {
                if sodium::sodium_mlock(ptr.as_ptr(), bytes.len()) != 0 {
                    secret.close();
                    return Err(Error::ProtectionUnavailable);
                }
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    ptr.as_ptr().cast::<u8>(),
                    bytes.len(),
                );
                if sodium::sodium_mprotect_noaccess(ptr.as_ptr()) != 0 {
                    secret.close();
                    return Err(Error::ProtectionUnavailable);
                }
            }
            Ok(secret)
        }
        /// No plaintext reference may escape this callback. A caller can still
        /// deliberately copy it; those copies are not protected by this type.
        pub fn with_bytes<R>(&mut self, f: impl FnOnce(&[u8]) -> R) -> Result<R, Error> {
            let ptr = self.ptr.ok_or(Error::Closed)?;
            // SAFETY: exclusive self access; live allocation currently no-access.
            if unsafe { sodium::sodium_mprotect_readonly(ptr.as_ptr()) } != 0 {
                return Err(Error::ProtectionUnavailable);
            }
            let guard = RestoreProtection(ptr);
            // SAFETY: allocation is readable for the callback and valid for len.
            let result =
                f(unsafe { std::slice::from_raw_parts(ptr.as_ptr().cast::<u8>(), self.len) });
            drop(guard);
            Ok(result)
        }
        /// Idempotent cleanup. sodium_free wipes before releasing the allocation.
        pub fn close(&mut self) {
            if let Some(ptr) = self.ptr.take() {
                // SAFETY: sole owned allocation; sodium_free accepts protected memory.
                unsafe {
                    sodium::sodium_free(ptr.as_ptr());
                }
                self.len = 0;
            }
        }
    }
    // Restore even when the user callback unwinds. If restoration fails, do not
    // continue with silently exposed memory. Production must disable core dumps.
    struct RestoreProtection(NonNull<c_void>);
    impl Drop for RestoreProtection {
        fn drop(&mut self) {
            // SAFETY: exclusive callback scope guarantees the allocation is live.
            if unsafe { sodium::sodium_mprotect_noaccess(self.0.as_ptr()) } != 0 {
                std::process::abort();
            }
        }
    }
    impl Drop for GuardedSecret {
        fn drop(&mut self) {
            self.close();
        }
    }
    impl fmt::Debug for GuardedSecret {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("GuardedSecret([REDACTED])")
        }
    }
}
#[cfg(feature = "guarded")]
pub use guarded::GuardedSecret;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn heap_redaction_and_bounds() {
        let secret = SecretBytes::consume(b"test-secret".to_vec()).unwrap();
        assert!(!format!("{secret:?}").contains("test-secret"));
        secret.with_bytes(|b| assert_eq!(b, b"test-secret"));
        assert_eq!(
            SecretBytes::consume(vec![]).unwrap_err(),
            Error::InvalidSize
        );
        assert_eq!(
            SecretBytes::consume(vec![0; MAX_SECRET_SIZE + 1]).unwrap_err(),
            Error::InvalidSize
        );
    }
    #[cfg(feature = "guarded")]
    #[test]
    fn native_lifecycle_and_panic_cleanup() {
        let mut secret = GuardedSecret::consume(b"test-secret".to_vec()).unwrap();
        assert!(!format!("{secret:?}").contains("test-secret"));
        secret
            .with_bytes(|b| assert_eq!(b, b"test-secret"))
            .unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = secret.with_bytes(|_| panic!("callback failed"));
        }));
        assert!(result.is_err());
        secret
            .with_bytes(|b| assert_eq!(b, b"test-secret"))
            .unwrap();
        secret.close();
        secret.close();
        assert_eq!(secret.with_bytes(|_| ()), Err(Error::Closed));
    }
}

#[cfg(all(test, feature = "guarded", unix))]
mod failure_tests {
    use super::*;
    #[test]
    fn rejects_failed_memory_lock() {
        if std::env::var_os("SS_RUST_LOCK_FAILURE_CHILD").is_some() {
            assert_eq!(
                GuardedSecret::consume(vec![1; 32]).unwrap_err(),
                Error::ProtectionUnavailable
            );
            return;
        }
        let output=std::process::Command::new("/bin/sh")
            .arg("-c").arg("ulimit -c 0; ulimit -l 0 || exit 90; exec \"$1\" --exact failure_tests::rejects_failed_memory_lock --nocapture")
            .arg("memory-limit-test").arg(std::env::current_exe().unwrap())
            .env("SS_RUST_LOCK_FAILURE_CHILD","1").output().unwrap();
        assert!(
            output.status.success(),
            "lock failure subprocess: {:?}",
            output
        );
    }
}
