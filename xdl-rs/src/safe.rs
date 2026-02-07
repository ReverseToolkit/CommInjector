//! Safe Rust wrapper for xDL library

use std::ffi::{CStr, CString};
use std::ptr;
use std::marker::PhantomData;
use crate::*;
use crate::xdl_iterate_phdr as xdl_iterate_phdr_unsafe;

/// Error types for xDL operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XdlError {
    /// Failed to open library
    OpenFailed(String),
    /// Symbol not found
    SymbolNotFound(String),
    /// Invalid UTF-8 in C string
    InvalidUtf8,
    /// Address lookup failed
    AddrLookupFailed,
    /// Null pointer encountered
    NullPointer,
}

impl std::fmt::Display for XdlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XdlError::OpenFailed(name) => write!(f, "Failed to open library: {}", name),
            XdlError::SymbolNotFound(name) => write!(f, "Symbol not found: {}", name),
            XdlError::InvalidUtf8 => write!(f, "Invalid UTF-8 string"),
            XdlError::AddrLookupFailed => write!(f, "Address lookup failed"),
            XdlError::NullPointer => write!(f, "Null pointer encountered"),
        }
    }
}

impl std::error::Error for XdlError {}

pub type Result<T> = std::result::Result<T, XdlError>;

/// Flags for opening a library
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdlOpenFlags {
    /// Default behavior - don't force load if already loaded
    Default,
    /// Try to force load with dlopen if not already loaded
    TryForceLoad,
    /// Always force load with dlopen
    AlwaysForceLoad,
}

impl From<XdlOpenFlags> for i32 {
    fn from(flags: XdlOpenFlags) -> i32 {
        match flags {
            XdlOpenFlags::Default => XDL_DEFAULT as i32,
            XdlOpenFlags::TryForceLoad => XDL_TRY_FORCE_LOAD as i32,
            XdlOpenFlags::AlwaysForceLoad => XDL_ALWAYS_FORCE_LOAD as i32,
        }
    }
}

/// A handle to a dynamically loaded library
pub struct XdlLibrary {
    handle: *mut std::ffi::c_void,
    _marker: PhantomData<*mut std::ffi::c_void>,
}

impl XdlLibrary {
    /// Open a dynamic library
    ///
    /// # Arguments
    /// * `filename` - Library name (basename) or full pathname
    /// * `flags` - Open flags controlling load behavior
    ///
    /// # Example
    /// ```no_run
    /// use xdl_rs::safe::{XdlLibrary, XdlOpenFlags};
    ///
    /// let lib = XdlLibrary::open("libc.so", XdlOpenFlags::Default)?;
    /// # Ok::<(), xdl_rs::safe::XdlError>(())
    /// ```
    pub fn open(filename: &str, flags: XdlOpenFlags) -> Result<Self> {
        let c_filename = CString::new(filename)
            .map_err(|_| XdlError::InvalidUtf8)?;

        let handle = unsafe {
            xdl_open(c_filename.as_ptr(), flags.into())
        };

        if handle.is_null() {
            return Err(XdlError::OpenFailed(filename.to_string()));
        }

        Ok(XdlLibrary {
            handle,
            _marker: PhantomData,
        })
    }

    /// Look up a symbol in the dynamic symbol table (.dynsym)
    ///
    /// # Arguments
    /// * `symbol` - Symbol name to look up
    ///
    /// # Example
    /// ```no_run
    /// use xdl_rs::safe::{XdlLibrary, XdlOpenFlags};
    ///
    /// let lib = XdlLibrary::open("libc.so", XdlOpenFlags::Default)?;
    /// if let Some(sym) = lib.sym("malloc")? {
    ///     println!("malloc at: {:p}, size: {}", sym.addr, sym.size);
    /// }
    /// # Ok::<(), xdl_rs::safe::XdlError>(())
    /// ```
    pub fn sym(&self, symbol: &str) -> Result<Option<XdlSymbol>> {
        let c_symbol = CString::new(symbol)
            .map_err(|_| XdlError::InvalidUtf8)?;

        let mut size: usize = 0;
        let addr = unsafe {
            xdl_sym(self.handle, c_symbol.as_ptr(), &mut size as *mut _)
        };

        if addr.is_null() {
            Ok(None)
        } else {
            Ok(Some(XdlSymbol { addr, size }))
        }
    }

    /// Look up a symbol in the debug symbol table (.symtab)
    ///
    /// This is slower than `sym()` as it needs to load from disk.
    ///
    /// # Arguments
    /// * `symbol` - Symbol name to look up
    pub fn dsym(&self, symbol: &str) -> Result<Option<XdlSymbol>> {
        let c_symbol = CString::new(symbol)
            .map_err(|_| XdlError::InvalidUtf8)?;

        let mut size: usize = 0;
        let addr = unsafe {
            xdl_dsym(self.handle, c_symbol.as_ptr(), &mut size as *mut _)
        };

        if addr.is_null() {
            Ok(None)
        } else {
            Ok(Some(XdlSymbol { addr, size }))
        }
    }

    /// Get information about this library
    pub fn info(&self) -> Result<XdlLibraryInfo> {
        let mut info: xdl_info_t = unsafe { std::mem::zeroed() };

        let ret = unsafe {
            xdl_info(
                self.handle,
                XDL_DI_DLINFO as i32,
                &mut info as *mut _ as *mut std::ffi::c_void
            )
        };

        if ret != 0 {
            return Err(XdlError::AddrLookupFailed);
        }

        Ok(XdlLibraryInfo::from_raw(&info))
    }
}

impl Drop for XdlLibrary {
    fn drop(&mut self) {
        unsafe {
            xdl_close(self.handle);
        }
    }
}

// XdlLibrary is not Send/Sync by default for safety
// Users can implement these traits if they know it's safe in their context

/// Information about a symbol
#[derive(Debug, Clone, Copy)]
pub struct XdlSymbol {
    /// Address of the symbol in memory
    pub addr: *mut std::ffi::c_void,
    /// Size of the symbol in bytes
    pub size: usize,
}

impl XdlSymbol {
    /// Get the address as a raw pointer
    pub fn as_ptr<T>(&self) -> *mut T {
        self.addr as *mut T
    }

    /// Get the address as a function pointer
    ///
    /// # Safety
    /// Caller must ensure the symbol is actually a function with the correct signature
    pub unsafe fn as_fn<F>(&self) -> F {
        std::mem::transmute_copy(&self.addr)
    }
}

/// Information about a loaded library
#[derive(Debug)]
pub struct XdlLibraryInfo {
    /// Pathname of the library
    pub filename: Option<String>,
    /// Base address where library is loaded
    pub base_addr: *mut std::ffi::c_void,
}

impl XdlLibraryInfo {
    fn from_raw(info: &xdl_info_t) -> Self {
        let filename = if info.dli_fname.is_null() {
            None
        } else {
            unsafe {
                CStr::from_ptr(info.dli_fname)
                    .to_str()
                    .ok()
                    .map(|s| s.to_string())
            }
        };

        XdlLibraryInfo {
            filename,
            base_addr: info.dli_fbase,
        }
    }
}

/// Cache for address lookups
pub struct XdlAddrCache {
    cache: *mut std::ffi::c_void,
}

impl XdlAddrCache {
    /// Create a new address lookup cache
    pub fn new() -> Self {
        XdlAddrCache {
            cache: ptr::null_mut(),
        }
    }

    /// Look up information about an address
    ///
    /// # Arguments
    /// * `addr` - The address to look up
    ///
    /// # Example
    /// ```no_run
    /// use xdl_rs::safe::XdlAddrCache;
    ///
    /// let mut cache = XdlAddrCache::new();
    /// let addr = some_function as *mut std::ffi::c_void;
    /// if let Some(info) = cache.lookup(addr)? {
    ///     println!("Symbol: {:?}", info.symbol_name);
    /// }
    ///
    /// fn some_function() {}
    /// # Ok::<(), xdl_rs::safe::XdlError>(())
    /// ```
    pub fn lookup(&mut self, addr: *mut std::ffi::c_void) -> Result<Option<XdlAddressInfo>> {
        let mut info: xdl_info_t = unsafe { std::mem::zeroed() };

        let ret = unsafe {
            xdl_addr(addr, &mut info as *mut _, &mut self.cache as *mut _)
        };

        if ret != 0 {
            return Ok(None);
        }

        Ok(Some(XdlAddressInfo::from_raw(&info)))
    }

    /// Look up information about an address without symbol information
    ///
    /// This is faster than `lookup()` as it skips symbol resolution.
    pub fn lookup_no_symbol(&mut self, addr: *mut std::ffi::c_void) -> Result<Option<XdlAddressInfo>> {
        let mut info: xdl_info_t = unsafe { std::mem::zeroed() };

        let ret = unsafe {
            xdl_addr4(addr, &mut info as *mut _, &mut self.cache as *mut _, XDL_NON_SYM as i32)
        };

        if ret != 0 {
            return Ok(None);
        }

        Ok(Some(XdlAddressInfo::from_raw(&info)))
    }
}

impl Drop for XdlAddrCache {
    fn drop(&mut self) {
        unsafe {
            xdl_addr_clean(&mut self.cache as *mut _);
        }
    }
}

impl Default for XdlAddrCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about an address
#[derive(Debug)]
pub struct XdlAddressInfo {
    /// Pathname of the library containing this address
    pub filename: Option<String>,
    /// Base address of the library
    pub base_addr: *mut std::ffi::c_void,
    /// Symbol name (if found)
    pub symbol_name: Option<String>,
    /// Symbol address (if found)
    pub symbol_addr: Option<*mut std::ffi::c_void>,
    /// Symbol size (if found)
    pub symbol_size: usize,
}

impl XdlAddressInfo {
    fn from_raw(info: &xdl_info_t) -> Self {
        let filename = if info.dli_fname.is_null() {
            None
        } else {
            unsafe {
                CStr::from_ptr(info.dli_fname)
                    .to_str()
                    .ok()
                    .map(|s| s.to_string())
            }
        };

        let symbol_name = if info.dli_sname.is_null() {
            None
        } else {
            unsafe {
                CStr::from_ptr(info.dli_sname)
                    .to_str()
                    .ok()
                    .map(|s| s.to_string())
            }
        };

        let symbol_addr = if info.dli_saddr.is_null() {
            None
        } else {
            Some(info.dli_saddr)
        };

        XdlAddressInfo {
            filename,
            base_addr: info.dli_fbase,
            symbol_name,
            symbol_addr,
            symbol_size: info.dli_ssize,
        }
    }
}

/// Iterate over all loaded program headers
///
/// # Arguments
/// * `callback` - Function to call for each loaded library
/// * `full_pathname` - If true, use full pathnames instead of basenames
///
/// # Example
/// ```no_run
/// use xdl_rs::safe::xdl_iterate_phdr;
///
/// xdl_iterate_phdr(|info| {
///     println!("Library: {}", info.name.unwrap_or("<unknown>"));
///     false // continue iteration
/// }, false)?;
/// # Ok::<(), xdl_rs::safe::XdlError>(())
/// ```
pub fn xdl_iterate_phdr<F>(mut callback: F, full_pathname: bool) -> Result<()>
where
    F: FnMut(XdlPhdrInfo) -> bool,
{
    struct CallbackData<F> {
        callback: F,
        error: bool,
    }

    extern "C" fn trampoline<F>(
        info: *mut dl_phdr_info,
        _size: usize,
        data: *mut std::ffi::c_void,
    ) -> i32
    where
        F: FnMut(XdlPhdrInfo) -> bool,
    {
        let data = unsafe { &mut *(data as *mut CallbackData<F>) };

        if info.is_null() {
            data.error = true;
            return 1; // stop iteration
        }

        let phdr_info = unsafe {
            let info_ref = &*info;
            let name = if info_ref.dlpi_name.is_null() {
                None
            } else {
                CStr::from_ptr(info_ref.dlpi_name)
                    .to_str()
                    .ok()
                    .map(|s| s.to_string())
            };

            XdlPhdrInfo {
                name,
                addr: info_ref.dlpi_addr as *mut std::ffi::c_void,
            }
        };

        if (data.callback)(phdr_info) {
            1 // stop iteration
        } else {
            0 // continue
        }
    }

    let mut data = CallbackData {
        callback,
        error: false,
    };

    let flags = if full_pathname {
        XDL_FULL_PATHNAME as i32
    } else {
        XDL_DEFAULT as i32
    };

    unsafe {
        xdl_iterate_phdr_unsafe(
            Some(trampoline::<F>),
            &mut data as *mut _ as *mut std::ffi::c_void,
            flags,
        );
    }

    if data.error {
        Err(XdlError::NullPointer)
    } else {
        Ok(())
    }
}

/// Information about a program header
#[derive(Debug)]
pub struct XdlPhdrInfo {
    /// Library name
    pub name: Option<String>,
    /// Base address
    pub addr: *mut std::ffi::c_void,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "android")]
    fn test_safe_open() {
        let lib = XdlLibrary::open("libc.so", XdlOpenFlags::Default);
        assert!(lib.is_ok());
    }

    #[test]
    #[cfg(target_os = "android")]
    fn test_safe_sym() {
        let lib = XdlLibrary::open("libc.so", XdlOpenFlags::Default).unwrap();
        let sym = lib.sym("malloc").unwrap();
        assert!(sym.is_some());

        let malloc = sym.unwrap();
        assert!(!malloc.addr.is_null());
        assert!(malloc.size > 0);
    }

    #[test]
    #[cfg(target_os = "android")]
    fn test_addr_cache() {
        fn test_fn() {}

        let mut cache = XdlAddrCache::new();
        let addr = test_fn as *mut std::ffi::c_void;
        let info = cache.lookup(addr).unwrap();
        assert!(info.is_some());
    }

    #[test]
    #[cfg(target_os = "android")]
    fn test_iterate() {
        let mut count = 0;
        xdl_iterate_phdr(|_info| {
            count += 1;
            false // continue
        }, false).unwrap();

        assert!(count > 0);
    }
}
