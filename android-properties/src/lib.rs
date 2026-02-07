use std::ffi::CString;

use android_system_properties::AndroidSystemProperties;
use lazy_static::lazy_static;
use rsproperties::system_properties;

unsafe extern "C" {
    fn __system_property_set(name: *const std::ffi::c_char, value: *const std::ffi::c_char) -> i32;
}

lazy_static! {
    static ref ANDROID_SYSTEM_VERSION: i32 = get_android_system_version();
}

fn get_android_system_version() -> i32 {
    AndroidSystemProperties::new()
        .get("ro.build.version.sdk")
        .map(|value| value.parse::<i32>())
        .map_or(29, |v| v.unwrap_or(29))
}

pub fn get<T>(name: &str) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let value = if *ANDROID_SYSTEM_VERSION >= 28 {
        system_properties().get_with_result(name).map_err(|e| e.to_string())?
    } else {
        AndroidSystemProperties::new().get(name).ok_or_else(|| format!("Not found: {}", name))?
    };
    value.parse().map_err(|e| format!("Failed to parse '{value}' for property '{name}': {e}"))
}

pub fn get_or<T>(name: &str, default: T) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match get::<T>(name) {
        Ok(value) => value,
        _ => default,
    }
}

pub fn set(name: &str, value: &str) -> Result<(), String> {
    let c_name = CString::new(name).map_err(|e| format!("Invalid property name: {e}"))?;
    let c_value = CString::new(value).map_err(|e| format!("Invalid property value: {e}"))?;
    let ret = unsafe { __system_property_set(c_name.as_ptr(), c_value.as_ptr()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(format!("__system_property_set failed with code {ret}"))
    }
}
