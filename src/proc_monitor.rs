use std::ffi::c_void;
use std::sync::LazyLock;
use std::thread;
use std::time::Duration;

use xdl_rs::safe::{XdlLibrary, XdlOpenFlags};

const AM_PROC_START_TAG: i32 = 30014;
const LOG_ID_EVENTS: i32 = 2;
const EVENT_TYPE_INT: i8 = 0;
const EVENT_TYPE_STRING: i8 = 2;
const EVENT_TYPE_LIST: i8 = 3;

#[repr(C)]
struct LoggerEntry {
    len: u16,
    hdr_size: u16,
    pid: i32,
    tid: u32,
    sec: u32,
    nsec: u32,
    lid: u32,
    uid: u32,
}

#[repr(C)]
union LogMsgInner {
    buf: [u8; 5 * 1024 + 1],
    entry: std::mem::ManuallyDrop<LoggerEntry>,
}

#[repr(C)]
struct LogMsg {
    inner: LogMsgInner,
}

#[repr(C, packed)]
struct AndroidEventHeader {
    tag: i32,
}

#[repr(C, packed)]
struct AndroidEventList {
    type_: i8,
    element_count: i8,
}

#[repr(C, packed)]
struct AndroidEventInt {
    type_: i8,
    data: i32,
}

#[repr(C, packed)]
struct AndroidEventString {
    type_: i8,
    length: i32,
    // data follows
}

/// 进程启动事件
#[derive(Debug, Clone)]
pub struct ProcStartEvent {
    pub user: i32,
    pub pid: i32,
    pub uid: i32,
    pub process_name: String,
}

type LoggerListAllocFn = unsafe extern "C" fn(mode: i32, tail: u32, pid: i32) -> *mut c_void;
type LoggerListFreeFn = unsafe extern "C" fn(list: *mut c_void);
type LoggerListReadFn = unsafe extern "C" fn(list: *mut c_void, log_msg: *mut LogMsg) -> i32;
type LoggerOpenFn = unsafe extern "C" fn(list: *mut c_void, id: i32) -> *mut c_void;

struct LibLog {
    _lib: XdlLibrary,
    logger_list_alloc: LoggerListAllocFn,
    logger_list_free: LoggerListFreeFn,
    logger_list_read: LoggerListReadFn,
    logger_open: LoggerOpenFn,
}

impl LibLog {
    fn load() -> Result<Self, String> {
        let candidates = [
            "liblog.so",
            "/system/lib64/liblog.so",
            "/system/lib/liblog.so",
        ];
        let lib = candidates.iter()
            .find_map(|name| XdlLibrary::open(name, XdlOpenFlags::TryForceLoad).ok())
            .ok_or_else(|| "Failed to open liblog.so from any path".to_string())?;

        unsafe {
            let alloc = lib.sym("android_logger_list_alloc")
                .map_err(|e| format!("sym error: {e}"))?
                .ok_or("android_logger_list_alloc not found")?;
            let free = lib.sym("android_logger_list_free")
                .map_err(|e| format!("sym error: {e}"))?
                .ok_or("android_logger_list_free not found")?;
            let read = lib.sym("android_logger_list_read")
                .map_err(|e| format!("sym error: {e}"))?
                .ok_or("android_logger_list_read not found")?;
            let open = lib.sym("android_logger_open")
                .map_err(|e| format!("sym error: {e}"))?
                .ok_or("android_logger_open not found")?;

            Ok(LibLog {
                _lib: lib,
                logger_list_alloc: alloc.as_fn(),
                logger_list_free: free.as_fn(),
                logger_list_read: read.as_fn(),
                logger_open: open.as_fn(),
            })
        }
    }
}

fn parse_proc_start(entry: &LoggerEntry, buf: &[u8]) -> Option<ProcStartEvent> {
    let hdr_size = entry.hdr_size as usize;
    let event_data = &buf[hdr_size..];

    if event_data.len() < std::mem::size_of::<AndroidEventHeader>() {
        return None;
    }

    let tag = i32::from_le_bytes(event_data[0..4].try_into().ok()?);
    if tag != AM_PROC_START_TAG {
        return None;
    }

    // skip header(4) + list header(2)
    let mut offset = 4 + 2;

    // read user (int)
    if offset + 5 > event_data.len() { return None; }
    if event_data[offset] != EVENT_TYPE_INT as u8 { return None; }
    let user = i32::from_le_bytes(event_data[offset + 1..offset + 5].try_into().ok()?);
    offset += 5;

    // read pid (int)
    if offset + 5 > event_data.len() { return None; }
    if event_data[offset] != EVENT_TYPE_INT as u8 { return None; }
    let pid = i32::from_le_bytes(event_data[offset + 1..offset + 5].try_into().ok()?);
    offset += 5;

    // read uid (int)
    if offset + 5 > event_data.len() { return None; }
    if event_data[offset] != EVENT_TYPE_INT as u8 { return None; }
    let uid = i32::from_le_bytes(event_data[offset + 1..offset + 5].try_into().ok()?);
    offset += 5;

    // read process_name (string)
    if offset + 5 > event_data.len() { return None; }
    if event_data[offset] != EVENT_TYPE_STRING as u8 { return None; }
    let str_len = i32::from_le_bytes(event_data[offset + 1..offset + 5].try_into().ok()?) as usize;
    offset += 5;

    if offset + str_len > event_data.len() { return None; }
    let process_name = std::str::from_utf8(&event_data[offset..offset + str_len])
        .ok()?
        .to_string();

    Some(ProcStartEvent { user, pid, uid, process_name })
}

/// 启动进程监控，每当有新进程启动时调用回调
/// 此函数会阻塞当前线程，建议在单独的线程中运行
pub fn monitor_proc_start<F>(callback: F) -> Result<(), String>
where
    F: Fn(ProcStartEvent),
{
    static RECONNECT_INTERVAL: LazyLock<Duration> = LazyLock::new(|| {
        let ms = std::env::var("PROC_MONITOR_INTERVAL_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1000);
        Duration::from_millis(ms)
    });

    let liblog = LibLog::load()?;

    // 清除日志 tag 过滤
    let _ = android_properties::set("persist.log.tag", "");

    loop {
        let logger_list = unsafe { (liblog.logger_list_alloc)(0, 1, 0) };
        if logger_list.is_null() {
            thread::sleep(*RECONNECT_INTERVAL);
            continue;
        }

        let logger = unsafe { (liblog.logger_open)(logger_list, LOG_ID_EVENTS) };
        let has_logger = !logger.is_null();

        if !has_logger {
            unsafe { (liblog.logger_list_free)(logger_list) };
            thread::sleep(*RECONNECT_INTERVAL);
            continue;
        }

        let mut first = true;
        let mut msg = LogMsg {
            inner: LogMsgInner { buf: [0u8; 5 * 1024 + 1] },
        };

        loop {
            let ret = unsafe { (liblog.logger_list_read)(logger_list, &mut msg) };
            if ret <= 0 {
                break;
            }

            if first {
                first = false;
                continue;
            }

            let entry = unsafe { &*msg.inner.entry };
            let buf = unsafe { &msg.inner.buf[..] };

            if let Some(event) = parse_proc_start(entry, buf) {
                callback(event);
            }
        }

        unsafe { (liblog.logger_list_free)(logger_list) };
        thread::sleep(*RECONNECT_INTERVAL);
    }
}
