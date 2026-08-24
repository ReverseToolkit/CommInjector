use crate::ptrace_ex::{find_remote_export, remote_mmap, remote_munmap};
use crate::ptrace_ext::RemoteProcess;
use anyhow::{Context, Result, bail};
use log::{debug, info, warn};

const JNI_OK: usize = 0;
const JNI_EDETACHED: i32 = -2;
const JNI_VERSION_1_6: usize = 0x0001_0006;

const JAVA_VM_ATTACH: usize = 4;
const JAVA_VM_DETACH: usize = 5;
const JAVA_VM_GET_ENV: usize = 6;

const JNI_FIND_CLASS: usize = 6;
const JNI_EXCEPTION_DESCRIBE: usize = 16;
const JNI_EXCEPTION_CLEAR: usize = 17;
const JNI_PUSH_LOCAL_FRAME: usize = 19;
const JNI_POP_LOCAL_FRAME: usize = 20;
const JNI_NEW_OBJECT_A: usize = 30;
const JNI_GET_METHOD_ID: usize = 33;
const JNI_CALL_OBJECT_A: usize = 36;
const JNI_CALL_VOID_A: usize = 63;
const JNI_GET_FIELD_ID: usize = 94;
const JNI_GET_OBJECT_FIELD: usize = 95;
const JNI_SET_OBJECT_FIELD: usize = 104;
const JNI_GET_STATIC_METHOD_ID: usize = 113;
const JNI_CALL_STATIC_OBJECT_A: usize = 116;
const JNI_CALL_STATIC_VOID_A: usize = 143;
const JNI_NEW_STRING_UTF: usize = 167;
const JNI_GET_ARRAY_LENGTH: usize = 171;
const JNI_NEW_OBJECT_ARRAY: usize = 172;
const JNI_GET_OBJECT_ARRAY_ELEMENT: usize = 173;
const JNI_SET_OBJECT_ARRAY_ELEMENT: usize = 174;
const JNI_NEW_BYTE_ARRAY: usize = 176;
const JNI_SET_BYTE_ARRAY_REGION: usize = 207;
const JNI_EXCEPTION_CHECK: usize = 228;
const JNI_NEW_DIRECT_BYTE_BUFFER: usize = 229;

const SCRATCH_SIZE: usize = 0x1000;
const JVALUE_OFF: usize = 0x400;

pub struct RemoteJni<'a> {
    proc: &'a RemoteProcess,
    env: usize,
    functions: usize,
    vm: usize,
    vm_functions: usize,
    scratch: usize,
    attached: bool,
}

impl<'a> RemoteJni<'a> {
    pub fn attach(proc: &'a RemoteProcess) -> Result<Self> {
        let vm = resolve_java_vm(proc)?;
        let vm_functions = read_ptr(proc, vm).context("failed to read JavaVM function table")?;
        if vm_functions == 0 {
            bail!("JavaVM function table is null");
        }

        let env_slot = remote_mmap(proc, 16)?;
        proc.write_mem(env_slot, &[0u8; 16])?;

        let get_env = read_ptr(proc, vm_functions + JAVA_VM_GET_ENV * 8)?;
        let status = proc.call_function(get_env, &[vm, env_slot, JNI_VERSION_1_6])? as i32;
        let mut attached = false;

        if status == JNI_EDETACHED {
            let attach = read_ptr(proc, vm_functions + JAVA_VM_ATTACH * 8)?;
            let rc = proc.call_function(attach, &[vm, env_slot, 0])?;
            if rc != JNI_OK {
                let _ = remote_munmap(proc, env_slot, 16);
                bail!("AttachCurrentThread failed: {rc:#x}");
            }
            attached = true;
        } else if status != 0 {
            let _ = remote_munmap(proc, env_slot, 16);
            bail!("GetEnv failed: {status}");
        }

        let env = read_ptr(proc, env_slot).context("JNIEnv* is null")?;
        let _ = remote_munmap(proc, env_slot, 16);
        if env == 0 {
            bail!("JNIEnv is null");
        }

        let functions = read_ptr(proc, env).context("failed to read JNINativeInterface")?;
        if functions == 0 {
            bail!("JNINativeInterface is null");
        }

        let scratch = remote_mmap(proc, SCRATCH_SIZE)?;
        info!("remote JNI attached env={env:#x} attached_here={attached}");

        let jni = Self {
            proc,
            env,
            functions,
            vm,
            vm_functions,
            scratch,
            attached,
        };
        let _ = jni.call_slot(JNI_PUSH_LOCAL_FRAME, &[jni.env, 64]);
        Ok(jni)
    }

    fn call_slot(&self, slot: usize, args: &[usize]) -> Result<usize> {
        let func = read_ptr(self.proc, self.functions + slot * 8)?;
        if func == 0 {
            bail!("JNI slot {slot} is null");
        }
        self.proc.call_function(func, args)
    }

    fn write_cstr(&self, s: &str) -> Result<usize> {
        let mut buf = s.as_bytes().to_vec();
        buf.push(0);
        if buf.len() > JVALUE_OFF {
            bail!("JNI string too long");
        }
        self.proc.write_mem(self.scratch, &buf)?;
        Ok(self.scratch)
    }

    fn write_jvalues(&self, values: &[usize]) -> Result<usize> {
        if values.is_empty() {
            return Ok(0);
        }
        let mut blob = vec![0u8; values.len() * 8];
        for (i, v) in values.iter().enumerate() {
            blob[i * 8..i * 8 + 8].copy_from_slice(&v.to_ne_bytes());
        }
        let addr = self.scratch + JVALUE_OFF;
        self.proc.write_mem(addr, &blob)?;
        Ok(addr)
    }

    pub fn exception_check(&self) -> Result<bool> {
        Ok(self.call_slot(JNI_EXCEPTION_CHECK, &[self.env])? != 0)
    }

    pub fn exception_clear(&self) -> Result<()> {
        self.call_slot(JNI_EXCEPTION_CLEAR, &[self.env])?;
        Ok(())
    }

    fn clear_pending(&self, what: &str) -> Result<()> {
        if self.exception_check()? {
            let _ = self.call_slot(JNI_EXCEPTION_DESCRIBE, &[self.env]);
            self.exception_clear()?;
            bail!("{what}: pending Java exception");
        }
        Ok(())
    }

    pub fn find_class(&self, name: &str) -> Result<usize> {
        let p = self.write_cstr(name)?;
        let cls = self.call_slot(JNI_FIND_CLASS, &[self.env, p])?;
        self.clear_pending(&format!("FindClass({name})"))?;
        if cls == 0 {
            bail!("FindClass({name}) returned null");
        }
        Ok(cls)
    }

    pub fn get_method_id(&self, clazz: usize, name: &str, sig: &str) -> Result<usize> {
        let name_p = self.write_cstr(name)?;
        let name_owned = name.to_string();
        let sig_buf = {
            let mut b = sig.as_bytes().to_vec();
            b.push(0);
            b
        };
        let sig_p = self.scratch + 0x200;
        self.proc.write_mem(sig_p, &sig_buf)?;
        let id = self.call_slot(JNI_GET_METHOD_ID, &[self.env, clazz, name_p, sig_p])?;
        self.clear_pending(&format!("GetMethodID({name_owned})"))?;
        if id == 0 {
            bail!("GetMethodID({name_owned}{sig}) returned null");
        }
        Ok(id)
    }

    pub fn get_static_method_id(&self, clazz: usize, name: &str, sig: &str) -> Result<usize> {
        let name_p = self.write_cstr(name)?;
        let name_owned = name.to_string();
        let mut sig_buf = sig.as_bytes().to_vec();
        sig_buf.push(0);
        let sig_p = self.scratch + 0x200;
        self.proc.write_mem(sig_p, &sig_buf)?;
        let id = self.call_slot(JNI_GET_STATIC_METHOD_ID, &[self.env, clazz, name_p, sig_p])?;
        self.clear_pending(&format!("GetStaticMethodID({name_owned})"))?;
        if id == 0 {
            bail!("GetStaticMethodID({name_owned}{sig}) returned null");
        }
        Ok(id)
    }

    pub fn get_field_id(&self, clazz: usize, name: &str, sig: &str) -> Result<usize> {
        let name_p = self.write_cstr(name)?;
        let name_owned = name.to_string();
        let mut sig_buf = sig.as_bytes().to_vec();
        sig_buf.push(0);
        let sig_p = self.scratch + 0x200;
        self.proc.write_mem(sig_p, &sig_buf)?;
        let id = self.call_slot(JNI_GET_FIELD_ID, &[self.env, clazz, name_p, sig_p])?;
        self.clear_pending(&format!("GetFieldID({name_owned})"))?;
        if id == 0 {
            bail!("GetFieldID({name_owned}{sig}) returned null");
        }
        Ok(id)
    }

    pub fn get_object_field(&self, obj: usize, field: usize) -> Result<usize> {
        let val = self.call_slot(JNI_GET_OBJECT_FIELD, &[self.env, obj, field])?;
        self.clear_pending("GetObjectField")?;
        Ok(val)
    }

    pub fn set_object_field(&self, obj: usize, field: usize, value: usize) -> Result<()> {
        self.call_slot(JNI_SET_OBJECT_FIELD, &[self.env, obj, field, value])?;
        self.clear_pending("SetObjectField")
    }

    pub fn call_object(&self, obj: usize, method: usize, args: &[usize]) -> Result<usize> {
        let jvalues = self.write_jvalues(args)?;
        let val = self.call_slot(JNI_CALL_OBJECT_A, &[self.env, obj, method, jvalues])?;
        self.clear_pending("CallObjectMethodA")?;
        Ok(val)
    }

    pub fn call_void(&self, obj: usize, method: usize, args: &[usize]) -> Result<()> {
        let jvalues = self.write_jvalues(args)?;
        self.call_slot(JNI_CALL_VOID_A, &[self.env, obj, method, jvalues])?;
        self.clear_pending("CallVoidMethodA")
    }

    pub fn call_static_object(&self, clazz: usize, method: usize, args: &[usize]) -> Result<usize> {
        let jvalues = self.write_jvalues(args)?;
        let val = self.call_slot(JNI_CALL_STATIC_OBJECT_A, &[self.env, clazz, method, jvalues])?;
        self.clear_pending("CallStaticObjectMethodA")?;
        Ok(val)
    }

    pub fn call_static_void(&self, clazz: usize, method: usize, args: &[usize]) -> Result<()> {
        let jvalues = self.write_jvalues(args)?;
        self.call_slot(JNI_CALL_STATIC_VOID_A, &[self.env, clazz, method, jvalues])?;
        self.clear_pending("CallStaticVoidMethodA")
    }

    pub fn new_object(&self, clazz: usize, ctor: usize, args: &[usize]) -> Result<usize> {
        let jvalues = self.write_jvalues(args)?;
        let obj = self.call_slot(JNI_NEW_OBJECT_A, &[self.env, clazz, ctor, jvalues])?;
        self.clear_pending("NewObjectA")?;
        if obj == 0 {
            bail!("NewObjectA returned null");
        }
        Ok(obj)
    }

    pub fn new_string_utf(&self, s: &str) -> Result<usize> {
        let p = self.write_cstr(s)?;
        let js = self.call_slot(JNI_NEW_STRING_UTF, &[self.env, p])?;
        self.clear_pending("NewStringUTF")?;
        if js == 0 {
            bail!("NewStringUTF returned null");
        }
        Ok(js)
    }

    pub fn new_object_array(&self, len: usize, clazz: usize, init: usize) -> Result<usize> {
        let arr = self.call_slot(JNI_NEW_OBJECT_ARRAY, &[self.env, len, clazz, init])?;
        self.clear_pending("NewObjectArray")?;
        if arr == 0 {
            bail!("NewObjectArray returned null");
        }
        Ok(arr)
    }

    pub fn get_array_length(&self, array: usize) -> Result<usize> {
        Ok(self.call_slot(JNI_GET_ARRAY_LENGTH, &[self.env, array])? as i32 as usize)
    }

    pub fn get_object_array_element(&self, array: usize, index: usize) -> Result<usize> {
        let val = self.call_slot(JNI_GET_OBJECT_ARRAY_ELEMENT, &[self.env, array, index])?;
        self.clear_pending("GetObjectArrayElement")?;
        Ok(val)
    }

    pub fn set_object_array_element(&self, array: usize, index: usize, value: usize) -> Result<()> {
        self.call_slot(JNI_SET_OBJECT_ARRAY_ELEMENT, &[self.env, array, index, value])?;
        self.clear_pending("SetObjectArrayElement")
    }

    pub fn new_byte_array(&self, len: usize) -> Result<usize> {
        let arr = self.call_slot(JNI_NEW_BYTE_ARRAY, &[self.env, len])?;
        self.clear_pending("NewByteArray")?;
        if arr == 0 {
            bail!("NewByteArray returned null");
        }
        Ok(arr)
    }

    pub fn set_byte_array_region(&self, array: usize, start: usize, data_ptr: usize, len: usize) -> Result<()> {
        self.call_slot(
            JNI_SET_BYTE_ARRAY_REGION,
            &[self.env, array, start, len, data_ptr],
        )?;
        self.clear_pending("SetByteArrayRegion")
    }

    pub fn new_direct_byte_buffer(&self, addr: usize, size: usize) -> Result<usize> {
        let buf = self.call_slot(JNI_NEW_DIRECT_BYTE_BUFFER, &[self.env, addr, size])?;
        if self.exception_check()? || buf == 0 {
            let _ = self.exception_clear();
            return self.byte_buffer_wrap(addr, size);
        }
        Ok(buf)
    }

    fn byte_buffer_wrap(&self, addr: usize, size: usize) -> Result<usize> {
        let arr = self.new_byte_array(size)?;
        self.set_byte_array_region(arr, 0, addr, size)?;
        let bb = self.find_class("java/nio/ByteBuffer")?;
        let wrap = self.get_static_method_id(bb, "wrap", "([B)Ljava/nio/ByteBuffer;")?;
        let obj = self.call_static_object(bb, wrap, &[arr])?;
        if obj == 0 {
            bail!("ByteBuffer.wrap returned null");
        }
        Ok(obj)
    }

    pub fn try_exempt_hidden_api(&self) {
        let result = (|| -> Result<()> {
            let vmr = self.find_class("dalvik/system/VMRuntime")?;
            let get_rt = self.get_static_method_id(vmr, "getRuntime", "()Ldalvik/system/VMRuntime;")?;
            let rt = self.call_static_object(vmr, get_rt, &[])?;
            if rt == 0 {
                bail!("VMRuntime.getRuntime returned null");
            }
            let set = self.get_method_id(vmr, "setHiddenApiExemptions", "([Ljava/lang/String;)V")?;
            let str_clz = self.find_class("java/lang/String")?;
            let arr = self.new_object_array(1, str_clz, 0)?;
            let s = self.new_string_utf("L")?;
            self.set_object_array_element(arr, 0, s)?;
            self.call_void(rt, set, &[arr])
        })();
        if let Err(e) = result {
            debug!("setHiddenApiExemptions skipped: {e:#}");
        }
    }
}

impl Drop for RemoteJni<'_> {
    fn drop(&mut self) {
        let _ = self.call_slot(JNI_POP_LOCAL_FRAME, &[self.env, 0]);
        if self.attached {
            if let Ok(detach) = read_ptr(self.proc, self.vm_functions + JAVA_VM_DETACH * 8) {
                let _ = self.proc.call_function(detach, &[self.vm]);
            }
        }
        let _ = remote_munmap(self.proc, self.scratch, SCRATCH_SIZE);
    }
}

fn resolve_java_vm(proc: &RemoteProcess) -> Result<usize> {
    let pid = proc.pid.as_raw();
    match find_remote_export(pid, "libart.so", "JNI_GetCreatedJavaVMs") {
        Ok(fn_addr) => {
            debug!("JNI_GetCreatedJavaVMs at {fn_addr:#x}");
            let buf = remote_mmap(proc, 16)?;
            proc.write_mem(buf, &[0u8; 16])?;
            let rc = proc.call_function(fn_addr, &[buf, 1, buf + 8]);
            let vm = read_ptr(proc, buf);
            let _ = remote_munmap(proc, buf, 16);
            match (rc, vm) {
                (Ok(0), Ok(vm)) if vm != 0 => {
                    info!("JavaVM from JNI_GetCreatedJavaVMs: {vm:#x}");
                    return Ok(vm);
                }
                (Ok(rc), Ok(vm)) => warn!("JNI_GetCreatedJavaVMs rc={rc:#x} vm={vm:#x}"),
                (Err(e), _) => warn!("JNI_GetCreatedJavaVMs call failed: {e:#}"),
                _ => {}
            }
        }
        Err(e) => warn!("JNI_GetCreatedJavaVMs not found: {e:#}"),
    }

    const MJAVAVM: &str = "_ZN7android14AndroidRuntime7mJavaVME";
    let slot = find_remote_export(pid, "libandroid_runtime.so", MJAVAVM)
        .context("JavaVM not found via JNI_GetCreatedJavaVMs or AndroidRuntime::mJavaVM")?;
    let vm = read_ptr(proc, slot).context("failed to read AndroidRuntime::mJavaVM")?;
    if vm == 0 {
        bail!("AndroidRuntime::mJavaVM is null");
    }
    info!("JavaVM from AndroidRuntime::mJavaVM: {vm:#x}");
    Ok(vm)
}

fn read_ptr(proc: &RemoteProcess, addr: usize) -> Result<usize> {
    let buf = proc.read_mem(addr, 8)?;
    Ok(usize::from_ne_bytes(buf.try_into().unwrap()))
}
