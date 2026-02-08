use std::ffi::c_void;
use std::io::{IoSlice, IoSliceMut};
use std::mem;

use anyhow::{Context, Result, bail};
use log::debug;
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::uio::{RemoteIoVec, process_vm_readv, process_vm_writev};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;

const CPSR_T_MASK: u64 = 1u64 << 5;
const REG_ARGS_NUM: usize = 8;
const NT_PRSTATUS: libc::c_int = 1;

type PtRegs = libc::user_regs_struct;

pub struct RemoteProcess {
    pub pid: Pid,
    attached: bool,
    default_caller: usize,
}

impl RemoteProcess {
    pub fn attach(pid: i32) -> Result<Self> {
        let nix_pid = Pid::from_raw(pid);

        ptrace::attach(nix_pid).context("PTRACE_ATTACH failed")?;

        match waitpid(nix_pid, None).context("waitpid after attach failed")? {
            WaitStatus::Stopped(_, _) => {}
            status => {
                let _ = ptrace::detach(nix_pid, None);
                bail!("waitpid after attach: unexpected status {:?}", status);
            }
        }

        Ok(RemoteProcess {
            pid: nix_pid,
            attached: true,
            default_caller: 0,
        })
    }

    pub fn detach(&mut self) -> Result<()> {
        if !self.attached {
            return Ok(());
        }
        ptrace::detach(self.pid, None).context("PTRACE_DETACH failed")?;
        self.attached = false;
        Ok(())
    }

    pub fn cont(&self) -> Result<()> {
        if !self.attached {
            bail!("PTRACE_CONT failed, not attached");
        }
        ptrace::cont(self.pid, None).context("PTRACE_CONT failed")?;
        Ok(())
    }

    pub fn wait(&self, flags: Option<WaitPidFlag>) -> Result<WaitStatus> {
        waitpid(self.pid, flags).context("waitpid failed")
    }

    pub fn get_regs(&self) -> Result<PtRegs> {
        if !self.attached {
            bail!("PTRACE_GETREGSET failed, not attached");
        }
        ptrace_getregset(self.pid)
    }

    pub fn set_regs(&self, regs: &PtRegs) -> Result<()> {
        if !self.attached {
            bail!("PTRACE_SETREGSET failed, not attached");
        }
        ptrace_setregset(self.pid, regs)
    }

    pub fn set_default_caller(&mut self, caller: usize) {
        self.default_caller = caller;
    }

    pub fn read_mem(&self, addr: usize, size: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; size];
        let mut local_iov = [IoSliceMut::new(&mut buf)];
        let remote_iov = [RemoteIoVec { base: addr, len: size }];
        process_vm_readv(self.pid, &mut local_iov, &remote_iov)
            .context("process_vm_readv failed")?;
        Ok(buf)
    }

    pub fn write_mem(&self, addr: usize, data: &[u8]) -> Result<()> {
        let local_iov = [IoSlice::new(data)];
        let remote_iov = [RemoteIoVec { base: addr, len: data.len() }];
        process_vm_writev(self.pid, &local_iov, &remote_iov)
            .context("process_vm_writev failed")?;
        Ok(())
    }

    pub fn read_cstring(&self, addr: usize, max_len: usize) -> Result<String> {
        let buf = self.read_mem(addr, max_len)?;
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Ok(String::from_utf8_lossy(&buf[..end]).to_string())
    }

    /// 使用 default_caller 作为返回地址
    pub fn call_function(&self, func_addr: usize, args: &[usize]) -> Result<usize> {
        self.call_function_from(self.default_caller, func_addr, args)
    }

    pub fn call_function_from(
        &self,
        caller_address: usize,
        function_address: usize,
        args: &[usize],
    ) -> Result<usize> {
        if function_address == 0 {
            return Ok(0);
        }

        if !self.attached {
            bail!("callFunction failed, not attached");
        }

        let backup_regs = self.get_regs()?;
        let mut tmp_regs = backup_regs;

        let nargs = args.len();

        debug!(
            "callFunction: Calling function {:#x} with {} args.",
            function_address, nargs
        );

        for i in 0..nargs.min(REG_ARGS_NUM) {
            tmp_regs.regs[i] = args[i] as u64;
        }

        if nargs > REG_ARGS_NUM {
            let extra_count = nargs - REG_ARGS_NUM;
            tmp_regs.sp -= (size_of::<usize>() * extra_count) as u64;

            let mut stack = tmp_regs.sp as usize;
            for i in REG_ARGS_NUM..nargs {
                self.write_mem(stack, &args[i].to_ne_bytes())?;
                stack += size_of::<usize>();
            }
        }

        // LR = caller_address
        tmp_regs.regs[30] = caller_address as u64;
        // PC = function_address
        tmp_regs.pc = function_address as u64;

        if tmp_regs.pc & 1 != 0 {
            tmp_regs.pc &= !1u64;
            tmp_regs.pstate |= CPSR_T_MASK;
        } else {
            tmp_regs.pstate &= !CPSR_T_MASK;
        }

        self.set_regs(&tmp_regs)?;
        self.cont()?;

        loop {
            match self.wait(Some(WaitPidFlag::WUNTRACED))? {
                WaitStatus::Stopped(_, sig)
                    if sig == Signal::SIGSEGV || sig == Signal::SIGILL =>
                {
                    break;
                }
                WaitStatus::Exited(_, code) => {
                    bail!("callFunction: Target process exited ({code})");
                }
                WaitStatus::Signaled(_, sig, _) => {
                    bail!("callFunction: Target process terminated ({sig})");
                }
                _ => {
                    self.cont()?;
                }
            }
        }

        let return_regs = self.get_regs()?;
        let result = return_regs.regs[0] as usize;

        self.set_regs(&backup_regs)?;

        debug!(
            "callFunction: Calling function {:#x} returned {:#x}.",
            function_address, result
        );

        Ok(result)
    }
}

impl Drop for RemoteProcess {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}

fn ptrace_getregset(pid: Pid) -> Result<PtRegs> {
    let mut regs: PtRegs = unsafe { mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: &mut regs as *mut _ as *mut c_void,
        iov_len: size_of::<PtRegs>(),
    };
    Errno::result(unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGSET,
            pid.as_raw(),
            NT_PRSTATUS,
            &mut iov as *mut _,
        )
    })
    .context("PTRACE_GETREGSET failed")?;
    Ok(regs)
}

fn ptrace_setregset(pid: Pid, regs: &PtRegs) -> Result<()> {
    let iov = libc::iovec {
        iov_base: regs as *const _ as *mut c_void,
        iov_len: size_of::<PtRegs>(),
    };
    Errno::result(unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGSET,
            pid.as_raw(),
            NT_PRSTATUS,
            &iov as *const _,
        )
    })
    .context("PTRACE_SETREGSET failed")?;
    Ok(())
}
