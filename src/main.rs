mod injector;
mod proc_monitor;
mod ptrace_ext;

use std::os::fd::AsFd;
use std::os::unix::prelude::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, info, warn};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};

#[derive(Parser)]
#[command(name = "injector", about = "Android process injector")]
struct Args {
    /// 目标包名
    #[arg(short, long)]
    package: String,

    /// 要注入的 so 路径
    #[arg(short, long)]
    lib: String,

    /// 等待进程就绪的超时时间（秒）
    #[arg(short, long, default_value_t = 5)]
    timeout: u64,

    /// 使用 memfd_create + android_dlopen_ext 注入，绕过路径限制
    #[arg(long)]
    memfd: bool,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    info!("Waiting for {} to start...", args.package);

    proc_monitor::monitor_proc_start(|event| {
        debug!("proc_start: pid={} uid={} name={}", event.pid, event.uid, event.process_name);

        if event.process_name != args.package {
            return false;
        }

        info!("Target found: pid={} uid={} name={}", event.pid, event.uid, event.process_name);

        match wait_for_proc_ready(event.pid, Duration::from_secs(args.timeout)) {
            Ok(true) => {
                info!("pid {} ready, injecting...", event.pid);
                match injector::inject(event.pid, &args.lib, args.memfd) {
                    Ok(info) => info!("Injection succeeded! handle={:#x} base={:#x}", info.dl_handle, info.base_addr),
                    Err(e) => warn!("Injection failed: {e:#}"),
                }
            }
            Ok(false) => warn!("pid {} exited or timeout", event.pid),
            Err(e) => warn!("wait_for_proc_ready failed: {e:#}"),
        }

        true // 停止监听
    })
}

/// 等待进程初始化就绪
fn wait_for_proc_ready(pid: i32, timeout: Duration) -> Result<bool> {
    let proc_dir = format!("/proc/{pid}");

    if !Path::new(&proc_dir).exists() {
        return Ok(false);
    }

    let inotify = Inotify::init(InitFlags::IN_NONBLOCK).context("inotify_init failed")?;

    inotify
        .add_watch(proc_dir.as_str(), AddWatchFlags::IN_ALL_EVENTS)
        .context("inotify add_watch failed")?;

    let start = Instant::now();
    let mut poll_fds = [PollFd::new(inotify.as_fd(), PollFlags::POLLIN)];

    loop {
        if start.elapsed() >= timeout {
            return Ok(false);
        }

        let remaining = timeout.saturating_sub(start.elapsed());
        let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;

        let timeout = PollTimeout::try_from(timeout_ms).context("Failed to convert timeout to PollTimeout")?;
        match poll(&mut poll_fds, timeout) {
            Ok(0) => return Ok(false),
            Err(e) => return Err(e).context("poll failed"),
            _ => {},
        }

        let events = inotify.read_events().context("inotify read failed")?;

        for event in &events {
            let name = match &event.name {
                Some(n) => n.as_bytes(),
                None => continue,
            };

            // skip fd event (0x6466 = "fd" little-endian)
            if name.len() >= 2 && u16::from_le_bytes([name[0], name[1]]) == 0x6466 {
                continue;
            }

            // skip timerslack event (0x656d6974 = "time" little-endian)
            if name.len() >= 4 && u32::from_le_bytes([name[0], name[1], name[2], name[3]]) == 0x656d6974 {
                continue;
            }

            return Ok(true);
        }
    }
}
