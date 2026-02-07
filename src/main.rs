mod proc_monitor;

fn main() {
    println!("Starting proc monitor...");
    proc_monitor::monitor_proc_start(|event| {
        println!("proc_start: user={} pid={} uid={} name={}", event.user, event.pid, event.uid, event.process_name);
    }).expect("Failed to start proc monitor");
}
