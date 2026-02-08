pub mod maps;
pub mod solist;

use crate::ptrace_ext::RemoteProcess;
use anyhow::Result;

pub struct HideTarget<'a> {
    pub proc: &'a RemoteProcess,
    pub pid: i32,
    pub base_addr: usize,
    pub maps_search_name: &'a str,
}

pub trait Hider {
    fn name(&self) -> &'static str;
    fn apply(&self, target: &HideTarget) -> Result<bool>;
}
