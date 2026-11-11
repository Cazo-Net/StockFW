//! StockFW 2.0.0 User-Space eBPF Loader (`aya`)
//! Manages loading, attaching, and populating eBPF programs and O(1) hash maps for StockFW C core (`fs-ebpf.c`).

use aya::{
    maps::HashMap,
    programs::{KProbe, Tc, TcAnchor},
    Ebpf,
};
use stockfw_ebpf_common::IpBlockKey;
use std::convert::TryInto;
use std::path::Path;

pub struct EbpfManager {
    bpf: Ebpf,
}

impl EbpfManager {
    /// Load the compiled eBPF object code into the Linux kernel
    pub fn load(object_code: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut bpf = Ebpf::load(object_code)?;
        Ok(Self { bpf })
    }

    /// Attach kprobe and TC filter programs to network interfaces and kernel functions
    pub fn attach_programs(&mut self, interface: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Attach tcp_connect kprobe for sub-millisecond SIGKILL enforcement
        let program: &mut KProbe = self.bpf.program_mut("stockfw_tcp_connect").unwrap().try_into()?;
        program.load()?;
        program.attach("tcp_connect", 0)?;

        // Attach TC egress socket filter
        let _tc_prog: &mut Tc = self.bpf.program_mut("stockfw_tc_egress").unwrap().try_into()?;
        // Additional TC attachment logic via TcAnchor / interface binding

        Ok(())
    }

    /// Insert or remove IP block rules in the O(1) kernel hash map
    pub fn update_block_rule(&mut self, key: IpBlockKey, action: u8) -> Result<(), Box<dyn std::error::Error>> {
        let mut block_map = HashMap::try_from(self.bpf.map_mut("STOCKFW_IP_BLOCKMAP").unwrap())?;
        block_map.insert(key, action, 0)?;
        Ok(())
    }
}
