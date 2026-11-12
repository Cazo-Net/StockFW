//! StockFW 2.0.0 eBPF Common Types
//! Shared definitions between user-space loader and kernel-space eBPF programs.

#![no_std]

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum RuleAction {
    Allow = 0,
    Block = 1,
    Monitor = 2,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct IpBlockKey {
    pub ipv4_addr: u32,
    pub prefix_len: u32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct PacketContext {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub protocol: u8,
    pub action: u8,
}
