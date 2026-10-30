//! pToken program snapshot with host-side Mollusk tests.
#![cfg_attr(any(target_arch = "bpf", target_os = "solana"), no_std)]
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
mod entrypoint;
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
mod processor;
