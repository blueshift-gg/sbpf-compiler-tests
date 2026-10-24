#![cfg_attr(any(target_arch = "bpf", target_os = "solana"), no_std)]
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
mod program {
    use core::sync::atomic::{AtomicU64, Ordering};

    #[unsafe(no_mangle)]
    extern "C" fn entrypoint(input: *mut u8) -> u64 {
        let data = unsafe { input.add(16) };
        let a = unsafe { &*data.cast::<AtomicU64>() };
        let b = unsafe { &*data.add(8).cast::<AtomicU64>() };

        let received = a.load(Ordering::Acquire);
        let expected = received.wrapping_add(1);
        b.store(expected, Ordering::Release);

        // A fresh acquire load must observe the release store above.
        let echoed = b.load(Ordering::Acquire);

        if echoed == expected {
            0x0
        } else {
            0x1
        }
    }
}

#[cfg(test)]
mod tests {
    use harness::{Instruction, Mollusk, Pubkey};

    #[test]
    fn test_atomic_load_store_roundtrip() {
        let program_id: Pubkey = [2u8; 32].into();
        let mollusk = Mollusk::new(&program_id, &harness::program_elf());

        for value in [0x1, 0x7, 0xABCD_CDEF, u64::MAX] {
            let mut data = value.to_le_bytes().to_vec();
            data.extend_from_slice(&[0u8; 8]);
            let instruction = Instruction {
                program_id,
                accounts: vec![],
                data,
            };
            let result = mollusk.process_instruction(&instruction, &[]);
            assert_eq!(result.raw_result, Ok(()), "value: {value:#x}");
        }
    }
}
