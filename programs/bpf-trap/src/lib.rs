#![cfg_attr(any(target_arch = "bpf", target_os = "solana"), no_std)]
#![cfg_attr(
    any(target_arch = "bpf", target_os = "solana"),
    feature(abort_immediate)
)]

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
#[unsafe(no_mangle)]
pub fn entrypoint(input: *const u64) -> u64 {
    let value = unsafe { core::ptr::read_volatile(input) };
    if value == 0 {
        core::process::abort_immediate();
    }
    value
}

#[cfg(test)]
mod tests {
    use harness::{Instruction, InstructionError, Mollusk, Pubkey};

    #[test]
    fn explicit_trap_aborts() {
        let program_id: Pubkey = [2u8; 32].into();
        let mollusk = Mollusk::new(&program_id, &harness::program_elf());
        // With no accounts, the first word of the serialized input is zero.
        let instruction = Instruction::new_with_bytes(program_id, &[], vec![]);

        let result = mollusk.process_instruction(&instruction, &[]);

        assert_eq!(
            result.raw_result,
            Err(InstructionError::ProgramFailedToComplete)
        );
    }
}
