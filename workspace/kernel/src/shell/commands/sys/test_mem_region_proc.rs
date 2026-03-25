use super::*;

/// Run multi-process public MemoryRegion test routine.
pub fn cmd_test_mem_region_proc(args: &[String]) -> Result<(), ShellError> {
    super::cmd_test_mem_region_proc_impl(args)
}