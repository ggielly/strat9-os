import re

def patch_file(filename):
    with open(filename, 'r') as f:
        content = f.read()

    replacement = """
        name: "test-user-ring3",
        process: alloc::sync::Arc::new(crate::process::process::Process::new(pid, user_as)),
        pending_signals: SyncUnsafeCell::new(super::signal::SignalSet::new()),
"""

    content = re.sub(r'        name: "test-user-ring3",\n        capabilities: SyncUnsafeCell::new\(CapabilityTable::new\(\)\),\n        address_space: SyncUnsafeCell::new\(user_as\),\n        fd_table: SyncUnsafeCell::new\(crate::vfs::FileDescriptorTable::new\(\)\),\n        pending_signals: SyncUnsafeCell::new\(super::signal::SignalSet::new\(\)\),', replacement, content)

    content = re.sub(r'        signal_actions: SyncUnsafeCell::new\(\[super::signal::SigAction::Default; 64\]\),\n', '', content)
    content = re.sub(r'        brk: core::sync::atomic::AtomicU64::new\(0\),\n        mmap_hint: core::sync::atomic::AtomicU64::new\(0x0000_0000_6000_0000\),\n', '', content)
    content = re.sub(r'        cwd: SyncUnsafeCell::new\(alloc::string::String::from\("/"\)\),\n        umask: core::sync::atomic::AtomicU32::new\(0o022\),\n', '', content)

    with open(filename, 'w') as f:
        f.write(content)

patch_file('workspace/kernel/src/process/usertest.rs')
patch_file('workspace/kernel/src/process/fork_test.rs')
