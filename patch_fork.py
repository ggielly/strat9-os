import re

with open('workspace/kernel/src/syscall/fork.rs', 'r') as f:
    content = f.read()

replacement = """
        name: "fork-child",
        process: alloc::sync::Arc::new(crate::process::process::Process {
            pid,
            address_space: crate::process::task::SyncUnsafeCell::new(child_as),
            fd_table: crate::process::task::SyncUnsafeCell::new(parent_fd),
            capabilities: crate::process::task::SyncUnsafeCell::new(parent_caps),
            signal_actions: crate::process::task::SyncUnsafeCell::new(parent_actions),
            brk: core::sync::atomic::AtomicU64::new(parent.process.brk.load(core::sync::atomic::Ordering::Relaxed)),
            mmap_hint: core::sync::atomic::AtomicU64::new(parent.process.mmap_hint.load(core::sync::atomic::Ordering::Relaxed)),
            cwd: crate::process::task::SyncUnsafeCell::new(unsafe { &*parent.process.cwd.get() }.clone()),
            umask: core::sync::atomic::AtomicU32::new(parent.process.umask.load(core::sync::atomic::Ordering::Relaxed)),
        }),
        // POSIX: pending signals are NOT inherited by the child.
"""

content = re.sub(r'        name: "fork-child",\n        capabilities: SyncUnsafeCell::new\(parent_caps\),\n        address_space: SyncUnsafeCell::new\(child_as\),\n        fd_table: SyncUnsafeCell::new\(parent_fd\),\n        // POSIX: pending signals are NOT inherited by the child.', replacement, content)

content = re.sub(r'        // POSIX: signal actions \(handlers\) ARE inherited\.\n        // TODO: support SA_NOCLDWAIT and other complex signal flags\.\n        signal_actions: SyncUnsafeCell::new\(parent_actions\),\n', '', content)

content = re.sub(r'        brk: AtomicU64::new\(parent\.process\.brk\.load\(Ordering::Relaxed\)\),\n        mmap_hint: AtomicU64::new\(parent\.process\.mmap_hint\.load\(Ordering::Relaxed\)\),\n', '', content)

content = re.sub(r'        cwd: SyncUnsafeCell::new\(unsafe \{ &\*parent\.process\.cwd\.get\(\) \}\.clone\(\)\),\n        umask: AtomicU32::new\(parent\.process\.umask\.load\(Ordering::Relaxed\)\),\n', '', content)

with open('workspace/kernel/src/syscall/fork.rs', 'w') as f:
    f.write(content)
