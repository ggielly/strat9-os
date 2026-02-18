//! Test module for the scheduler
//!
//! Contains simple test tasks to verify that the scheduler is working correctly.
//! Includes both a cooperative task and a busy-loop task to demonstrate
//! preemptive scheduling.

use crate::process::{add_task, Task, TaskPriority};

/// Creates and adds test tasks to the scheduler
pub fn create_test_tasks() {
    // Cooperative test task (yields voluntarily)
    let test_task = Task::new_kernel_task(test_task_main, "test-coop", TaskPriority::Normal)
        .expect("Failed to create cooperative test task");
    add_task(test_task);

    // Busy-loop test task (never yields — relies on preemption)
    let busy_task = Task::new_kernel_task(busy_task_main, "test-busy", TaskPriority::Normal)
        .expect("Failed to create busy test task");
    add_task(busy_task);
}

/// Main function for the cooperative test task
extern "C" fn test_task_main() -> ! {
    crate::serial_println!("[test-coop] Cooperative test task started!");
    let mut counter = 0u64;

    // Run for a limited number of iterations to allow keyboard input
    let max_iterations = 100_000; // Adjust this value as needed

    loop {
        if counter % 1000 == 0 {
            crate::serial_println!("[test-coop] iteration {}", counter);
        }

        // Check if we've reached our iteration limit
        if counter >= max_iterations {
            crate::serial_println!("[test-coop] Iteration limit reached, exiting task");
            break;
        }

        counter += 1;

        // Cooperatively yield to other tasks
        crate::process::yield_task();
    }

    // Exit the current task to allow keyboard input
    crate::process::scheduler::exit_current_task();
}

/// Main function for the busy-loop test task (never yields).
///
/// If preemption is working, this task will be forcibly interrupted by the
/// timer and other tasks will still get CPU time. If preemption is broken,
/// this task will starve everything else.
///
/// This task now runs for approximately 3-5 seconds then exits to allow keyboard input.
extern "C" fn busy_task_main() -> ! {
    crate::serial_println!("[test-busy] Busy-loop test task started (never yields)!");
    let mut counter = 0u64;

    // Assuming ~100 iterations per millisecond with preemption at 100Hz
    // So 300,000 to 500,000 iterations = 3-5 seconds
    let max_iterations = 400_000; // Adjust this value as needed

    loop {
        if counter % 5_000_000 == 0 {
            crate::serial_println!("[test-busy] iteration {} (preemption works!)", counter);
        }

        // Check if we've reached our time limit
        if counter >= max_iterations {
            crate::serial_println!("[test-busy] Time limit reached, exiting task");
            break;
        }

        counter += 1;
        // No yield! Timer preemption is the only way other tasks run.
    }

    // Exit the current task to allow keyboard input
    crate::process::scheduler::exit_current_task();
}
