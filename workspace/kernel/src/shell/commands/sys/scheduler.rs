use crate::{
    process::{
        configure_class_table, log_scheduler_state, reset_scheduler_metrics, scheduler_class_table,
        scheduler_metrics_snapshot, scheduler_verbose_enabled, set_scheduler_verbose,
    },
    shell::ShellError,
    shell_println,
};
use alloc::string::String;

fn parse_class(s: &str) -> Option<crate::process::sched::SchedClassId> {
    crate::process::sched::SchedClassId::parse(s)
}

fn parse_kind(s: &str) -> Option<crate::process::sched::SchedPolicyKind> {
    crate::process::sched::SchedPolicyKind::parse(s)
}

fn print_table(table: crate::process::sched::SchedClassTable) {
    let pick = table.pick_order();
    let steal = table.steal_order();
    shell_println!(
        "class table: pick=[{},{},{}] steal=[{},{}]",
        pick[0].as_str(),
        pick[1].as_str(),
        pick[2].as_str(),
        steal[0].as_str(),
        steal[1].as_str()
    );
    for entry in table.entries().iter() {
        shell_println!(
            "  class={} name={} rank={}",
            entry.id.as_str(),
            entry.name,
            entry.rank
        );
    }
    for kind in [
        crate::process::sched::SchedPolicyKind::Fair,
        crate::process::sched::SchedPolicyKind::RealTime,
        crate::process::sched::SchedPolicyKind::Idle,
    ] {
        let class = table.policy_class(kind);
        shell_println!("  policy_map: {}->{}", kind.as_str(), class.as_str());
    }
}

/// scheduler debug on|off|dump | class | metrics [reset]
pub fn cmd_scheduler(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: scheduler <debug|class|policy|metrics> ...");
        return Err(ShellError::InvalidArguments);
    }

    match args[0].as_str() {
        "debug" => {
            if args.len() != 2 {
                shell_println!("Usage: scheduler debug on|off|dump");
                return Err(ShellError::InvalidArguments);
            }
            match args[1].as_str() {
                "on" => {
                    set_scheduler_verbose(true);
                    shell_println!("scheduler debug: on");
                    Ok(())
                }
                "off" => {
                    set_scheduler_verbose(false);
                    shell_println!("scheduler debug: off");
                    Ok(())
                }
                "dump" => {
                    let table = scheduler_class_table();
                    shell_println!(
                        "scheduler debug: {}",
                        if scheduler_verbose_enabled() {
                            "on"
                        } else {
                            "off"
                        }
                    );
                    print_table(table);
                    log_scheduler_state("shell");
                    Ok(())
                }
                _ => {
                    shell_println!("Usage: scheduler debug on|off|dump");
                    Err(ShellError::InvalidArguments)
                }
            }
        }
        "class" => {
            if args.len() == 1 {
                print_table(scheduler_class_table());
                return Ok(());
            }
            if args.len() >= 3 && args[1].as_str() == "order" && args[2].as_str() == "set" {
                if args.len() != 6 {
                    shell_println!("Usage: scheduler class order set <c1> <c2> <c3>");
                    return Err(ShellError::InvalidArguments);
                }
                let c1 = parse_class(args[3].as_str()).ok_or(ShellError::InvalidArguments)?;
                let c2 = parse_class(args[4].as_str()).ok_or(ShellError::InvalidArguments)?;
                let c3 = parse_class(args[5].as_str()).ok_or(ShellError::InvalidArguments)?;
                let mut table = scheduler_class_table();
                if !table.set_pick_order([c1, c2, c3]) || !configure_class_table(table) {
                    shell_println!("scheduler: rejected class order");
                    return Err(ShellError::InvalidArguments);
                }
                print_table(table);
                return Ok(());
            }
            if args.len() >= 3 && args[1].as_str() == "steal" && args[2].as_str() == "set" {
                if args.len() != 5 {
                    shell_println!("Usage: scheduler class steal set <c1> <c2>");
                    return Err(ShellError::InvalidArguments);
                }
                let c1 = parse_class(args[3].as_str()).ok_or(ShellError::InvalidArguments)?;
                let c2 = parse_class(args[4].as_str()).ok_or(ShellError::InvalidArguments)?;
                let mut table = scheduler_class_table();
                if !table.set_steal_order([c1, c2]) || !configure_class_table(table) {
                    shell_println!("scheduler: rejected steal order");
                    return Err(ShellError::InvalidArguments);
                }
                print_table(table);
                return Ok(());
            }
            shell_println!("Usage: scheduler class [order set <c1> <c2> <c3> | steal set <c1> <c2>]");
            Err(ShellError::InvalidArguments)
        }
        "policy" => {
            if args.len() == 1 || (args.len() == 2 && args[1].as_str() == "map") {
                print_table(scheduler_class_table());
                return Ok(());
            }
            if args.len() >= 3 && args[1].as_str() == "map" && args[2].as_str() == "show" {
                print_table(scheduler_class_table());
                return Ok(());
            }
            if args.len() >= 3 && args[1].as_str() == "map" && args[2].as_str() == "set" {
                if args.len() != 5 {
                    shell_println!("Usage: scheduler policy map set <fair|rt|idle> <rt|fair|idle>");
                    return Err(ShellError::InvalidArguments);
                }
                let kind = parse_kind(args[3].as_str()).ok_or(ShellError::InvalidArguments)?;
                let class = parse_class(args[4].as_str()).ok_or(ShellError::InvalidArguments)?;
                let mut table = scheduler_class_table();
                if !table.set_policy_class(kind, class) || !configure_class_table(table) {
                    shell_println!("scheduler: rejected policy map");
                    return Err(ShellError::InvalidArguments);
                }
                print_table(table);
                return Ok(());
            }
            shell_println!("Usage: scheduler policy map <show|set <fair|rt|idle> <rt|fair|idle>>");
            Err(ShellError::InvalidArguments)
        }
        "metrics" => {
            if args.len() == 2 && args[1].as_str() == "reset" {
                reset_scheduler_metrics();
                shell_println!("scheduler metrics: reset");
                return Ok(());
            }
            if args.len() != 1 {
                shell_println!("Usage: scheduler metrics [reset]");
                return Err(ShellError::InvalidArguments);
            }
            let m = scheduler_metrics_snapshot();
            for i in 0..m.cpu_count.min(crate::arch::x86_64::percpu::MAX_CPUS) {
                shell_println!(
                    "cpu{} rt={} fair={} idle={} sw={} pre={} st+={} st-={}",
                    i,
                    m.rt_runtime_ticks[i],
                    m.fair_runtime_ticks[i],
                    m.idle_runtime_ticks[i],
                    m.switch_count[i],
                    m.preempt_count[i],
                    m.steal_in_count[i],
                    m.steal_out_count[i]
                );
            }
            Ok(())
        }
        _ => {
            shell_println!("Usage: scheduler <debug|class|policy|metrics> ...");
            Err(ShellError::InvalidArguments)
        }
    }
}
