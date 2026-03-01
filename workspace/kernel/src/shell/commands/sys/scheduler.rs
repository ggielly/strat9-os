use crate::{
    process::{
        configure_class_table, log_scheduler_state, reset_scheduler_metrics, scheduler_class_table,
        scheduler_metrics_snapshot, scheduler_state_snapshot, scheduler_verbose_enabled,
        set_scheduler_verbose,
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

fn print_table_kv(table: crate::process::sched::SchedClassTable) {
    let pick = table.pick_order();
    let steal = table.steal_order();
    shell_println!("scheduler.pick.0={}", pick[0].as_str());
    shell_println!("scheduler.pick.1={}", pick[1].as_str());
    shell_println!("scheduler.pick.2={}", pick[2].as_str());
    shell_println!("scheduler.steal.0={}", steal[0].as_str());
    shell_println!("scheduler.steal.1={}", steal[1].as_str());
    for entry in table.entries().iter() {
        shell_println!("scheduler.class.{}.name={}", entry.id.as_str(), entry.name);
        shell_println!("scheduler.class.{}.rank={}", entry.id.as_str(), entry.rank);
    }
    for kind in [
        crate::process::sched::SchedPolicyKind::Fair,
        crate::process::sched::SchedPolicyKind::RealTime,
        crate::process::sched::SchedPolicyKind::Idle,
    ] {
        let class = table.policy_class(kind);
        shell_println!("scheduler.policy_map.{}={}", kind.as_str(), class.as_str());
    }
}

fn print_metrics_kv(m: crate::process::SchedulerMetricsSnapshot) {
    shell_println!("scheduler.cpu_count={}", m.cpu_count);
    for i in 0..m.cpu_count.min(crate::arch::x86_64::percpu::MAX_CPUS) {
        shell_println!("scheduler.cpu.{}.rt={}", i, m.rt_runtime_ticks[i]);
        shell_println!("scheduler.cpu.{}.fair={}", i, m.fair_runtime_ticks[i]);
        shell_println!("scheduler.cpu.{}.idle={}", i, m.idle_runtime_ticks[i]);
        shell_println!("scheduler.cpu.{}.switch={}", i, m.switch_count[i]);
        shell_println!("scheduler.cpu.{}.preempt={}", i, m.preempt_count[i]);
        shell_println!("scheduler.cpu.{}.steal_in={}", i, m.steal_in_count[i]);
        shell_println!("scheduler.cpu.{}.steal_out={}", i, m.steal_out_count[i]);
        shell_println!(
            "scheduler.cpu.{}.try_lock_fail={}",
            i,
            m.try_lock_fail_count[i]
        );
    }
}

fn wants_kv(args: &[String], idx: usize) -> bool {
    args.get(idx).map(|s| s.as_str()) == Some("kv")
}

/// scheduler debug on|off|dump | class [kv] | policy map show [kv] | metrics [reset|kv] | dump [kv]
pub fn cmd_scheduler(args: &[String]) -> Result<(), ShellError> {
    if args.is_empty() {
        shell_println!("Usage: scheduler <debug|class|policy|metrics|dump> ...");
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
            if args.len() == 1 || (args.len() == 2 && args[1].as_str() == "kv") {
                let table = scheduler_class_table();
                if args.len() == 2 {
                    print_table_kv(table);
                } else {
                    print_table(table);
                }
                return Ok(());
            }
            if args.len() >= 3 && args[1].as_str() == "order" && args[2].as_str() == "set" {
                if args.len() != 6 && args.len() != 7 {
                    shell_println!("Usage: scheduler class order set <c1> <c2> <c3> [kv]");
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
                if args.len() == 7 {
                    if !wants_kv(args, 6) {
                        shell_println!("Usage: scheduler class order set <c1> <c2> <c3> [kv]");
                        return Err(ShellError::InvalidArguments);
                    }
                    print_table_kv(table);
                } else {
                    print_table(table);
                }
                return Ok(());
            }
            if args.len() >= 3 && args[1].as_str() == "steal" && args[2].as_str() == "set" {
                if args.len() != 5 && args.len() != 6 {
                    shell_println!("Usage: scheduler class steal set <c1> <c2> [kv]");
                    return Err(ShellError::InvalidArguments);
                }
                let c1 = parse_class(args[3].as_str()).ok_or(ShellError::InvalidArguments)?;
                let c2 = parse_class(args[4].as_str()).ok_or(ShellError::InvalidArguments)?;
                let mut table = scheduler_class_table();
                if !table.set_steal_order([c1, c2]) || !configure_class_table(table) {
                    shell_println!("scheduler: rejected steal order");
                    return Err(ShellError::InvalidArguments);
                }
                if args.len() == 6 {
                    if !wants_kv(args, 5) {
                        shell_println!("Usage: scheduler class steal set <c1> <c2> [kv]");
                        return Err(ShellError::InvalidArguments);
                    }
                    print_table_kv(table);
                } else {
                    print_table(table);
                }
                return Ok(());
            }
            shell_println!(
                "Usage: scheduler class [kv | order set <c1> <c2> <c3> [kv] | steal set <c1> <c2> [kv]]"
            );
            Err(ShellError::InvalidArguments)
        }
        "policy" => {
            if args.len() == 1 || (args.len() == 2 && args[1].as_str() == "map") {
                print_table(scheduler_class_table());
                return Ok(());
            }
            if args.len() >= 3 && args[1].as_str() == "map" && args[2].as_str() == "show" {
                let table = scheduler_class_table();
                if args.len() == 4 {
                    if args[3].as_str() != "kv" {
                        shell_println!("Usage: scheduler policy map show [kv]");
                        return Err(ShellError::InvalidArguments);
                    }
                    print_table_kv(table);
                } else if args.len() == 3 {
                    print_table(table);
                } else {
                    shell_println!("Usage: scheduler policy map show [kv]");
                    return Err(ShellError::InvalidArguments);
                }
                return Ok(());
            }
            if args.len() >= 3 && args[1].as_str() == "map" && args[2].as_str() == "set" {
                if args.len() != 5 && args.len() != 6 {
                    shell_println!(
                        "Usage: scheduler policy map set <fair|rt|idle> <rt|fair|idle> [kv]"
                    );
                    return Err(ShellError::InvalidArguments);
                }
                let kind = parse_kind(args[3].as_str()).ok_or(ShellError::InvalidArguments)?;
                let class = parse_class(args[4].as_str()).ok_or(ShellError::InvalidArguments)?;
                let mut table = scheduler_class_table();
                if !table.set_policy_class(kind, class) || !configure_class_table(table) {
                    shell_println!("scheduler: rejected policy map");
                    return Err(ShellError::InvalidArguments);
                }
                if args.len() == 6 {
                    if args[5].as_str() != "kv" {
                        shell_println!(
                            "Usage: scheduler policy map set <fair|rt|idle> <rt|fair|idle> [kv]"
                        );
                        return Err(ShellError::InvalidArguments);
                    }
                    print_table_kv(table);
                } else {
                    print_table(table);
                }
                return Ok(());
            }
            shell_println!(
                "Usage: scheduler policy map <show [kv] | set <fair|rt|idle> <rt|fair|idle> [kv]>"
            );
            Err(ShellError::InvalidArguments)
        }
        "metrics" => {
            if args.len() == 2 && args[1].as_str() == "reset" {
                reset_scheduler_metrics();
                shell_println!("scheduler metrics: reset");
                return Ok(());
            }
            if args.len() > 2 || (args.len() == 2 && args[1].as_str() != "kv") {
                shell_println!("Usage: scheduler metrics [reset|kv]");
                return Err(ShellError::InvalidArguments);
            }
            let m = scheduler_metrics_snapshot();
            if args.len() == 2 && args[1].as_str() == "kv" {
                print_metrics_kv(m);
                return Ok(());
            }
            for i in 0..m.cpu_count.min(crate::arch::x86_64::percpu::MAX_CPUS) {
                shell_println!(
                    "cpu{} rt={} fair={} idle={} sw={} pre={} st+={} st-={} tlm={}",
                    i,
                    m.rt_runtime_ticks[i],
                    m.fair_runtime_ticks[i],
                    m.idle_runtime_ticks[i],
                    m.switch_count[i],
                    m.preempt_count[i],
                    m.steal_in_count[i],
                    m.steal_out_count[i],
                    m.try_lock_fail_count[i]
                );
            }
            Ok(())
        }
        "dump" => {
            let kv = args.len() == 2 && args[1].as_str() == "kv";
            if args.len() > 2 || (args.len() == 2 && !kv) {
                shell_println!("Usage: scheduler dump [kv]");
                return Err(ShellError::InvalidArguments);
            }
            let s = scheduler_state_snapshot();
            if kv {
                shell_println!("scheduler.initialized={}", if s.initialized { 1 } else { 0 });
                shell_println!("scheduler.boot_phase={}", s.boot_phase);
                shell_println!("scheduler.cpu_count={}", s.cpu_count);
                shell_println!("scheduler.pick.0={}", s.pick_order[0].as_str());
                shell_println!("scheduler.pick.1={}", s.pick_order[1].as_str());
                shell_println!("scheduler.pick.2={}", s.pick_order[2].as_str());
                shell_println!("scheduler.steal.0={}", s.steal_order[0].as_str());
                shell_println!("scheduler.steal.1={}", s.steal_order[1].as_str());
                shell_println!("scheduler.blocked={}", s.blocked_tasks);
                for i in 0..s.cpu_count.min(crate::arch::x86_64::percpu::MAX_CPUS) {
                    shell_println!("scheduler.cpu.{}.current={}", i, s.current_task[i]);
                    shell_println!("scheduler.cpu.{}.rq_rt={}", i, s.rq_rt[i]);
                    shell_println!("scheduler.cpu.{}.rq_fair={}", i, s.rq_fair[i]);
                    shell_println!("scheduler.cpu.{}.rq_idle={}", i, s.rq_idle[i]);
                    shell_println!(
                        "scheduler.cpu.{}.need_resched={}",
                        i,
                        if s.need_resched[i] { 1 } else { 0 }
                    );
                }
            } else {
                shell_println!(
                    "scheduler dump: initialized={} phase={} cpus={} blocked={} pick=[{},{},{}] steal=[{},{}]",
                    s.initialized,
                    s.boot_phase,
                    s.cpu_count,
                    s.blocked_tasks,
                    s.pick_order[0].as_str(),
                    s.pick_order[1].as_str(),
                    s.pick_order[2].as_str(),
                    s.steal_order[0].as_str(),
                    s.steal_order[1].as_str()
                );
                for i in 0..s.cpu_count.min(crate::arch::x86_64::percpu::MAX_CPUS) {
                    shell_println!(
                        "  cpu{} current={} rq_rt={} rq_fair={} rq_idle={} need_resched={}",
                        i,
                        s.current_task[i],
                        s.rq_rt[i],
                        s.rq_fair[i],
                        s.rq_idle[i],
                        s.need_resched[i]
                    );
                }
            }
            Ok(())
        }
        _ => {
            shell_println!("Usage: scheduler <debug|class|policy|metrics|dump> ...");
            Err(ShellError::InvalidArguments)
        }
    }
}
