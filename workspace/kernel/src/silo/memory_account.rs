//! Allocation-free quota accounting, independent of the silo registry lock.

use crate::{sync::SpinLock, syscall::error::SyscallError};

pub(crate) struct SiloMemoryAccount {
    budget: SpinLock<MemoryBudget>,
}

impl core::fmt::Debug for SiloMemoryAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let budget = self.budget.lock();
        f.debug_struct("SiloMemoryAccount")
            .field("used", &budget.used)
            .field("max", &budget.max)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_reservation_does_not_change_usage() {
        let account = SiloMemoryAccount::new(8192);
        account.charge(4096).unwrap();
        assert!(matches!(
            account.charge(4097),
            Err(SyscallError::OutOfMemory)
        ));
        assert_eq!(account.used(), 4096);
        account.release(4096);
        account.charge(8192).unwrap();
        assert_eq!(account.used(), 8192);
    }

    #[test]
    fn limit_update_cannot_undercut_live_reservations() {
        let account = SiloMemoryAccount::new(0);
        account.charge(8192).unwrap();
        assert!(account.set_max(4096).is_err());
        assert_eq!(account.used(), 8192);
        account.release(4096);
        account.set_max(4096).unwrap();
        assert!(account.charge(1).is_err());
    }

    #[test]
    fn unlimited_budget_still_checks_overflow() {
        let account = SiloMemoryAccount::new(0);
        account.charge(u64::MAX).unwrap();
        assert!(account.charge(1).is_err());
        assert_eq!(account.used(), u64::MAX);
    }
}

#[derive(Debug)]
struct MemoryBudget {
    used: u64,
    max: u64,
}

impl SiloMemoryAccount {
    pub(crate) fn new(max: u64) -> Self {
        Self {
            budget: SpinLock::new(MemoryBudget { used: 0, max }),
        }
    }

    pub(crate) fn charge(&self, bytes: u64) -> Result<(), SyscallError> {
        let mut budget = self.budget.lock();
        let next = budget
            .used
            .checked_add(bytes)
            .ok_or(SyscallError::OutOfMemory)?;
        if budget.max != 0 && next > budget.max {
            return Err(SyscallError::OutOfMemory);
        }
        budget.used = next;
        Ok(())
    }

    pub(crate) fn release(&self, bytes: u64) {
        let mut budget = self.budget.lock();
        budget.used = budget.used.saturating_sub(bytes);
    }

    pub(crate) fn used(&self) -> u64 {
        self.budget.lock().used
    }

    pub(crate) fn set_max(&self, max: u64) -> Result<(), SyscallError> {
        let mut budget = self.budget.lock();
        if max != 0 && budget.used > max {
            return Err(SyscallError::InvalidArgument);
        }
        budget.max = max;
        Ok(())
    }
}
