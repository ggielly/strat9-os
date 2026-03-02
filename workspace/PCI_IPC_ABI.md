# PCI IPC ABI (Strat9)

ABI pour l'enumeration PCI et l'acces a la config PCI depuis `strate-bus`.

## Syscalls

- `SYS_PCI_ENUM` (`240`)
  - args: `criteria_ptr`, `out_ptr`, `max_entries`
  - retour: nombre d'entrees ecrites
- `SYS_PCI_CFG_READ` (`241`)
  - args: `address_ptr`, `offset`, `width`
  - retour: valeur (`u32`) dans `rax`
- `SYS_PCI_CFG_WRITE` (`242`)
  - args: `address_ptr`, `offset`, `width`, `value`
  - retour: `0`

## Structures

- `PciAddress { bus, device, function }`
- `PciProbeCriteria { match_flags, vendor_id, device_id, class_code, subclass, prog_if }`
- `PciDeviceInfo { address, vendor_id, device_id, class_code, subclass, prog_if, revision, header_type, interrupt_line, interrupt_pin }`

## Match flags

- `PCI_MATCH_VENDOR_ID = 1 << 0`
- `PCI_MATCH_DEVICE_ID = 1 << 1`
- `PCI_MATCH_CLASS_CODE = 1 << 2`
- `PCI_MATCH_SUBCLASS = 1 << 3`
- `PCI_MATCH_PROG_IF = 1 << 4`
