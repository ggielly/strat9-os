#Requires -Version 5.1
<#
.SYNOPSIS
    Build strat9-os under Windows and create bootable ISO.
.DESCRIPTION
    Compiles the kernel and all userland components, sets up Limine,
    assembles the ISO, and optionally runs it in QEMU.
.PARAMETER Profile
    Build profile: debug (default), dev-opt, or release
.PARAMETER Run
    Launch QEMU after build
.PARAMETER RunVMware
    Launch VMware after build instead of QEMU
.PARAMETER Tests
    Include test binaries in the ISO
#>

param(
    [ValidateSet("debug", "dev-opt", "release")]
    [string]$Profile = "release",
    [switch]$Run,
    [switch]$RunVMware,
    [switch]$Tests
)

$ErrorActionPreference = "Continue"
$WarningPreference = "Continue"
$RootDir = (Get-Item $PSScriptRoot).Parent.Parent.FullName
$BuildDir = Join-Path $RootDir "build"
$Target = "x86_64-unknown-none"
$CargoProfile = if ($Profile -eq "debug") { "" } else { "--profile $Profile" }
$ProfileDir = if ($Profile -eq "debug") { "debug" } elseif ($Profile -eq "release") { "release" } else { "dev-opt" }

function Step([string]$Name) {
    Write-Host "`n=== $Name ===" -ForegroundColor Cyan
}

function CargoBuild([string]$Cwd, [string[]]$ExtraArgs = @()) {
    $Args = @("build", "--target", $Target) + $CargoProfile.Split(" ") + $ExtraArgs
    Push-Location $Cwd
    try {
        & cargo $Args 2>&1 | ForEach-Object { Write-Host $_ }
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed in $Cwd" }
    } finally {
        Pop-Location
    }
}

# =========================================================================
# 1. Setup Limine
# =========================================================================
Step "1. Setting up Limine"
$LimineDir = Join-Path $BuildDir "limine"
if (-not (Test-Path "$LimineDir\limine-bios.sys")) {
    if (-not (Test-Path $LimineDir)) {
        New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
    }
    Write-Host "  Cloning Limine..."
    git clone https://github.com/limine-bootloader/limine.git `
        --branch=v8.x-binary --depth=1 $LimineDir 2>&1 | Out-Null
    if (Test-Path "$LimineDir\limine-bios.sys") {
        Write-Host "  Limine cloned successfully" -ForegroundColor Green
    } else {
        Write-Host "  ERROR: Limine clone failed" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  Limine already present" -ForegroundColor Yellow
}

# =========================================================================
# 2. Build kernel
# =========================================================================
Step "2. Building kernel ($Profile)"
CargoBuild (Join-Path $RootDir "workspace\kernel")

# =========================================================================
# 3. Build userland components
# =========================================================================
$Components = @(
    @{ Name = "strate-ext4";           Cwd = "workspace\components\strate-fs-ext4" }
    @{ Name = "strate-fs-ramfs";       Cwd = "workspace\components\strate-fs-ramfs" }
    @{ Name = "strate-init";           Cwd = "workspace\components\strate-init" }
    @{ Name = "strate-console-admin";  Cwd = "workspace\components\strate-console-admin" }
    @{ Name = "strate-net";            Cwd = "workspace\components\strate-net" }
    @{ Name = "strate-bus";            Cwd = "workspace\components\strate-bus" }
    @{ Name = "strate-wasm";           Cwd = "workspace\components\strate-wasm" }
    @{ Name = "strate-webrtc";         Cwd = "workspace\components\strate-webrtc" }
    @{ Name = "dhcp-client";           Cwd = "workspace\components\netutils\dhcp-client" }
    @{ Name = "ping";                  Cwd = "workspace\components\netutils\ping" }
    @{ Name = "telnetd";               Cwd = "workspace\components\netutils\telnetd" }
    @{ Name = "udp-tool";              Cwd = "workspace\components\netutils\udp-tool" }
    @{ Name = "strate-sshd";           Cwd = "workspace\components\strate-sshd" }
    @{ Name = "strate-web-admin";      Cwd = "workspace\components\strate-web-admin" }
)

if ($Tests) {
    $Components += @(
        @{ Name = "strate-silo-test";   Cwd = "workspace\components\strate-silo-test" }
        @{ Name = "strate-mem-test";    Cwd = "workspace\components\strate-mem-test" }
    )
}

$Skipped = @()
foreach ($Comp in $Components) {
    Write-Host "  Building $($Comp.Name)..." -NoNewline
    try {
        CargoBuild (Join-Path $RootDir $Comp.Cwd)
        Write-Host " OK" -ForegroundColor Green
    } catch {
        Write-Host " FAILED (skipping)" -ForegroundColor Red
        $Skipped += $Comp.Name
    }
}

if ($Skipped.Count -gt 0) {
    Write-Host "`n  Skipped components: $($Skipped -join ', ')" -ForegroundColor Yellow
}

# =========================================================================
# 4. Assemble ISO
# =========================================================================
Step "3. Assembling bootable ISO"

$IsoRoot = Join-Path $BuildDir "iso_root"
if (Test-Path $IsoRoot) { Remove-Item -Recurse -Force $IsoRoot }
New-Item -ItemType Directory -Path (Join-Path $IsoRoot "boot\limine") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $IsoRoot "initfs\bin") -Force | Out-Null

function Copy-Optional([string]$Src, [string]$Dst, [string]$Label) {
    if (Test-Path $Src) {
        Copy-Item $Src $Dst -Force
        Write-Host "  [OK] $Label" -ForegroundColor Green
    } else {
        Write-Host "  [SKIP] $Label (not found)" -ForegroundColor Yellow
    }
}

# Kernel ELF path
$KernelPath = Join-Path $RootDir "target\$Target\$ProfileDir\kernel"
Copy-Optional $KernelPath (Join-Path $IsoRoot "boot\kernel.elf") "Kernel ELF"

# Limine bootloader files
$LimineFiles = @("limine-bios.sys", "limine-bios-cd.bin", "limine-uefi-cd.bin")
foreach ($F in $LimineFiles) {
    $Src = Join-Path $LimineDir $F
    $Dst = Join-Path $IsoRoot "boot\limine\$F"
    if (Test-Path $Src) {
        Copy-Item $Src $Dst -Force
    }
}
Write-Host "  [OK] Limine bootloader files" -ForegroundColor Green

# limine.conf config
$ConfSrc = Join-Path $RootDir "limine.conf"
$ConfDst = Join-Path $IsoRoot "boot\limine\limine.conf"
Copy-Optional $ConfSrc $ConfDst "Limine config"

# Module paths
$Modules = @(
    @{ Src = "target\$Target\$ProfileDir\fs-ext4-strate";            Dst = "initfs/fs-ext4" }
    @{ Src = "target\$Target\$ProfileDir\fs-ext4-strate";            Dst = "initfs/fs-ext4-strate" }
    @{ Src = "target\$Target\$ProfileDir\strate-fs-ramfs";           Dst = "initfs/strate-fs-ramfs" }
    @{ Src = "target\$Target\$ProfileDir\strate-init";               Dst = "initfs/init" }
    @{ Src = "target\$Target\$ProfileDir\console-admin";             Dst = "initfs/console-admin" }
    @{ Src = "target\$Target\$ProfileDir\strate-net-silo";           Dst = "initfs/strate-net" }
    @{ Src = "target\$Target\$ProfileDir\strate-bus";                Dst = "initfs/strate-bus" }
    @{ Src = "target\$Target\$ProfileDir\strate-wasm";               Dst = "initfs/strate-wasm" }
    @{ Src = "target\$Target\$ProfileDir\strate-webrtc";             Dst = "initfs/strate-webrtc" }
    @{ Src = "target\$Target\$ProfileDir\dhcp-client";               Dst = "initfs/bin/dhcp-client" }
    @{ Src = "target\$Target\$ProfileDir\ping";                      Dst = "initfs/bin/ping" }
    @{ Src = "target\$Target\$ProfileDir\telnetd";                   Dst = "initfs/bin/telnetd" }
    @{ Src = "target\$Target\$ProfileDir\udp-tool";                  Dst = "initfs/bin/udp-tool" }
    @{ Src = "target\$Target\$ProfileDir\strate-sshd";               Dst = "initfs/bin/sshd" }
    @{ Src = "target\$Target\$ProfileDir\web-admin";                 Dst = "initfs/bin/web-admin" }
)

if ($Tests) {
    $Modules += @(
        @{ Src = "target\$Target\$ProfileDir\test_pid";       Dst = "initfs/test_pid" }
        @{ Src = "target\$Target\$ProfileDir\test_syscalls";  Dst = "initfs/test_syscalls" }
        @{ Src = "target\$Target\$ProfileDir\test_mem";       Dst = "initfs/test_mem" }
        @{ Src = "target\$Target\$ProfileDir\test_mem_stressed"; Dst = "initfs/test_mem_stressed" }
    )
}

foreach ($Mod in $Modules) {
    $SrcPath = Join-Path $RootDir $Mod.Src
    $DstPath = Join-Path $IsoRoot $Mod.Dst
    Copy-Optional $SrcPath $DstPath $Mod.Dst
}

# WASM assets
Copy-Optional (Join-Path $RootDir "workspace\assets\wasm\hello.wasm") (Join-Path $IsoRoot "initfs\bin\hello.wasm") "hello.wasm"
Copy-Optional (Join-Path $RootDir "workspace\assets\wasm\wasm-test.toml") (Join-Path $IsoRoot "initfs\wasm-test.toml") "wasm-test.toml"
Copy-Optional (Join-Path $RootDir "workspace\assets\boot\silo.toml") (Join-Path $IsoRoot "initfs\silo.toml") "silo.toml"

# =========================================================================
# 5. Create ISO
# =========================================================================
Step "4. Creating ISO"

$IsoFile = Join-Path $BuildDir "strat9-os.iso"

# Use WSL xorriso (reliable), fallback to bundled Windows binary
$UseXorrisoWsl = $false
$WslDistro = "Debian"
$XorrisoBundled = Join-Path $RootDir "tools\xorriso-win32.2026-02-25\xorriso.exe"

# Prefer WSL - it handles path conversion correctly
try {
    $WslCheck = & wsl -d $WslDistro -- which xorriso 2>$null
    if ($LASTEXITCODE -eq 0 -and $WslCheck -match "xorriso") {
        $UseXorrisoWsl = $true
        Write-Host "  xorriso found via WSL ($WslDistro)" -ForegroundColor Green
    }
} catch {}

# Fallback to bundled Windows binary (may have path issues with Cygwin builds)
if (-not $UseXorrisoWsl -and (Test-Path $XorrisoBundled)) {
    Write-Host "  xorriso found (bundled Windows binary)" -ForegroundColor Yellow
    Write-Host "  Note: WSL xorriso is preferred for reliable path handling" -ForegroundColor Yellow
}

if ($UseXorrisoWsl -or (Test-Path $XorrisoBundled)) {
    Write-Host "  Creating ISO with xorriso..."

    $XorrisoArgs = @(
        "-as", "mkisofs",
        "-b", "boot/limine/limine-bios-cd.bin",
        "-no-emul-boot",
        "-boot-load-size", "4",
        "-boot-info-table",
        "--efi-boot", "boot/limine/limine-uefi-cd.bin",
        "-efi-boot-part",
        "--efi-boot-image",
        "--protective-msdos-label"
    )

    if ($UseXorrisoWsl) {
        $IsoRootWsl = $IsoRoot.Replace('\', '/').Replace('C:', '/mnt/c')
        $IsoFileWsl = $IsoFile.Replace('\', '/').Replace('C:', '/mnt/c')
        $XorrisoArgs += @($IsoRootWsl, "-o", $IsoFileWsl)
        & wsl -d $WslDistro -- xorriso @XorrisoArgs 2>&1 | ForEach-Object { Write-Host "    $_" }
    } else {
        # Bundled Windows binary - use forward slashes
        $IsoRootPosix = $IsoRoot.Replace('\', '/')
        $IsoFilePosix = $IsoFile.Replace('\', '/')
        $XorrisoArgs += @($IsoRootPosix, "-o", $IsoFilePosix)
        & $XorrisoBundled @XorrisoArgs 2>&1 | ForEach-Object { Write-Host "    $_" }
    }

    if ((Test-Path $IsoFile) -and ((Get-Item $IsoFile).Length -gt 1MB)) {
        $SizeMB = [math]::Round((Get-Item $IsoFile).Length / 1MB, 1)
        Write-Host "  [OK] ISO created ($SizeMB MB)" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] ISO is empty or too small" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  ERROR: No xorriso found." -ForegroundColor Red
    Write-Host "  Place xorriso.exe in tools\xorriso-win32*/" -ForegroundColor Yellow
    exit 1
}

# =========================================================================
# 6. Install Limine to ISO (bios-install)
# =========================================================================
Step "5. Installing Limine to ISO (BIOS)"

$LimineExe = Join-Path $LimineDir "limine.exe"
$LimineLinux = Join-Path $LimineDir "limine"

if (Test-Path $LimineExe) {
    $FileType = & wsl -d $WslDistro -- file $LimineExe 2>$null
    if ($FileType -match "ELF") {
        Write-Host "  limine.exe is an ELF binary, running via WSL..."
        & wsl -d $WslDistro -- $LimineExe bios-install $IsoFile 2>&1 | ForEach-Object { Write-Host "    $_" }
    } elseif ($FileType -match "PE.*Windows") {
        Write-Host "  limine.exe is a Windows PE, executing directly..."
        & $LimineExe bios-install $IsoFile 2>&1 | ForEach-Object { Write-Host "    $_" }
    }
} elseif (Test-Path $LimineLinux) {
    & wsl -d $WslDistro -- $LimineLinux bios-install $IsoFile 2>&1 | ForEach-Object { Write-Host "    $_" }
} else {
    Write-Host "  [WARN] limine host utility not found, ISO still bootable" -ForegroundColor Yellow
}

# =========================================================================
# 7. Create raw disk image
# =========================================================================
Step "6. Creating raw disk image"

$ImgFile = Join-Path $BuildDir "strat9-os.img"
$ImgSize = 64MB
$NullBytes = New-Object byte[] $ImgSize
[System.IO.File]::WriteAllBytes($ImgFile, $NullBytes)
Write-Host "  [OK] Created 64MB disk image" -ForegroundColor Green

# =========================================================================
# 8. Summary
# =========================================================================
Step "Build Complete!"
Write-Host "  ISO file  : $IsoFile" -ForegroundColor White
Write-Host "  Disk image: $ImgFile" -ForegroundColor White
Write-Host "  Profile   : $Profile" -ForegroundColor White
Write-Host ""

if ($Run) {
    Step "Launching QEMU..."
    $QemuArgs = @(
        "-cdrom", $IsoFile
        "-drive", "file=$(Join-Path $RootDir 'qemu-stuff\disk.img'),format=raw,if=none,id=drv0,cache=none"
        "-device", "virtio-blk-pci,drive=drv0"
        "-machine", "q35"
        "-cpu", "qemu64"
        "-smp", "2"
        "-m", "256M"
        "-display", "gtk,grab-on-hover=off,zoom-to-fit=on"
        "-no-reboot", "-no-shutdown"
        "-serial", "mon:stdio"
        "-netdev", "user,id=net0,net=192.168.76.0/24,dhcpstart=192.168.76.9,dns=192.168.76.1"
        "-device", "e1000,netdev=net0,mac=52:54:00:12:34:56"
        "-D", (Join-Path $BuildDir "qemu.log")
        "-d", "guest_errors"
    )
    & qemu-system-x86_64 $QemuArgs
}
elseif ($RunVMware) {
    Write-Host "  To test in VMware Workstation:" -ForegroundColor Cyan
    Write-Host "  1. Create a new VM (Other Linux 5.x or later 64-bit)" -ForegroundColor Cyan
    Write-Host "  2. Set CD/DVD to use: $IsoFile" -ForegroundColor Cyan
    Write-Host "  3. Add serial port: \\.\pipe\strat9 (server end, other end = application)" -ForegroundColor Cyan
    Write-Host "  4. Power on the VM" -ForegroundColor Cyan
}

Write-Host "`nDone!`n" -ForegroundColor Green
