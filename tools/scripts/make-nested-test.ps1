<#
.SYNOPSIS
    Prépare un artefact de validation « virtualisation imbriquée » pour s9vm.

.DESCRIPTION
    Construit (optionnellement) le noyau + le bootloader UEFI, prépare une
    image disque FAT32 bootable (MBR + ESP), la convertit en disque virtuel et
    génère un descripteur de machine avec :
      - firmware UEFI ;
      - virtualisation matérielle imbriquée activée ;
      - port série redirigé vers un fichier (journal de validation) ;
      - option de boot s9vm.selftest=1 (le noyau exécute le test de fumée
        dès que VT-x est disponible).

    Le format de descripteur produit est le format `.vmx` (hyperviseurs de
    bureau courants). Le même disque peut être utilisé par tout hyperviseur
    hôte exposant VT-x/EPT et un firmware UEFI (QNX, KVM, etc.).

.PARAMETER Build
    Lance d'abord le harnais QEMU pour (re)construire le noyau et l'ESP de
    staging (`build/qemu-esp`).

.PARAMETER OutDir
    Répertoire de sortie (par défaut `build/nested-test`).

.PARAMETER Source
    Répertoire ESP source (par défaut `build/qemu-esp`).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools/scripts/make-nested-test.ps1 -Build
#>
[CmdletBinding()]
param(
    [switch]$Build,
    [string]$Source = "build/qemu-esp",
    [string]$OutDir = "build/nested-test",
    [int]$SizeMB = 280,
    [string]$QemuImg = ""
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repo

if ($Build) {
    Write-Host "[s9vm-test] build du noyau + ESP via le harnais QEMU..."
    $harness = Join-Path $repo "docs\virtualisation\implementation\qemu-boot-test.ps1"
    if (-not (Test-Path $harness)) {
        throw "Harnais introuvable : $harness"
    }
    & powershell -NoProfile -ExecutionPolicy Bypass -File $harness -ForceBuild -TimeoutSec 180 | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Le build/boot du harnais a échoué (code $LASTEXITCODE)"
    }
}

$sourceDir = Join-Path $repo $Source
if (-not (Test-Path $sourceDir)) {
    throw "ESP source introuvable : $sourceDir. Lancez avec -Build."
}
$outAbs = Join-Path $repo $OutDir
$espDir = Join-Path $outAbs "esp"
if (Test-Path $espDir) { Remove-Item $espDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $espDir | Out-Null
Copy-Item (Join-Path $sourceDir "*") $espDir -Recurse -Force

# Console série uniquement + test de fumée automatique dès que VT-x existe.
$cfg = Join-Path $espDir "boot\strat9.cfg"
if (-not (Test-Path $cfg)) { throw "Configuration de boot introuvable : $cfg" }
$lines = Get-Content $cfg | Where-Object { $_ -notmatch '^\s*console\.mode\s*=' -and $_ -notmatch '^\s*s9vm\.selftest\s*=' }
$lines += ""
$lines += "# Validation s9vm : console série et test de fumée automatique."
$lines += "console.mode=serial"
$lines += "s9vm.selftest=1"
Set-Content -Path $cfg -Value $lines -Encoding utf8

$image = Join-Path $outAbs "s9vm-esp.img"
Write-Host "[s9vm-test] création de l'image FAT32 ($SizeMB Mio)..."
python (Join-Path $repo "tools\scripts\make-esp-image.py") --source $espDir --output $image --size-mb $SizeMB
if ($LASTEXITCODE -ne 0) { throw "Échec de la création de l'image (code $LASTEXITCODE)" }

# qemu-img : variable d'environnement, paramètre, PATH, ou emplacement connu.
$qemuImgPath = $QemuImg
if (-not $qemuImgPath) { $qemuImgPath = $env:QEMU_IMG }
if (-not $qemuImgPath) {
    $candidate = Get-Command qemu-img -ErrorAction SilentlyContinue
    if ($candidate) { $qemuImgPath = $candidate.Source }
}
if (-not $qemuImgPath) {
    $known = "C:\src\noram\.tools\qemu\20260811\qemu-img.exe"
    if (Test-Path $known) { $qemuImgPath = $known }
}
if (-not $qemuImgPath) {
    throw "qemu-img introuvable : passez -QemuImg <chemin> ou définissez QEMU_IMG."
}

$vmdk = Join-Path $outAbs "s9vm-esp.vmdk"
Write-Host "[s9vm-test] conversion en disque virtuel..."
& $qemuImgPath convert -f raw -O vmdk $image $vmdk
if ($LASTEXITCODE -ne 0) { throw "Échec de la conversion vmdk (code $LASTEXITCODE)" }

$serialLog = Join-Path $outAbs "serial.log"
$vmxPath = Join-Path $outAbs "s9vm-nested.vmx"
$vmx = @(
    '.encoding = "UTF-8"',
    'config.version = "8"',
    'virtualHW.version = "20"',
    'displayName = "s9vm nested virtualization test"',
    'guestOS = "other-64"',
    'firmware = "efi"',
    'memsize = "4096"',
    'numvcpus = "2"',
    'cpuid.coresPerSocket = "2"',
    '# Virtualisation matérielle imbriquée : nécessaire pour VT-x/EPT dans l''invité.',
    'vhv.enable = "TRUE"',
    'hpet0.present = "TRUE"',
    'scsi0.present = "TRUE"',
    'scsi0.virtualDev = "lsilogic"',
    'scsi0:0.present = "TRUE"',
    'scsi0:0.deviceType = "disk"',
    'scsi0:0.fileName = "s9vm-esp.vmdk"',
    'serial0.present = "TRUE"',
    'serial0.fileType = "file"',
    ('serial0.fileName = "' + $serialLog.Replace('\', '\\') + '"'),
    'serial0.tryNoRxLoss = "FALSE"',
    'serial0.yieldOnMsrRead = "TRUE"',
    'bios.bootOrder = "hdd"',
    'bios.hddOrder = "scsi0:0"',
    'tools.syncTime = "FALSE"',
    'powerType.powerOff = "soft"',
    'powerType.suspend = "soft"'
)
Set-Content -Path $vmxPath -Value $vmx -Encoding ascii

Write-Host ""
Write-Host "[s9vm-test] Artefacts prêts :"
Write-Host "  image disque : $image"
Write-Host "  disque virtuel : $vmdk"
Write-Host "  descripteur : $vmxPath"
Write-Host "  journal série : $serialLog"
Write-Host ""
Write-Host "Procédure :"
Write-Host "  1. Ouvrir le descripteur dans l'hyperviseur de bureau (VT-x/EPT imbriqué requis)."
Write-Host "  2. Démarrer la machine ; la console série est écrite dans le journal."
Write-Host "  3. Attendre 'Boot complete' puis 's9vm selftest PASS'."
Write-Host ""
Write-Host "Auto-vérification locale de l'image (QEMU/TCG, sans VT-x) :"
Write-Host "  la même image est bootable ; on doit voir '[s9vm] VT-x absent'."
