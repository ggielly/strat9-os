//! s9vm — trampoline d'entrée/sortie invité.
//!
//! La seule manière fiable d'entrer chez l'invité est une routine assembleur
//! qui respecte le contrat matériel :
//!
//! 1. sauvegarder les registres callee-saved de l'hôte ;
//! 2. charger les registres généraux invités depuis [`EnterFrame`] ;
//! 3. exécuter `vmlaunch` (première entrée) ou `vmresume` (entrées
//!    suivantes) ;
//! 4. sur sortie, le matériel charge `HOST_RSP`/`HOST_RIP` : on arrive sur le
//!    label `s9vm_guest_exit`, qui sauve les registres invités et restaure
//!    l'hôte.
//!
//! # Contrat
//!
//! `s9vm_enter_guest(frame, host_stack_top) -> u64`
//! - `frame` : `*mut EnterFrame`, vivant pendant tout l'appel ;
//! - `host_stack_top` : sommet (16 octets aligné) d'une pile hôte dédiée,
//!    écrite dans `HOST_RSP` avant l'entrée ;
//! - retour : `0` = sortie invité normale (lire la raison dans le bloc de
//!   contrôle), `1` = échec d'entrée (`VMfail`, lire le statut).
//!
//! Le frame est référencé par un pointeur rangé sur la pile hôte
//! (`[host_stack_top - 8]`), ce qui permet de le retrouver au retour sans
//! dépendre d'un registre (tous les GPR appartiennent à l'invité).
//!
//! Les offsets `S9VM_F_*` sont partagés entre l'assembleur et la structure
//! Rust ; un test hôte vérifie qu'ils correspondent (`offset_of!`).

use core::arch::global_asm;

/// Registres généraux invités, dans l'ordre de sauvegarde.
pub const S9VM_F_RAX: usize = 0;
pub const S9VM_F_RBX: usize = 8;
pub const S9VM_F_RCX: usize = 16;
pub const S9VM_F_RDX: usize = 24;
pub const S9VM_F_RSI: usize = 32;
pub const S9VM_F_RDI: usize = 40;
pub const S9VM_F_RBP: usize = 48;
pub const S9VM_F_RSP: usize = 56;
pub const S9VM_F_R8: usize = 64;
pub const S9VM_F_R9: usize = 72;
pub const S9VM_F_R10: usize = 80;
pub const S9VM_F_R11: usize = 88;
pub const S9VM_F_R12: usize = 96;
pub const S9VM_F_R13: usize = 104;
pub const S9VM_F_R14: usize = 112;
pub const S9VM_F_R15: usize = 120;
pub const S9VM_F_RIP: usize = 128;
pub const S9VM_F_RFLAGS: usize = 136;
pub const S9VM_F_HOST_RSP: usize = 144;
pub const S9VM_F_HOST_RBX: usize = 152;
pub const S9VM_F_HOST_RBP: usize = 160;
pub const S9VM_F_HOST_R12: usize = 168;
pub const S9VM_F_HOST_R13: usize = 176;
pub const S9VM_F_HOST_R14: usize = 184;
pub const S9VM_F_HOST_R15: usize = 192;
pub const S9VM_F_STATUS: usize = 200;
pub const S9VM_F_LAUNCHED: usize = 208;
/// Taille totale du frame.
pub const S9VM_ENTER_FRAME_SIZE: usize = 216;

/// Zone d'échange entre le noyau et le trampoline pour une entrée invitée.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EnterFrame {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    /// RSP invité (informatif : le matériel utilise `GUEST_RSP`).
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// RIP invité (informatif : le matériel utilise `GUEST_RIP`).
    pub rip: u64,
    /// RFLAGS invité (informatif).
    pub rflags: u64,
    /// RSP hôte sauvegardé par le trampoline.
    pub host_rsp: u64,
    pub host_rbx: u64,
    pub host_rbp: u64,
    pub host_r12: u64,
    pub host_r13: u64,
    pub host_r14: u64,
    pub host_r15: u64,
    /// Statut d'échec : drapeaux du CPU au moment du `VMfail`.
    pub status: u64,
    /// 1 si l'invité a déjà été lancé (`vmresume`), 0 sinon (`vmlaunch`).
    pub launched: u64,
}

impl EnterFrame {
    /// Frame nul.
    pub const fn zeroed() -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0,
            host_rsp: 0,
            host_rbx: 0,
            host_rbp: 0,
            host_r12: 0,
            host_r13: 0,
            host_r14: 0,
            host_r15: 0,
            status: 0,
            launched: 0,
        }
    }
}

/// Vérifications à la compilation : les offsets partagés avec l'assembleur
/// doivent correspondre exactement aux champs de [`EnterFrame`]. Une
/// régression ici produirait une corruption silencieuse de l'état hôte.
const _: () = {
    assert!(core::mem::offset_of!(EnterFrame, rax) == S9VM_F_RAX);
    assert!(core::mem::offset_of!(EnterFrame, rbx) == S9VM_F_RBX);
    assert!(core::mem::offset_of!(EnterFrame, rcx) == S9VM_F_RCX);
    assert!(core::mem::offset_of!(EnterFrame, rdx) == S9VM_F_RDX);
    assert!(core::mem::offset_of!(EnterFrame, rsi) == S9VM_F_RSI);
    assert!(core::mem::offset_of!(EnterFrame, rdi) == S9VM_F_RDI);
    assert!(core::mem::offset_of!(EnterFrame, rbp) == S9VM_F_RBP);
    assert!(core::mem::offset_of!(EnterFrame, rsp) == S9VM_F_RSP);
    assert!(core::mem::offset_of!(EnterFrame, r8) == S9VM_F_R8);
    assert!(core::mem::offset_of!(EnterFrame, r9) == S9VM_F_R9);
    assert!(core::mem::offset_of!(EnterFrame, r10) == S9VM_F_R10);
    assert!(core::mem::offset_of!(EnterFrame, r11) == S9VM_F_R11);
    assert!(core::mem::offset_of!(EnterFrame, r12) == S9VM_F_R12);
    assert!(core::mem::offset_of!(EnterFrame, r13) == S9VM_F_R13);
    assert!(core::mem::offset_of!(EnterFrame, r14) == S9VM_F_R14);
    assert!(core::mem::offset_of!(EnterFrame, r15) == S9VM_F_R15);
    assert!(core::mem::offset_of!(EnterFrame, rip) == S9VM_F_RIP);
    assert!(core::mem::offset_of!(EnterFrame, rflags) == S9VM_F_RFLAGS);
    assert!(core::mem::offset_of!(EnterFrame, host_rsp) == S9VM_F_HOST_RSP);
    assert!(core::mem::offset_of!(EnterFrame, host_rbx) == S9VM_F_HOST_RBX);
    assert!(core::mem::offset_of!(EnterFrame, host_rbp) == S9VM_F_HOST_RBP);
    assert!(core::mem::offset_of!(EnterFrame, host_r12) == S9VM_F_HOST_R12);
    assert!(core::mem::offset_of!(EnterFrame, host_r13) == S9VM_F_HOST_R13);
    assert!(core::mem::offset_of!(EnterFrame, host_r14) == S9VM_F_HOST_R14);
    assert!(core::mem::offset_of!(EnterFrame, host_r15) == S9VM_F_HOST_R15);
    assert!(core::mem::offset_of!(EnterFrame, status) == S9VM_F_STATUS);
    assert!(core::mem::offset_of!(EnterFrame, launched) == S9VM_F_LAUNCHED);
    assert!(core::mem::size_of::<EnterFrame>() == S9VM_ENTER_FRAME_SIZE);
};

extern "C" {
    /// Point d'entrée assembleur (défini par [`S9VM_TRAMPOLINE`]).
    ///
    /// # Safety
    /// Voir le contrat du module ; ne jamais appeler si VT-x n'est pas actif
    /// sur le CPU courant, ou si le bloc de contrôle n'est pas chargé.
    pub fn s9vm_enter_guest(frame: *mut EnterFrame, host_stack_top: u64) -> u64;

    /// Label de reprise après sortie invité (adresse posée dans `HOST_RIP`).
    /// Ce n'est pas une fonction appelable : on ne prend que son adresse.
    pub fn s9vm_guest_exit();

    /// Entrée assembleur du guest (adresse utilisée pour `HOST_RIP`).
    pub fn s9vm_guest_entry();
}

// Code du trampoline. Les offsets `S9VM_F_*` doivent rester synchronisés avec
// [`EnterFrame`] ; un test hôte le vérifie.
global_asm!(
    r#"
    .set S9VM_F_RAX,        0
    .set S9VM_F_RBX,        8
    .set S9VM_F_RCX,       16
    .set S9VM_F_RDX,       24
    .set S9VM_F_RSI,       32
    .set S9VM_F_RDI,       40
    .set S9VM_F_RBP,       48
    .set S9VM_F_R8,        64
    .set S9VM_F_R9,        72
    .set S9VM_F_R10,       80
    .set S9VM_F_R11,       88
    .set S9VM_F_R12,       96
    .set S9VM_F_R13,      104
    .set S9VM_F_R14,      112
    .set S9VM_F_R15,      120
    .set S9VM_F_HOST_RSP, 144
    .set S9VM_F_HOST_RBX, 152
    .set S9VM_F_HOST_RBP, 160
    .set S9VM_F_HOST_R12, 168
    .set S9VM_F_HOST_R13, 176
    .set S9VM_F_HOST_R14, 184
    .set S9VM_F_HOST_R15, 192
    .set S9VM_F_STATUS,   200
    .set S9VM_F_LAUNCHED, 208

    .text
    .global s9vm_enter_guest
    .type s9vm_enter_guest, @function
s9vm_enter_guest:
    /* rdi = frame, rsi = host_stack_top */
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rdi                        /* slot de récupération sur échec */
    mov [rdi + S9VM_F_HOST_RSP], rsp
    mov [rdi + S9VM_F_HOST_RBX], rbx
    mov [rdi + S9VM_F_HOST_RBP], rbp
    mov [rdi + S9VM_F_HOST_R12], r12
    mov [rdi + S9VM_F_HOST_R13], r13
    mov [rdi + S9VM_F_HOST_R14], r14
    mov [rdi + S9VM_F_HOST_R15], r15

    /* Pointeur de frame accessible depuis la pile hôte au retour. */
    mov [rsi - 8], rdi
    mov rax, [rdi + S9VM_F_LAUNCHED]
    mov [rsi - 16], rax

    /* Le choix vmlaunch/vmresume est fixé ici ; les mov suivants ne
       modifient pas les drapeaux. */
    cmp qword ptr [rsi - 16], 0

    mov rax, [rdi + S9VM_F_RAX]
    mov rbx, [rdi + S9VM_F_RBX]
    mov rcx, [rdi + S9VM_F_RCX]
    mov rdx, [rdi + S9VM_F_RDX]
    mov rsi, [rdi + S9VM_F_RSI]
    mov rbp, [rdi + S9VM_F_RBP]
    mov r8,  [rdi + S9VM_F_R8]
    mov r9,  [rdi + S9VM_F_R9]
    mov r10, [rdi + S9VM_F_R10]
    mov r11, [rdi + S9VM_F_R11]
    mov r12, [rdi + S9VM_F_R12]
    mov r13, [rdi + S9VM_F_R13]
    mov r14, [rdi + S9VM_F_R14]
    mov r15, [rdi + S9VM_F_R15]
    mov rdi, [rdi + S9VM_F_RDI]
    je .Ls9vm_launch
    vmresume
    jmp .Ls9vm_fail
.Ls9vm_launch:
    vmlaunch
    jmp .Ls9vm_fail

.Ls9vm_fail:
    /* Toujours sur la pile noyau : le frame est dans le slot poussé. */
    pop rdi
    pushfq
    pop rax
    mov [rdi + S9VM_F_STATUS], rax
    mov rsp, [rdi + S9VM_F_HOST_RSP]
    mov rbx, [rdi + S9VM_F_HOST_RBX]
    mov rbp, [rdi + S9VM_F_HOST_RBP]
    mov r12, [rdi + S9VM_F_HOST_R12]
    mov r13, [rdi + S9VM_F_HOST_R13]
    mov r14, [rdi + S9VM_F_HOST_R14]
    mov r15, [rdi + S9VM_F_HOST_R15]
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    mov eax, 1
    ret

    .global s9vm_guest_entry
    .type s9vm_guest_entry, @function
s9vm_guest_entry:
    /* Jamais exécuté directement : adresse informative. */
    ud2

    .global s9vm_guest_exit
    .type s9vm_guest_exit, @function
s9vm_guest_exit:
    /* Le matériel a chargé HOST_RSP = host_stack_top ; [rsp-8] = frame. */
    mov [rsp - 16], rdi             /* sauve le rdi invité */
    mov rdi, [rsp - 8]              /* frame */
    mov [rdi + S9VM_F_RAX], rax
    mov [rdi + S9VM_F_RBX], rbx
    mov [rdi + S9VM_F_RCX], rcx
    mov [rdi + S9VM_F_RDX], rdx
    mov [rdi + S9VM_F_RSI], rsi
    mov [rdi + S9VM_F_R8],  r8
    mov [rdi + S9VM_F_R9],  r9
    mov [rdi + S9VM_F_R10], r10
    mov [rdi + S9VM_F_R11], r11
    mov [rdi + S9VM_F_R12], r12
    mov [rdi + S9VM_F_R13], r13
    mov [rdi + S9VM_F_R14], r14
    mov [rdi + S9VM_F_R15], r15
    mov rax, [rsp - 16]
    mov [rdi + S9VM_F_RDI], rax
    mov qword ptr [rdi + S9VM_F_STATUS], 0

    /* Restaure l'hôte et revient à l'appelant Rust. */
    mov rsp, [rdi + S9VM_F_HOST_RSP]
    mov rbx, [rdi + S9VM_F_HOST_RBX]
    mov rbp, [rdi + S9VM_F_HOST_RBP]
    mov r12, [rdi + S9VM_F_HOST_R12]
    mov r13, [rdi + S9VM_F_HOST_R13]
    mov r14, [rdi + S9VM_F_HOST_R14]
    mov r15, [rdi + S9VM_F_HOST_R15]
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    xor eax, eax
    ret
    "#
);
