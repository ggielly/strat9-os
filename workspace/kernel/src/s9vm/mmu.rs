//! s9vm — traduction de second niveau (tables de pages matérielles).
//!
//! Le module construit et parcourt les tables qui traduisent les adresses
//! physiques invitées (GPA) vers les adresses physiques hôtes (HPA), selon la
//! SDM Intel (traduction de second niveau, « EPT »). Il est **pur** : il ne
//! connaît ni `HHDM`, ni allocateur de frames. L'accès mémoire aux tables est
//! fourni par un [`TableMemory`] (le noyau fournit une implémentation HHDM,
//! les tests une implémentation en mémoire hôte).
//!
//! Convention : les adresses manipulées sont des adresses **physiques** ; le
//! fournisseur [`TableMemory`] sait les lire et les écrire.

/// Taille d'une page de base.
pub const PAGE_SIZE: u64 = 4096;
/// Nombre d'entrées par table.
pub const ENTRY_COUNT: usize = 512;
/// Décalages des niveaux de la marche de tables 4 niveaux.
pub const SHIFT_PML4: u32 = 39;
pub const SHIFT_PDPT: u32 = 30;
pub const SHIFT_PD: u32 = 21;
pub const SHIFT_PT: u32 = 12;
/// Largeur maximale d'adresse physique invitée couverte (48 bits).
pub const MAX_GPA: u64 = 1 << 48;

/// Bits et masques des entrées de table de second niveau.
pub mod entry {
    /// Entrée présente.
    pub const PRESENT: u64 = 1 << 0;
    /// Lecture autorisée (bit 0 de l'EPT).
    pub const READ: u64 = 1 << 0;
    /// Écriture autorisée (bit 1 de l'EPT).
    pub const WRITE: u64 = 1 << 1;
    /// Exécution autorisée (bit 2 de l'EPT).
    pub const EXECUTE: u64 = 1 << 2;
    /// Type mémoire *write-back* (bits 5:3 = 6).
    pub const MEMTYPE_WB: u64 = 6 << 3;
    /// Page de grande taille (bit 7, page de 2 Mio au niveau PD).
    pub const LARGE_PAGE: u64 = 1 << 7;
    /// Masque de l'adresse physique encodée (bits 51:12).
    pub const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    /// Alignement d'une page de 2 Mio.
    pub const LARGE_2MB: u64 = 2 * 1024 * 1024;
    /// Alignement d'une page de 1 Gio.
    pub const LARGE_1GB: u64 = 1024 * 1024 * 1024;
}

/// Permissions demandées pour un mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Perms {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Perms {
    /// Lecture seule et exécution (code invité).
    pub const fn read_execute() -> Self {
        Self {
            read: true,
            write: false,
            execute: true,
        }
    }

    /// Lecture/écriture (données invitées).
    pub const fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
        }
    }

    /// Toutes les permissions (RAM classique).
    pub const fn read_write_execute() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
        }
    }

    /// Encode les permissions dans les bits 2:0 d'une entrée.
    pub const fn bits(self) -> u64 {
        let mut bits = 0;
        if self.read {
            bits |= entry::READ;
        }
        if self.write {
            bits |= entry::WRITE;
        }
        if self.execute {
            bits |= entry::EXECUTE;
        }
        bits
    }
}

/// Erreurs de manipulation des tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmuError {
    /// Le fournisseur n'a plus de table disponible.
    OutOfMemory,
    /// Adresse ou longueur invalide.
    InvalidRange,
    /// Une page de 2 Mio est mal alignée.
    Misaligned,
    /// La mémoire récupérée auprès du fournisseur n'est pas utilisable.
    BadMemory,
    /// Le mapping demandé chevauche un mapping existant incompatible.
    Conflict,
}

/// Fournisseur de mémoire pour les tables (allocation, lecture, écriture).
///
/// Le noyau implémente ce trait en allouant des frames et en passant par le
/// HHDM ; les tests utilisent une table en mémoire hôte. Chaque poignée
/// (`table`) identifie une table de 512 entrées de 8 octets.
pub trait TableMemory {
    /// Alloue une table nulle et retourne sa poignée (identifiant physique).
    fn alloc_table(&mut self) -> Option<u64>;
    /// Libère une table précédemment allouée.
    fn free_table(&mut self, table: u64);
    /// Lit l'entrée `index` de la table.
    fn read_entry(&self, table: u64, index: usize) -> u64;
    /// Écrit l'entrée `index` de la table.
    fn write_entry(&mut self, table: u64, index: usize, value: u64);
}

/// Racine d'une traduction de second niveau.
#[derive(Debug)]
pub struct SecondLevel {
    root: u64,
}

impl SecondLevel {
    /// Crée une traduction vide (une table racine nulle).
    pub fn new<M: TableMemory>(memory: &mut M) -> Result<Self, MmuError> {
        let root = memory.alloc_table().ok_or(MmuError::OutOfMemory)?;
        Ok(Self { root })
    }

    /// Adresse physique de la racine.
    pub const fn root_phys(&self) -> u64 {
        self.root
    }

    /// Libère la racine (les sous-tables doivent avoir été libérées par
    /// [`Self::unmap`] ou par l'appelant).
    pub fn release<M: TableMemory>(&self, memory: &mut M) {
        memory.free_table(self.root);
    }

    /// Mappe une plage de `len` octets (multiple de 4 Kio) en pages de 4 Kio.
    ///
    /// `gpa` et `hpa` doivent être alignés sur 4 Kio.
    pub fn map_4k<M: TableMemory>(
        &self,
        memory: &mut M,
        gpa: u64,
        hpa: u64,
        len: u64,
        perms: Perms,
    ) -> Result<(), MmuError> {
        if len == 0 || gpa % PAGE_SIZE != 0 || hpa % PAGE_SIZE != 0 || len % PAGE_SIZE != 0 {
            return Err(MmuError::InvalidRange);
        }
        if gpa.checked_add(len).map_or(true, |end| end > MAX_GPA) {
            return Err(MmuError::InvalidRange);
        }
        let leaf = perms.bits() | entry::MEMTYPE_WB;
        let pages = len / PAGE_SIZE;
        for index in 0..pages {
            let offset = index * PAGE_SIZE;
            let table = self.ensure_table(memory, gpa + offset, SHIFT_PT)?;
            let slot = index_of(gpa + offset, SHIFT_PT);
            let existing = memory.read_entry(table, slot);
            if existing & entry::PRESENT != 0 && existing & entry::LARGE_PAGE == 0 {
                return Err(MmuError::Conflict);
            }
            memory.write_entry(table, slot, (hpa + offset) | leaf);
        }
        Ok(())
    }

    /// Mappe une plage de `len` octets en pages de 2 Mio.
    ///
    /// `gpa`, `hpa` et `len` doivent être alignés sur 2 Mio.
    pub fn map_2m<M: TableMemory>(
        &self,
        memory: &mut M,
        gpa: u64,
        hpa: u64,
        len: u64,
        perms: Perms,
    ) -> Result<(), MmuError> {
        let align = entry::LARGE_2MB;
        if len == 0 || gpa % align != 0 || hpa % align != 0 || len % align != 0 {
            return Err(MmuError::Misaligned);
        }
        if gpa.checked_add(len).map_or(true, |end| end > MAX_GPA) {
            return Err(MmuError::InvalidRange);
        }
        let leaf = perms.bits() | entry::MEMTYPE_WB | entry::LARGE_PAGE;
        let pages = len / align;
        for index in 0..pages {
            let offset = index * align;
            let table = self.ensure_table(memory, gpa + offset, SHIFT_PD)?;
            let slot = index_of(gpa + offset, SHIFT_PD);
            let existing = memory.read_entry(table, slot);
            if existing & entry::PRESENT != 0 {
                return Err(MmuError::Conflict);
            }
            memory.write_entry(table, slot, (hpa + offset) | leaf);
        }
        Ok(())
    }

    /// Traduit une GPA en HPA, si une feuille existe.
    pub fn translate<M: TableMemory>(&self, memory: &M, gpa: u64) -> Option<u64> {
        if gpa >= MAX_GPA {
            return None;
        }
        let pml4 = memory.read_entry(self.root, index_of(gpa, SHIFT_PML4));
        if pml4 & entry::PRESENT == 0 {
            return None;
        }
        let pdpt_table = pml4 & entry::ADDR_MASK;
        let pdpt = memory.read_entry(pdpt_table, index_of(gpa, SHIFT_PDPT));
        if pdpt & entry::PRESENT == 0 {
            return None;
        }
        if pdpt & entry::LARGE_PAGE != 0 {
            // Pages de 1 Gio : supportées uniquement si le fournisseur les a
            // posées ; on les accepte en lecture.
            let base = pdpt & entry::ADDR_MASK & !(entry::LARGE_1GB - 1);
            return Some(base | (gpa & (entry::LARGE_1GB - 1)));
        }
        let pd_table = pdpt & entry::ADDR_MASK;
        let pd = memory.read_entry(pd_table, index_of(gpa, SHIFT_PD));
        if pd & entry::PRESENT == 0 {
            return None;
        }
        if pd & entry::LARGE_PAGE != 0 {
            let base = pd & entry::ADDR_MASK & !(entry::LARGE_2MB - 1);
            return Some(base | (gpa & (entry::LARGE_2MB - 1)));
        }
        let pt_table = pd & entry::ADDR_MASK;
        let pt = memory.read_entry(pt_table, index_of(gpa, SHIFT_PT));
        if pt & entry::PRESENT == 0 {
            return None;
        }
        Some((pt & entry::ADDR_MASK) | (gpa & (PAGE_SIZE - 1)))
    }

    /// Retire un mapping de 4 Kio. Retourne `true` si une feuille existait.
    ///
    /// Les tables intermédiaires devenues vides ne sont pas libérées (elles
    /// peuvent être réutilisées par un mapping ultérieur) ; utiliser
    /// [`Self::release`] après [`Self::release_all`] ou laisser le
    /// propriétaire du fournisseur les récupérer.
    pub fn unmap_4k<M: TableMemory>(&self, memory: &mut M, gpa: u64) -> bool {
        let Some(pt_table) = self.leaf_table(memory, gpa, SHIFT_PT) else {
            return false;
        };
        let slot = index_of(gpa, SHIFT_PT);
        let existing = memory.read_entry(pt_table, slot);
        if existing & entry::PRESENT == 0 || existing & entry::LARGE_PAGE != 0 {
            return false;
        }
        memory.write_entry(pt_table, slot, 0);
        true
    }

    /// Retire un mapping de 2 Mio. Retourne `true` si une feuille existait.
    pub fn unmap_2m<M: TableMemory>(&self, memory: &mut M, gpa: u64) -> bool {
        let Some(pd_table) = self.leaf_table(memory, gpa, SHIFT_PD) else {
            return false;
        };
        let slot = index_of(gpa, SHIFT_PD);
        let existing = memory.read_entry(pd_table, slot);
        if existing & entry::PRESENT == 0 || existing & entry::LARGE_PAGE == 0 {
            return false;
        }
        memory.write_entry(pd_table, slot, 0);
        true
    }

    /// Parcourt les tables jusqu'au tableau contenant la feuille du niveau
    /// demandé (`SHIFT_PT` pour 4 Kio, `SHIFT_PD` pour 2 Mio).
    fn leaf_table<M: TableMemory>(
        &self,
        memory: &M,
        gpa: u64,
        leaf_shift: u32,
    ) -> Option<u64> {
        if gpa >= MAX_GPA {
            return None;
        }
        let pml4 = memory.read_entry(self.root, index_of(gpa, SHIFT_PML4));
        if pml4 & entry::PRESENT == 0 {
            return None;
        }
        let pdpt = memory.read_entry(pml4 & entry::ADDR_MASK, index_of(gpa, SHIFT_PDPT));
        if pdpt & entry::PRESENT == 0 || pdpt & entry::LARGE_PAGE != 0 {
            return None;
        }
        let pd = memory.read_entry(pdpt & entry::ADDR_MASK, index_of(gpa, SHIFT_PD));
        if pd & entry::PRESENT == 0 {
            return None;
        }
        if leaf_shift == SHIFT_PD {
            return Some(pdpt & entry::ADDR_MASK);
        }
        if pd & entry::LARGE_PAGE != 0 {
            return None;
        }
        Some(pd & entry::ADDR_MASK)
    }

    /// Crée (si nécessaire) la table du niveau `shift` pour la GPA donnée et
    /// retourne sa poignée. Alloue les niveaux manquants.
    fn ensure_table<M: TableMemory>(
        &self,
        memory: &mut M,
        gpa: u64,
        shift: u32,
    ) -> Result<u64, MmuError> {
        debug_assert!(shift >= SHIFT_PT);
        let pml4_slot = index_of(gpa, SHIFT_PML4);
        let pml4 = memory.read_entry(self.root, pml4_slot);
        let pdpt_table = if pml4 & entry::PRESENT != 0 {
            pml4 & entry::ADDR_MASK
        } else {
            let table = memory.alloc_table().ok_or(MmuError::OutOfMemory)?;
            memory.write_entry(self.root, pml4_slot, table | entry::READ | entry::WRITE);
            table
        };
        if shift == SHIFT_PDPT {
            return Ok(pdpt_table);
        }
        let pdpt_slot = index_of(gpa, SHIFT_PDPT);
        let pdpt = memory.read_entry(pdpt_table, pdpt_slot);
        let pd_table = if pdpt & entry::PRESENT != 0 {
            pdpt & entry::ADDR_MASK
        } else {
            let table = memory.alloc_table().ok_or(MmuError::OutOfMemory)?;
            memory.write_entry(
                pdpt_table,
                pdpt_slot,
                table | entry::READ | entry::WRITE,
            );
            table
        };
        if shift == SHIFT_PD {
            return Ok(pd_table);
        }
        let pd_slot = index_of(gpa, SHIFT_PD);
        let pd = memory.read_entry(pd_table, pd_slot);
        let pt_table = if pd & entry::PRESENT != 0 {
            pd & entry::ADDR_MASK
        } else {
            let table = memory.alloc_table().ok_or(MmuError::OutOfMemory)?;
            memory.write_entry(pd_table, pd_slot, table | entry::READ | entry::WRITE);
            table
        };
        Ok(pt_table)
    }
}

/// Index d'une adresse dans la table du niveau `shift`.
const fn index_of(addr: u64, shift: u32) -> usize {
    ((addr >> shift) & 0x1FF) as usize
}

/// Encode la valeur d'activation de la traduction de second niveau (`EPTP`).
///
/// Format (SDM) : bits 2:0 = type mémoire (6 = WB), bits 5:3 = longueur de
/// marche moins 1 (3 pour 4 niveaux), bit 6 = A/D, bits 51:12 = racine.
pub const fn encode_second_level_pointer(
    root_phys: u64,
    memory_type: u8,
    four_levels: bool,
    accessed_dirty: bool,
) -> u64 {
    let mut value = (memory_type as u64) & 0x7;
    if four_levels {
        value |= 3 << 3;
    }
    if accessed_dirty {
        value |= 1 << 6;
    }
    value | (root_phys & entry::ADDR_MASK)
}
