//! s9vm — carte mémoire invitée (GPA).
//!
//! Module **pur** : il tient l'ensemble des plages d'adresses physiques
//! invitées réservées pour un monde (chevauchements, alignement, quotas,
//! comptabilité de pages) sans toucher aux frames ni aux tables de
//! traduction. La couche noyau (`s9vm::vm`) associe ces plages aux frames
//! épinglées et aux tables de second niveau.
//!
//! Testable sur l'hôte (tests L2).

use alloc::collections::BTreeMap;

/// Taille d'une page de base (4 Kio).
pub const PAGE_SIZE: u64 = 4096;
/// Largeur maximale d'adresse physique invitée couverte (48 bits).
pub const MAX_GPA: u64 = 1 << 48;

/// Nombre maximal de plages distinctes par monde (borne de sécurité).
pub const MAX_REGIONS: usize = 256;

/// Erreurs de réservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// Adresse ou longueur nulle, non alignée, ou hors de l'espace GPA.
    InvalidRange,
    /// La plage chevauche une plage déjà réservée.
    Overlap,
    /// Quota de pages du monde dépassé.
    QuotaExceeded,
    /// Trop de plages distinctes.
    TooManyRegions,
    /// La plage n'existe pas.
    NotMapped,
}

/// Plage réservée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    /// Adresse physique invitée de départ (alignée 4 Kio).
    pub gpa: u64,
    /// Longueur en octets (multiple de 4 Kio).
    pub len: u64,
    /// Permissions demandées (bits `Perms` : 1 = lecture, 2 = écriture,
    /// 4 = exécution).
    pub perms: u32,
    /// Type mémoire (0 = WB par défaut).
    pub memtype: u8,
}

impl Region {
    /// Adresse de fin (exclue).
    pub const fn end(&self) -> u64 {
        self.gpa + self.len
    }

    /// Vrai si la plage contient l'adresse.
    pub const fn contains(&self, gpa: u64) -> bool {
        gpa >= self.gpa && gpa < self.end()
    }
}

/// Carte mémoire invitée d'un monde.
#[derive(Debug)]
pub struct GuestMap {
    regions: BTreeMap<u64, Region>,
    pages: u64,
    quota_pages: u64,
}

impl GuestMap {
    /// Crée une carte vide avec un quota de pages.
    pub fn new(quota_pages: u64) -> Self {
        Self {
            regions: BTreeMap::new(),
            pages: 0,
            quota_pages,
        }
    }

    /// Nombre de pages réservées.
    pub const fn pages(&self) -> u64 {
        self.pages
    }

    /// Quota de pages.
    pub const fn quota_pages(&self) -> u64 {
        self.quota_pages
    }

    /// Nombre de plages.
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }

    /// Réserve une plage. Idempotence interdite : un chevauchement exact est
    /// une erreur, ce qui rend les doubles mappings visibles.
    pub fn reserve(
        &mut self,
        gpa: u64,
        len: u64,
        perms: u32,
        memtype: u8,
    ) -> Result<Region, MapError> {
        if len == 0 || gpa % PAGE_SIZE != 0 || len % PAGE_SIZE != 0 {
            return Err(MapError::InvalidRange);
        }
        let end = gpa.checked_add(len).ok_or(MapError::InvalidRange)?;
        if end > MAX_GPA {
            return Err(MapError::InvalidRange);
        }
        if self.overlaps(gpa, end) {
            return Err(MapError::Overlap);
        }
        if self.regions.len() >= MAX_REGIONS {
            return Err(MapError::TooManyRegions);
        }
        let pages = len / PAGE_SIZE;
        let new_total = self
            .pages
            .checked_add(pages)
            .ok_or(MapError::QuotaExceeded)?;
        if new_total > self.quota_pages {
            return Err(MapError::QuotaExceeded);
        }
        let region = Region {
            gpa,
            len,
            perms,
            memtype,
        };
        self.regions.insert(gpa, region);
        self.pages = new_total;
        Ok(region)
    }

    /// Vrai si `[gpa, end)` chevauche une plage existante.
    fn overlaps(&self, gpa: u64, end: u64) -> bool {
        if let Some((_, previous)) = self.regions.range(..=gpa).next_back() {
            if previous.end() > gpa {
                return true;
            }
        }
        if let Some((start, _)) = self.regions.range(gpa..).next() {
            if *start < end {
                return true;
            }
        }
        false
    }

    /// Retire la plage commençant exactement à `gpa`.
    pub fn remove(&mut self, gpa: u64) -> Option<Region> {
        let region = self.regions.remove(&gpa)?;
        self.pages = self.pages.saturating_sub(region.len / PAGE_SIZE);
        Some(region)
    }

    /// Retourne la plage contenant `gpa`.
    pub fn region_containing(&self, gpa: u64) -> Option<Region> {
        let (_, region) = self.regions.range(..=gpa).next_back()?;
        if region.contains(gpa) {
            Some(*region)
        } else {
            None
        }
    }

    /// Itère sur les plages (ordre croissant).
    pub fn regions(&self) -> impl Iterator<Item = &Region> {
        self.regions.values()
    }

    /// Libère toute la carte (les frames restent à la charge de l'appelant).
    pub fn clear(&mut self) {
        self.regions.clear();
        self.pages = 0;
    }

    /// Réinitialise le quota (utilisé quand un monde est reconfiguré).
    pub fn set_quota(&mut self, quota_pages: u64) {
        self.quota_pages = quota_pages;
    }
}

/// Permissions décodées depuis l'ABI (1 = lecture, 2 = écriture, 4 = exécution).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapPerms {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

/// Convertit des permissions ABI (1 = R, 2 = W, 4 = X ; 0 = lecture) en
/// [`MapPerms`].
pub const fn perms_from_abi(bits: u32) -> MapPerms {
    MapPerms {
        read: bits & 1 != 0 || bits == 0,
        write: bits & 2 != 0,
        execute: bits & 4 != 0,
    }
}
