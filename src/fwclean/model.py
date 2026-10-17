"""Modèle commun aux deux constructeurs."""

from __future__ import annotations

from dataclasses import dataclass


class ErreurLecture(Exception):
    """Export illisible ou hors format attendu."""


@dataclass(frozen=True)
class Objet:
    sorte: str
    nom: str
    empreinte: tuple
    detail: str
    mentions_adresses: tuple[str, ...] = ()
    mentions_services: tuple[str, ...] = ()
    mentions_calendriers: tuple[str, ...] = ()
    mentions_pools: tuple[str, ...] = ()
    vlan: int | None = None
    # Raison pour laquelle le nom ne doit pas changer (ex. nom DNS résolu par le SNS).
    fige: str | None = None
    # Objet global SMC (SNS, dossier Global/) : non modifiable sur le firewall.
    globale: bool = False


@dataclass(frozen=True)
class Regle:
    nom: str
    action: str
    active: bool
    sources: tuple[str, ...] = ()
    destinations: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    protocoles: tuple[str, ...] = ()
    interfaces_source: tuple[str, ...] = ()
    interfaces_destination: tuple[str, ...] = ()
    planification: str | None = None
    pool: str | None = None
    # Slot Filter SNS (nom de fichier « 05 ») et position 1-based (séparateurs inclus).
    slot: str | None = None
    position: int | None = None
    # Listes brutes pour RULE UPDATE (any, internet… conservés).
    sources_brutes: tuple[str, ...] = ()
    destinations_brutes: tuple[str, ...] = ()
    services_brutes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Lien:
    """Référence hors règle de filtrage : route ou NAT."""

    origine: str
    adresses: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    protocoles: tuple[str, ...] = ()
    calendriers: tuple[str, ...] = ()
    pools: tuple[str, ...] = ()


@dataclass(frozen=True)
class Inventaire:
    constructeur: str
    sources: tuple[str, ...]
    objets: tuple[Objet, ...]
    regles: tuple[Regle, ...] = ()
    liens: tuple[Lien, ...] = ()
    ignores: tuple[str, ...] = ()
    avertissements: tuple[str, ...] = ()
    # Noms cités par les règles, routes ou groupes mais définis nulle part dans l'export.
    non_definis: tuple[str, ...] = ()
    # Raison pour laquelle aucun retrait d'orphelin n'est proposé (export incomplet).
    retraits_suspendus: str | None = None


@dataclass(frozen=True)
class Renommage:
    sorte: str
    ancien: str
    nouveau: str
    references: tuple[str, ...]


@dataclass(frozen=True)
class Fusion:
    sorte: str
    contenu: str
    conserve: str
    nouveau_nom: str
    supprimes: tuple[str, ...]
    references_reecrites: tuple[str, ...]


@dataclass(frozen=True)
class Retrait:
    sorte: str
    nom: str
    motif: str


@dataclass(frozen=True)
class RemplacementGlobal:
    """Objet global SMC remplacé par un objet local (`reutiliser`, `creer`), à revoir, ou à supprimer."""

    sorte: str
    ancien: str
    action: str
    nouveau: str | None
    contenu: str
    membres: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    commentaire: str | None = None


@dataclass(frozen=True)
class NonConforme:
    sorte: str
    nom: str
    traitement: str
    nom_propose: str | None
    commentaire: str | None = None


@dataclass(frozen=True)
class Resultat:
    inventaire: Inventaire
    non_conformes: tuple[NonConforme, ...]
    renommages: tuple[Renommage, ...]
    fusions: tuple[Fusion, ...]
    retraits: tuple[Retrait, ...]
    referentiel: str = "aucun : objets à adresse IP signalés à revoir"
    # Objets de la base par défaut SNS, laissés tels quels.
    natifs: tuple[Objet, ...] = ()
    globaux: tuple[RemplacementGlobal, ...] = ()
