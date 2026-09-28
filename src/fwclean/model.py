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


@dataclass(frozen=True)
class Regle:
    nom: str
    action: str
    active: bool
    sources: tuple[str, ...] = ()
    destinations: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    interfaces_source: tuple[str, ...] = ()
    interfaces_destination: tuple[str, ...] = ()
    planification: str | None = None
    pool: str | None = None


@dataclass(frozen=True)
class Lien:
    """Référence hors règle de filtrage : route ou NAT."""

    origine: str
    adresses: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
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
