"""Référentiel réseaux (reseaux.csv) et déduction site + zone des objets."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import NamedTuple

from fwclean.model import ErreurLecture, Inventaire, Objet
from fwclean.naming import (
    CTX,
    ESPACE,
    MULTI,
    RESERVES,
    normaliser_chaine,
    zone_connue,
)

Adresse = ipaddress.IPv4Address | ipaddress.IPv6Address
Reseau = ipaddress.IPv4Network | ipaddress.IPv6Network

ENTETE = ("reseau", "site", "zone")
ENTETE_VLAN = (*ENTETE, "vlan")


class Localisation(NamedTuple):
    site: str
    zone: str


INCONNUE = Localisation(CTX, CTX)


@dataclass(frozen=True)
class Entree:
    reseau: Reseau
    site: str
    zone: str
    vlan: int | None = None


@dataclass(frozen=True)
class Referentiel:
    entrees: tuple[Entree, ...] = ()
    source: str | None = None
    _tries: tuple[Entree, ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        tries = tuple(sorted(self.entrees, key=lambda entree: -entree.reseau.prefixlen))
        object.__setattr__(self, "_tries", tries)

    @property
    def sites(self) -> tuple[str, ...]:
        return tuple(sorted({entree.site for entree in self.entrees}))

    def localiser(self, debut: Adresse, fin: Adresse | None = None) -> Localisation | None:
        """Réseau le plus précis contenant toute la plage [debut, fin]."""
        fin = debut if fin is None else fin
        for entree in self._tries:
            if entree.reseau.version != debut.version or entree.reseau.version != fin.version:
                continue
            if debut in entree.reseau and fin in entree.reseau:
                return Localisation(entree.site, entree.zone)
        return None

    def vlan(self, reseau: Reseau) -> int | None:
        """VLAN de l'entrée la plus précise qui contient le réseau (None si elle n'en a pas)."""
        for entree in self._tries:
            if entree.reseau.version == reseau.version and reseau.subnet_of(entree.reseau):
                return entree.vlan
        return None

    def decrire(self) -> str:
        if not self.entrees:
            return "aucun : objets à adresse IP signalés à revoir"
        sites = ", ".join(site.upper() for site in self.sites)
        origine = f"{self.source} — " if self.source else ""
        return f"{origine}{len(self.entrees)} réseaux, sites : {sites}"


def lire_reseaux(chemin: Path, contextes: Sequence[str]) -> Referentiel:
    try:
        texte = chemin.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ErreurLecture(f"Référentiel réseaux illisible : {chemin} ({exc.strerror})") from exc
    return analyser_reseaux(texte, contextes, source=str(chemin))


def analyser_reseaux(texte: str, contextes: Sequence[str], source: str | None = None) -> Referentiel:
    """Lit `reseau;site;zone` ou `reseau;site;zone;vlan` (vlan vide permis). `#` : commentaire."""
    entrees: dict[Reseau, Entree] = {}
    entete: tuple[str, ...] | None = None
    for numero, brut in enumerate(texte.splitlines(), start=1):
        ligne = brut.split("#", 1)[0].strip()
        if not ligne:
            continue
        champs = [champ.strip() for champ in ligne.split(";")]
        if entete is None:
            entete = tuple(champ.lower() for champ in champs)
            if entete not in {ENTETE, ENTETE_VLAN}:
                raise ErreurLecture(
                    "reseaux.csv : en-tête attendu « reseau;site;zone » ou "
                    f"« reseau;site;zone;vlan », lu « {ligne} »."
                )
            continue
        if len(champs) != len(entete) and not (entete == ENTETE_VLAN and len(champs) == 3):
            raise ErreurLecture(
                f"reseaux.csv ligne {numero} : {len(entete)} champs attendus ({';'.join(entete)})."
            )
        brut_reseau, site, zone = champs[0], champs[1].lower(), champs[2].lower()
        brut_vlan = champs[3] if len(champs) > 3 else ""
        if brut_vlan and not (brut_vlan.isdigit() and 1 <= int(brut_vlan) <= 4094):
            raise ErreurLecture(f"reseaux.csv ligne {numero} : VLAN invalide « {brut_vlan} » (1 à 4094).")
        vlan = int(brut_vlan) if brut_vlan else None
        try:
            reseau = ipaddress.ip_network(brut_reseau, strict=False)
        except ValueError as exc:
            raise ErreurLecture(f"reseaux.csv ligne {numero} : réseau invalide « {brut_reseau} ».") from exc
        if not re.fullmatch(r"[a-z0-9]+", site) or site in RESERVES:
            raise ErreurLecture(f"reseaux.csv ligne {numero} : site invalide « {champs[1]} ».")
        if not zone_connue(zone, contextes) or zone in RESERVES:
            raise ErreurLecture(
                f"reseaux.csv ligne {numero} : zone « {champs[2]} » absente de contextes.txt."
            )
        existante = entrees.get(reseau)
        if existante is not None and (existante.site, existante.zone, existante.vlan) != (site, zone, vlan):
            raise ErreurLecture(
                f"reseaux.csv ligne {numero} : {reseau} déjà déclaré avec un autre site, zone ou VLAN."
            )
        entrees[reseau] = Entree(reseau=reseau, site=site, zone=zone, vlan=vlan)
    return Referentiel(entrees=tuple(entrees.values()), source=source)


def appliquer_vlans(inventaire: Inventaire, referentiel: Referentiel) -> Inventaire:
    """Réseaux sans VLAN dans la config : VLAN de l'entrée la plus précise du référentiel."""
    if not any(entree.vlan is not None for entree in referentiel.entrees):
        return inventaire
    objets = []
    for objet in inventaire.objets:
        if objet.sorte == "reseau" and objet.vlan is None:
            vlans = {referentiel.vlan(reseau) for reseau in _reseaux(objet)}
            if len(vlans) == 1 and None not in vlans:
                objet = replace(objet, vlan=vlans.pop())
        objets.append(objet)
    return replace(inventaire, objets=tuple(objets))


def commun(valeurs: Iterable[str]) -> str:
    """Valeur commune, `CTX` ignoré ; plusieurs valeurs → `MULTI`, aucune → `CTX`."""
    connues = {valeur for valeur in valeurs if valeur != CTX}
    if not connues:
        return CTX
    if len(connues) == 1:
        return connues.pop()
    return MULTI


def fusionner(localisations: Iterable[Localisation]) -> Localisation:
    liste = list(localisations)
    return Localisation(
        commun(loc.site for loc in liste),
        commun(loc.zone for loc in liste),
    )


def depuis_nom(nom: str, contextes: Sequence[str], sites: Collection[str]) -> Localisation:
    """Premier jeton site connu et premier jeton zone connu du nom."""
    site = zone = None
    for jeton in normaliser_chaine(nom).split("-"):
        if site is None and jeton in sites:
            site = jeton
        elif zone is None and zone_connue(jeton, contextes) and jeton not in RESERVES:
            zone = jeton
    return Localisation(site or CTX, zone or CTX)


class Localisateur:
    """Site + zone de chaque objet d'un inventaire, calculés une fois."""

    def __init__(self, inventaire: Inventaire, contextes: Sequence[str], referentiel: Referentiel):
        self.contextes = contextes
        self.referentiel = referentiel
        self.sites = frozenset(referentiel.sites)
        self._adresses = {
            objet.nom: objet for objet in inventaire.objets if ESPACE[objet.sorte] == "adresse"
        }
        self._cache: dict[tuple[str, str], Localisation] = {}

    def nom(self, nom: str) -> Localisation:
        objet = self._adresses.get(nom)
        if objet is not None:
            return self.objet(objet)
        return depuis_nom(nom, self.contextes, self.sites)

    def objet(self, objet: Objet) -> Localisation:
        cle = (objet.sorte, objet.nom)
        if cle in self._cache:
            return self._cache[cle]
        self._cache[cle] = INCONNUE
        resultat = self._calculer(objet)
        self._cache[cle] = resultat
        return resultat

    def _calculer(self, objet: Objet) -> Localisation:
        par_nom = depuis_nom(objet.nom, self.contextes, self.sites)
        if objet.sorte in {"hote", "reseau", "plage", "pool"}:
            par_bornes = objet.sorte == "pool"
            trouvees = [
                loc
                for debut, fin in _plages(objet)
                if (loc := self._localiser_plage(debut, fin, par_bornes)) is not None
            ]
            if not trouvees:
                return Localisation(CTX, par_nom.zone)
            return fusionner(trouvees)
        if objet.sorte == "vip":
            return self._vip(objet, par_nom)
        if objet.sorte == "groupe-adresses":
            membres = fusionner(self.nom(membre) for membre in objet.mentions_adresses)
            zone = membres.zone if membres.zone != CTX else par_nom.zone
            return Localisation(membres.site, zone)
        return par_nom

    def _localiser_plage(
        self, debut: Adresse, fin: Adresse, par_bornes: bool = True
    ) -> Localisation | None:
        """Réseau contenant toute la plage ; sinon, si `par_bornes`, zones communes aux deux bornes."""
        entiere = self.referentiel.localiser(debut, fin)
        if entiere is not None or debut == fin or not par_bornes:
            return entiere
        bornes = [loc for loc in (self.referentiel.localiser(debut), self.referentiel.localiser(fin)) if loc]
        return fusionner(bornes) if bornes else None

    def _vip(self, objet: Objet, par_nom: Localisation) -> Localisation:
        _genre, externe, mappe, *_reste = objet.empreinte
        trouvees: list[Localisation] = []
        for valeur in (externe, mappe):
            plage = _plage_texte(valeur)
            if plage is not None:
                loc = self._localiser_plage(*plage)
                if loc is not None:
                    trouvees.append(loc)
            elif valeur in self._adresses:
                trouvees.append(self.nom(valeur))
        resultat = fusionner(trouvees)
        if resultat.zone == CTX:
            resultat = Localisation(resultat.site, par_nom.zone)
        return resultat


def _plages(objet: Objet) -> list[tuple[Adresse, Adresse]]:
    empreinte = objet.empreinte
    if objet.sorte == "pool":
        return [(ipaddress.ip_address(empreinte[0]), ipaddress.ip_address(empreinte[1]))]
    if objet.sorte == "plage":
        return [(ipaddress.ip_address(empreinte[1]), ipaddress.ip_address(empreinte[2]))]
    parties = empreinte if empreinte and isinstance(empreinte[0], tuple) else (empreinte,)
    plages: list[tuple[Adresse, Adresse]] = []
    for _famille, adresse, prefixe in parties:
        reseau = ipaddress.ip_network(f"{adresse}/{prefixe}", strict=False)
        plages.append((reseau.network_address, reseau.broadcast_address))
    return plages


def _reseaux(objet: Objet) -> list[Reseau]:
    parties = objet.empreinte if isinstance(objet.empreinte[0], tuple) else (objet.empreinte,)
    return [ipaddress.ip_network(f"{adresse}/{prefixe}", strict=False) for _famille, adresse, prefixe in parties]


def _plage_texte(valeur: str) -> tuple[Adresse, Adresse] | None:
    try:
        if "-" in valeur:
            gauche, droite = valeur.split("-", 1)
            return ipaddress.ip_address(gauche.strip()), ipaddress.ip_address(droite.strip())
        if "/" in valeur:
            reseau = ipaddress.ip_network(valeur, strict=False)
            return reseau.network_address, reseau.broadcast_address
        adresse = ipaddress.ip_address(valeur)
    except ValueError:
        return None
    return adresse, adresse
