"""Référentiel réseaux (reseaux.csv) et déduction site + interface des objets."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Collection, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from fwclean.model import ErreurLecture, Inventaire, Objet
from fwclean.naming import (
    CTX,
    ESPACE,
    MULTI,
    RESERVES,
    Localisation,
    normaliser_chaine,
    normaliser_interface,
)

Adresse = ipaddress.IPv4Address | ipaddress.IPv6Address
Reseau = ipaddress.IPv4Network | ipaddress.IPv6Network

# En-tête écrit par fwclean. Les anciens en-têtes avec colonne zone restent lus : la zone y est
# ignorée (elle n'entre dans aucun nom et n'est plus vérifiée).
ENTETE_INTERFACE = ("reseau", "site", "vlan", "interface")
ENTETES = (
    ENTETE_INTERFACE,
    ("reseau", "site", "zone", "vlan", "interface"),
    ("reseau", "site", "zone", "vlan"),
    ("reseau", "site", "zone"),
)

INCONNUE = Localisation(CTX, CTX)


@dataclass(frozen=True)
class Entree:
    reseau: Reseau
    site: str
    vlan: int | None = None
    # Nom tel qu'écrit dans reseaux.csv (VLAN-16, LABO_ANA…) ; None : colonne absente ou vide.
    interface: str | None = None

    @property
    def cle_interface(self) -> str | None:
        return normaliser_interface(self.interface) if self.interface else None


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

    @property
    def interfaces(self) -> tuple[str, ...]:
        """Interfaces normalisées (minuscules, `-`) : segment interface autorisé dans les noms."""
        return tuple(sorted({entree.cle_interface for entree in self.entrees if entree.cle_interface}))

    @property
    def sans_interface(self) -> tuple[Entree, ...]:
        return tuple(entree for entree in self.entrees if entree.interface is None)

    def entree(self, debut: Adresse, fin: Adresse | None = None) -> Entree | None:
        """Réseau le plus précis contenant toute la plage [debut, fin]."""
        fin = debut if fin is None else fin
        for entree in self._tries:
            if entree.reseau.version != debut.version or entree.reseau.version != fin.version:
                continue
            if debut in entree.reseau and fin in entree.reseau:
                return entree
        return None

    def localiser(self, debut: Adresse, fin: Adresse | None = None) -> Localisation | None:
        entree = self.entree(debut, fin)
        if entree is None:
            return None
        return Localisation(entree.site, entree.cle_interface or CTX)

    def decrire(self) -> str:
        if not self.entrees:
            return "aucun : objets à adresse IP signalés à revoir"
        sites = ", ".join(site.upper() for site in self.sites)
        origine = f"{self.source} — " if self.source else ""
        texte = f"{origine}{len(self.entrees)} réseaux, sites : {sites}"
        manquantes = len(self.sans_interface)
        if manquantes:
            texte += (
                f" ; {manquantes} sans interface (colonne vide ou absente) : "
                "objets de ces réseaux à revoir"
            )
        return texte


def lire_reseaux(chemin: Path) -> Referentiel:
    try:
        texte = chemin.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ErreurLecture(f"Référentiel réseaux illisible : {chemin} ({exc.strerror})") from exc
    return analyser_reseaux(texte, source=str(chemin))


def analyser_reseaux(texte: str, source: str | None = None) -> Referentiel:
    """Lit `reseau;site;vlan;interface` ; `#` : commentaire.

    VLAN et interface peuvent être vides. Les anciens en-têtes `reseau;site;zone;vlan;interface`,
    `reseau;site;zone;vlan` et `reseau;site;zone` restent lus, colonne zone ignorée. Une ligne
    plus courte que l'en-tête est complétée par des champs vides : sans interface, les objets
    de ce réseau sont à revoir.
    """
    entrees: dict[Reseau, Entree] = {}
    entete: tuple[str, ...] | None = None
    for numero, brut in enumerate(texte.splitlines(), start=1):
        ligne = brut.split("#", 1)[0].strip()
        if not ligne:
            continue
        champs = [champ.strip() for champ in ligne.split(";")]
        en_tete = tuple(champ.lower() for champ in champs)
        if entete is None:
            if en_tete not in ENTETES:
                raise ErreurLecture(
                    "reseaux.csv : en-tête attendu « reseau;site;vlan;interface » "
                    f"(ou un ancien en-tête avec colonne zone), lu « {ligne} »."
                )
            entete = en_tete
            continue
        if en_tete in ENTETES:
            continue
        if not 2 <= len(champs) <= len(entete):
            raise ErreurLecture(
                f"reseaux.csv ligne {numero} : {len(entete)} champs attendus ({';'.join(entete)})."
            )
        valeurs = dict(zip(entete, champs + [""] * (len(entete) - len(champs)), strict=True))
        brut_reseau, site = valeurs["reseau"], valeurs["site"].lower()
        brut_vlan, interface = valeurs.get("vlan", ""), valeurs.get("interface", "")
        if brut_vlan and not (brut_vlan.isdigit() and 1 <= int(brut_vlan) <= 4094):
            raise ErreurLecture(f"reseaux.csv ligne {numero} : VLAN invalide « {brut_vlan} » (1 à 4094).")
        vlan = int(brut_vlan) if brut_vlan else None
        try:
            reseau = ipaddress.ip_network(brut_reseau, strict=False)
        except ValueError as exc:
            raise ErreurLecture(f"reseaux.csv ligne {numero} : réseau invalide « {brut_reseau} ».") from exc
        if not re.fullmatch(r"[a-z0-9]+", site) or site in RESERVES:
            raise ErreurLecture(f"reseaux.csv ligne {numero} : site invalide « {valeurs['site']} ».")
        if interface and normaliser_interface(interface) in {"", *RESERVES}:
            raise ErreurLecture(f"reseaux.csv ligne {numero} : interface invalide « {interface} ».")
        entree = Entree(reseau=reseau, site=site, vlan=vlan, interface=interface or None)
        existante = entrees.get(reseau)
        if existante is not None and existante != entree:
            raise ErreurLecture(
                f"reseaux.csv ligne {numero} : {reseau} déjà déclaré avec un autre site, VLAN "
                "ou interface."
            )
        entrees[reseau] = entree
    return Referentiel(entrees=tuple(entrees.values()), source=source)


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
        commun(loc.interface for loc in liste),
    )


def depuis_nom(nom: str, sites: Collection[str], interfaces: Collection[str]) -> Localisation:
    """Premier site connu et interface connue cités dans le nom (segment entier, sinon suite de jetons)."""
    jetons = normaliser_chaine(nom).split("-")
    site = next((jeton for jeton in jetons if jeton in sites), None)
    segments = [normaliser_chaine(partie) for partie in nom.split("_")]
    interface = next((segment for segment in segments if segment in interfaces), None)
    if interface is None:
        for candidate in sorted(interfaces, key=lambda valeur: (-len(valeur), valeur)):
            cherches = candidate.split("-")
            if any(jetons[i : i + len(cherches)] == cherches for i in range(len(jetons))):
                interface = candidate
                break
    return Localisation(site or CTX, interface or CTX)


class Localisateur:
    """Site + interface de chaque objet d'un inventaire, calculés une fois.

    Les réseaux reçoivent en plus le VLAN et `exact` de l'entrée de reseaux.csv qui les contient.
    """

    def __init__(self, inventaire: Inventaire, referentiel: Referentiel):
        self.referentiel = referentiel
        self.sites = frozenset(referentiel.sites)
        self.interfaces = frozenset(referentiel.interfaces)
        self._adresses = {
            objet.nom: objet for objet in inventaire.objets if ESPACE[objet.sorte] == "adresse"
        }
        self._cache: dict[tuple[str, str], Localisation] = {}

    def nom(self, nom: str) -> Localisation:
        objet = self._adresses.get(nom)
        if objet is not None:
            return self.objet(objet)
        return depuis_nom(nom, self.sites, self.interfaces)

    def objet(self, objet: Objet) -> Localisation:
        cle = (objet.sorte, objet.nom)
        if cle in self._cache:
            return self._cache[cle]
        self._cache[cle] = INCONNUE
        resultat = self._calculer(objet)
        self._cache[cle] = resultat
        return resultat

    def _calculer(self, objet: Objet) -> Localisation:
        if objet.sorte == "reseau":
            return self._reseau(objet)
        if objet.sorte in {"hote", "plage", "pool"}:
            par_bornes = objet.sorte == "pool"
            trouvees = [
                loc
                for debut, fin in _plages(objet)
                if (loc := self._localiser_plage(debut, fin, par_bornes)) is not None
            ]
            return fusionner(trouvees) if trouvees else INCONNUE
        if objet.sorte == "vip":
            return self._vip(objet)
        par_nom = depuis_nom(objet.nom, self.sites, self.interfaces)
        if objet.sorte == "groupe-adresses":
            membres = fusionner(self.nom(membre) for membre in objet.mentions_adresses)
            interface = membres.interface if membres.interface != CTX else par_nom.interface
            return Localisation(membres.site, interface)
        return par_nom

    def _reseau(self, objet: Objet) -> Localisation:
        reseaux = _reseaux(objet)
        trouvees = {
            entree
            for reseau in reseaux
            if (entree := self.referentiel.entree(reseau.network_address, reseau.broadcast_address))
        }
        if not trouvees:
            return INCONNUE
        if len(trouvees) > 1:
            return fusionner(Localisation(entree.site, entree.cle_interface or CTX) for entree in trouvees)
        entree = trouvees.pop()
        return Localisation(
            entree.site,
            entree.cle_interface or CTX,
            vlan=entree.vlan,
            exact=all(reseau == entree.reseau for reseau in reseaux),
        )

    def _localiser_plage(
        self, debut: Adresse, fin: Adresse, par_bornes: bool = True
    ) -> Localisation | None:
        """Réseau contenant toute la plage ; sinon, si `par_bornes`, interfaces communes aux deux bornes."""
        entiere = self.referentiel.localiser(debut, fin)
        if entiere is not None or debut == fin or not par_bornes:
            return entiere
        bornes = [loc for loc in (self.referentiel.localiser(debut), self.referentiel.localiser(fin)) if loc]
        return fusionner(bornes) if bornes else None

    def _vip(self, objet: Objet) -> Localisation:
        """Interface de l'adresse interne (mappedip) seule ; inconnue : à revoir, sans repli sur le nom."""
        _genre, _externe, mappe, *_reste = objet.empreinte
        plage = _plage_texte(mappe)
        if plage is not None:
            return self._localiser_plage(*plage) or INCONNUE
        if mappe in self._adresses:
            loc = self.nom(mappe)
            return Localisation(loc.site, loc.interface)
        return INCONNUE


def _plages(objet: Objet) -> list[tuple[Adresse, Adresse]]:
    empreinte = objet.empreinte
    if objet.sorte == "pool":
        return [(ipaddress.ip_address(empreinte[0]), ipaddress.ip_address(empreinte[1]))]
    if objet.sorte == "plage":
        return [(ipaddress.ip_address(empreinte[1]), ipaddress.ip_address(empreinte[2]))]
    return [(reseau.network_address, reseau.broadcast_address) for reseau in _reseaux(objet)]


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
