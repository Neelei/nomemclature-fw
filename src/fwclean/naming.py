"""Convention de nommage et liste des zones (contextes.txt)."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Collection, Sequence
from pathlib import Path
from typing import NamedTuple

from fwclean.model import ErreurLecture

LONGUEUR_MAX = 79

# Séparateur des segments (site, type, interface, détail). Le tiret sert dans le détail
# et dans les noms d'interfaces normalisés (LABO_ANA → LABO-ANA).
SEP = "_"

# Limites FortiOS plus courtes que 79 (CLI reference, taille du champ name).
LIMITES = {
    ("fortigate", "calendrier"): 31,
}

# Valeurs réservées, valables comme site et comme interface :
# CTX = rien trouvé (jamais proposé dans un nom), MULTI = plusieurs sites ou interfaces
# parmi les membres.
CTX = "ctx"
MULTI = "multi"
RESERVES = frozenset({CTX, MULTI})


class Localisation(NamedTuple):
    """Site et interface d'un objet (minuscules) ; VLAN et `exact` entrent dans les noms réseau.

    `zone` reste lue dans reseaux.csv (inventaire) et sert à retirer l'ancienne zone d'un
    nom déjà appliqué ; elle n'entre plus dans les noms proposés.
    `exact` : l'objet réseau est le réseau même de l'interface (pas un sous-réseau).
    """

    site: str
    interface: str
    zone: str | None = None
    vlan: int | None = None
    exact: bool = False

# Types sans site ni zone : {PREFIXE}_{DETAIL} (services : SVC_{PROTOCOLE}_{PORTS}_{LIBELLE}).
SANS_LOCALISATION = frozenset({"service", "protocole", "groupe-services", "calendrier"})

# Sortes nommées SVC_{PROTOCOLE}_{PORTS}_{LIBELLE} ; « protocole » : objet [Protocol] SNS (ipproto).
SORTES_SERVICE = frozenset({"service", "protocole"})

PREFIXE = {
    "hote": "HST",
    "reseau": "NET",
    "plage": "RNG",
    "fqdn": "FQDN",
    "groupe-adresses": "GRP",
    "service": "SVC",
    "protocole": "SVC",
    "groupe-services": "SG",
    "vip": "VIP",
    "pool": "POOL",
    "calendrier": "SCH",
}

# Anciens préfixes retirés du détail lors d'un renommage (SGRP_WEB → SG_WEB).
ANCIENS_PREFIXES = {
    "SG": ("SGRP",),
}

# Espace de noms des références (adresse, service, calendrier, pool).
ESPACE = {
    "hote": "adresse",
    "reseau": "adresse",
    "plage": "adresse",
    "fqdn": "adresse",
    "groupe-adresses": "adresse",
    "vip": "adresse",
    "service": "service",
    "protocole": "protocole",
    "groupe-services": "service",
    "calendrier": "calendrier",
    "pool": "pool",
}

LIBELLE = {
    "hote": "hôte",
    "reseau": "réseau",
    "plage": "plage",
    "fqdn": "fqdn",
    "groupe-adresses": "groupe d'adresses",
    "service": "service",
    "protocole": "protocole IP",
    "groupe-services": "groupe de services",
    "vip": "vip",
    "pool": "pool",
    "calendrier": "calendrier",
}

LIBELLE_CONSTRUCTEUR = {
    "fortigate": "FortiGate",
    "stormshield": "Stormshield",
}

_FORME = re.compile(r"[A-Z0-9]+(?:[-_.][A-Z0-9]+)*")


def lire_contextes(chemin: Path) -> tuple[str, ...]:
    return analyser_contextes(chemin.read_text(encoding="utf-8"))


def analyser_contextes(texte: str) -> tuple[str, ...]:
    """Lit les zones FortiGate courtes : clés en minuscules, matching ensuite case-insensitive.

    CTX et MULTI sont toujours valables ; s'ils figurent dans le fichier, ils sont ignorés.
    """
    zones, _correspondances = _analyser_contextes(texte)
    return zones


def lire_correspondances(chemin: Path) -> dict[str, str]:
    """Zones FortiGate → zone courte, d'après les lignes « zone = nom, nom »."""
    _zones, correspondances = _analyser_contextes(chemin.read_text(encoding="utf-8"))
    return correspondances


def cle_correspondance(nom: str) -> str:
    return re.sub(r"[^a-z0-9]", "", nom.lower())


def _analyser_contextes(texte: str) -> tuple[tuple[str, ...], dict[str, str]]:
    vus: list[str] = []
    correspondances: dict[str, str] = {}
    for brut in texte.splitlines():
        ligne = brut.split("#", 1)[0].strip()
        if not ligne:
            continue
        zone, _egal, noms = ligne.partition("=")
        zone = zone.strip().lower()
        if not re.fullmatch(r"[a-z0-9]+", zone):
            raise ErreurLecture(f"Contexte invalide : {zone}")
        if zone not in vus and zone not in RESERVES:
            vus.append(zone)
        for nom in noms.split(","):
            cle = cle_correspondance(nom)
            if not cle:
                continue
            if correspondances.get(cle, zone) != zone:
                raise ErreurLecture(f"contextes.txt : « {nom.strip()} » associé à deux zones.")
            correspondances[cle] = zone
    if not vus:
        raise ErreurLecture("La liste de contextes est vide.")
    return tuple(vus), correspondances


def zone_connue(jeton: str, contextes: Sequence[str]) -> bool:
    cle = jeton.lower()
    return cle in RESERVES or cle in {contexte.lower() for contexte in contextes}


def normaliser_chaine(valeur: str) -> str:
    """Jetons internes en minuscules (matching contextes, en-têtes CSV)."""
    decompose = unicodedata.normalize("NFKD", valeur)
    sans_accent = "".join(c for c in decompose if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]+", "-", sans_accent.lower()).strip("-")


def normaliser_interface(nom: str) -> str:
    """Segment interface d'un nom : `_`, espaces et autres signes deviennent `-` (WIFI INVITE → wifi-invite)."""
    return normaliser_chaine(nom)


def longueur_max(constructeur: str, sorte: str) -> int:
    return LIMITES.get((constructeur, sorte), LONGUEUR_MAX)


def forme_valide(nom: str, limite: int = LONGUEUR_MAX) -> bool:
    return bool(_FORME.fullmatch(nom)) and len(nom) <= limite


def _couper_detail(detail: str, place: int) -> str:
    if len(detail) <= place:
        return detail
    coupe = detail[:place]
    if "-" in coupe and detail[place] != "-":
        coupe = coupe.rsplit("-", 1)[0]
    return coupe.rstrip("-") or detail[:place]


def tronquer(nom: str, limite: int = LONGUEUR_MAX, reserve: int = 0, protege: int = 0) -> str:
    """Raccourcit seulement le détail ; la structure reste entière.

    `protege` : longueur de tête du dernier segment à garder (interface d'un nom réseau
    INTERFACE-DETAIL) ; elle n'est coupée que si elle ne tient pas seule.
    """
    if len(nom) + reserve <= limite:
        return nom
    if SEP not in nom:
        return _couper_detail(nom, max(1, limite - reserve))
    corps, detail = nom.rsplit(SEP, 1)
    if protege:
        tete, reste = detail[:protege], detail[protege + 1 :]
        place = limite - reserve - len(corps) - len(tete) - 2
        if reste and place >= 1:
            return f"{corps}{SEP}{tete}-{_couper_detail(reste, place)}"
        if len(corps) + len(tete) + 1 + reserve <= limite:
            return f"{corps}{SEP}{tete}"
    place = max(1, limite - reserve - len(corps) - 1)
    return f"{corps}{SEP}{_couper_detail(detail, place)}"


def rendre_unique(base: str, reserves: set[str], limite: int = LONGUEUR_MAX, protege: int = 0) -> str:
    base = tronquer(base, limite, protege=protege)
    if base and base not in reserves:
        return base
    for numero in range(1, 100):
        suffixe = f"-{numero:02d}"
        candidat = f"{tronquer(base, limite, len(suffixe), protege)}{suffixe}"
        if candidat not in reserves:
            return candidat
    raise ErreurLecture(f"Impossible de proposer un nom unique à partir de {base}.")


def site_valide(jeton: str, sites: Collection[str]) -> bool:
    """Site utilisable dans un nom : connu de reseaux.csv, ou MULTI. CTX n'est jamais proposé."""
    cle = jeton.lower()
    return cle == MULTI or cle in {site.lower() for site in sites}


def zone_valide(jeton: str, contextes: Sequence[str]) -> bool:
    cle = jeton.lower()
    return cle == MULTI or cle in {contexte.lower() for contexte in contextes}


_SEGMENT_VLAN = re.compile(r"v\d+")


def segments_reseau(localisation: Localisation) -> list[str]:
    """Segments d'un nom réseau avant le dernier : SITE, NET, [V{ID}] (minuscules)."""
    segments = [localisation.site, PREFIXE["reseau"].lower()]
    if localisation.vlan is not None:
        segments.append(f"v{localisation.vlan}")
    return segments


def est_conforme_objet(
    nom: str,
    sorte: str,
    contextes: Sequence[str],
    sites: Collection[str] = (),
    limite: int = LONGUEUR_MAX,
    signature: tuple[str, str] | None = None,
    interfaces: Collection[str] = (),
    attendu: Localisation | None = None,
) -> bool:
    """Forme du nom ; si `attendu` est connu (site et interface), segments identiques à lui.

    Sans localisation connue, seules la forme et l'appartenance du site et de l'interface
    à reseaux.csv sont vérifiées.
    """
    if not forme_valide(nom, limite):
        return False
    prefixe = PREFIXE.get(sorte)
    if prefixe is None:
        return False
    parties = nom.split(SEP)
    if sorte in SORTES_SERVICE:
        return (
            signature is not None
            and len(parties) in {3, 4}
            and tuple(parties[1:3]) == signature
            and parties[0] == prefixe
            and all("." not in partie for partie in parties[3:])
        )
    if "." in nom:
        return False
    if sorte in SANS_LOCALISATION:
        return len(parties) == 2 and parties[0] == prefixe
    if len(parties) < 3 or parties[1] != prefixe or not site_valide(parties[0], sites):
        return False
    minuscules = [partie.lower() for partie in parties]
    if attendu is not None and CTX not in (attendu.site, attendu.interface):
        if sorte != "reseau":
            return len(parties) == 4 and minuscules[:3] == [attendu.site, prefixe.lower(), attendu.interface]
        corps = segments_reseau(attendu)
        dernier = minuscules[-1]
        return (
            minuscules[:-1] == corps
            and len(parties) == len(corps) + 1
            and (
                dernier == attendu.interface
                or (not attendu.exact and dernier.startswith(f"{attendu.interface}-"))
            )
        )
    connues = {interface.lower() for interface in interfaces} | {MULTI}
    if sorte != "reseau":
        return len(parties) == 4 and minuscules[2] in connues
    *milieu, dernier = minuscules[2:]
    # Milieu : éventuellement un seul segment VLAN (v\d+) ; plus de zone.
    if len(milieu) > 1 or (milieu and not _SEGMENT_VLAN.fullmatch(milieu[0])):
        return False
    return any(dernier == interface or dernier.startswith(f"{interface}-") for interface in connues)


def _sequence(jetons: list[str], cherches: list[str]) -> int | None:
    """Position de la suite `cherches` dans `jetons`."""
    taille = len(cherches)
    for debut in range(len(jetons) - taille + 1):
        if jetons[debut : debut + taille] == cherches:
            return debut
    return None


def _detail_depuis_nom(
    nom: str,
    prefixe: str,
    contextes: Sequence[str],
    localisation: Localisation | None = None,
    interfaces: Collection[str] = (),
) -> list[str]:
    """Jetons de l'ancien nom sans le préfixe, ni le site, la zone, le VLAN et l'interface.

    Un nom déjà découpé en SITE_PREFIXE_… ou PREFIXE_SITE_… (ancienne convention avec zone,
    HQ_NET_LAN_VLAN11-RES / HQ_NET_LAN_V11_…, ou forme actuelle HQ_NET_V11_…) ne garde que
    son dernier segment, moins l'interface en tête : l'ancienne zone n'est jamais recopiée
    dans le détail.
    """
    cles = {prefixe.lower(), *(ancien.lower() for ancien in ANCIENS_PREFIXES.get(prefixe, ()))}
    reseau = prefixe == PREFIXE["reseau"]
    site = localisation.site if localisation else None
    connues = sorted(
        {
            interface.lower()
            for interface in (localisation.interface if localisation else None, *interfaces)
            if interface and interface.lower() not in RESERVES
        },
        key=lambda interface: (-len(interface), interface),
    )
    segments = [segment for segment in (normaliser_chaine(partie) for partie in nom.split(SEP)) if segment]
    structure = (len(segments) >= 3 and segments[1] in cles) or (len(segments) >= 4 and segments[0] in cles)
    if structure:
        reste = segments[2:]
        if len(reste) > 1:
            reste = reste[1:]
        while len(reste) > 1 and (
            _SEGMENT_VLAN.fullmatch(reste[0])
            or _VLAN.fullmatch(reste[0])
            or reste[0] in connues
            or reste[0] in RESERVES
            or zone_connue(reste[0], contextes)
        ):
            reste = reste[1:]
        jetons = "-".join(reste).split("-")
        for interface in connues:
            cherches = interface.split("-")
            if jetons[: len(cherches)] == cherches:
                jetons = jetons[len(cherches) :]
                break
    else:
        jetons = [jeton for jeton in normaliser_chaine(nom).split("-") if jeton]
        if jetons and jetons[0] in cles:
            jetons = jetons[1:]
        elif len(jetons) >= 2 and jetons[1] in cles and site is not None and jetons[0] == site:
            jetons = [jetons[0], *jetons[2:]]
        if localisation is not None and localisation.interface not in RESERVES:
            cherches = localisation.interface.split("-")
            position = _sequence(jetons, cherches)
            if position is not None:
                jetons = jetons[:position] + jetons[position + len(cherches) :]
        a_retirer = [site] if site else []
        if reseau and localisation is not None and localisation.zone:
            a_retirer.append(localisation.zone)
        detail: list[str] = []
        for jeton in jetons:
            if jeton in a_retirer:
                a_retirer.remove(jeton)
            elif localisation is None or jeton not in RESERVES:
                detail.append(jeton)
        jetons = detail
    return _sans_vlan(jetons) if reseau else jetons


_VLAN = re.compile(r"v(?:la|al)n(\d+)")


def _sans_vlan(detail: list[str]) -> list[str]:
    """Retire les mentions de VLAN de l'ancien nom (VLAN11, VLAN-11) : le VLAN a son segment."""
    propre: list[str] = []
    index = 0
    while index < len(detail):
        jeton = detail[index]
        if _VLAN.fullmatch(jeton):
            index += 1
            continue
        if jeton in {"vlan", "valn"} and index + 1 < len(detail) and detail[index + 1].isdigit():
            index += 2
            continue
        propre.append(jeton)
        index += 1
    return propre


def proposer_objet(
    nom: str,
    prefixe: str,
    localisation: Localisation | None = None,
    contextes: Sequence[str] = (),
    limite: int = LONGUEUR_MAX,
    interfaces: Collection[str] = (),
) -> str:
    """Nom proposé selon la sorte :

    - réseau : {SITE}_NET_[V{VLAN}_]{INTERFACE}, suivi de -{DETAIL} pour un sous-réseau ;
    - autre objet localisé : {SITE}_{PREFIXE}_{INTERFACE}_{DETAIL} ;
    - sans localisation (services, calendriers…) : {PREFIXE}_{DETAIL}.
    """
    detail = _detail_depuis_nom(nom, prefixe, contextes, localisation, interfaces)
    if localisation is None:
        return tronquer(SEP.join([prefixe, "-".join(detail) or "nd"]).upper(), limite)
    interface = localisation.interface
    if prefixe == PREFIXE["reseau"]:
        dernier = interface if localisation.exact or not detail else f"{interface}-{'-'.join(detail)}"
        nom_propose = SEP.join([*segments_reseau(localisation), dernier]).upper()
        return tronquer(nom_propose, limite, protege=len(interface))
    parties = [localisation.site, prefixe, interface, "-".join(detail) or "nd"]
    return tronquer(SEP.join(parties).upper(), limite)


_JETONS_PROTOCOLE = frozenset({"svc", "tcp", "udp", "sctp", "any", "icmp", "icmp6", "ip"})


def signature_service(empreinte: tuple) -> tuple[str, str]:
    """(PROTOCOLE, PORTS) du contenu : ANY pour TCP et UDP ensemble, plage 67-68, liste 88.464."""
    protocoles = {protocole for protocole, _plages in empreinte}
    if not protocoles:
        return "IP", "ANY"
    if len(protocoles) > 1:
        protocole = "ANY" if protocoles <= {"tcp", "udp", "sctp"} else "MULTI"
    else:
        protocole = next(iter(protocoles)).upper()
    bornes = sorted({(debut, fin) for _proto, plages in empreinte for debut, fin, *_src in plages})
    if protocole in {"ICMP", "ICMP6"}:
        types = [str(debut) for debut, _fin in bornes if debut >= 0]
        return protocole, ".".join(types) or "ANY"
    if protocole == "IP":
        numeros = [str(debut) for debut, _fin in bornes if debut > 0]
        return protocole, ".".join(numeros) or "ANY"
    return protocole, ".".join(str(d) if d == f else f"{d}-{f}" for d, f in bornes)


def proposer_service(nom: str, empreinte: tuple, limite: int = LONGUEUR_MAX) -> str:
    """SVC_{PROTOCOLE}_{PORTS}_{LIBELLE} ; le libellé vient de l'ancien nom, sans protocole ni port."""
    protocole, ports = signature_service(empreinte)
    nombres = set(re.split(r"[.-]", ports))
    libelle = [
        jeton
        for jeton in normaliser_chaine(nom).split("-")
        if jeton and jeton not in _JETONS_PROTOCOLE and jeton not in nombres
    ]
    parties = ["SVC", protocole, ports]
    if libelle:
        parties.append("-".join(libelle))
    return tronquer(SEP.join(parties).upper(), limite)
