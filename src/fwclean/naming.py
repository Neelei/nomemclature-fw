"""Convention de nommage et liste des zones (contextes.txt)."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Collection, Sequence
from pathlib import Path

from fwclean.model import ErreurLecture

LONGUEUR_MAX = 79

# Séparateur des segments (type, site, zone, détail). Le tiret reste réservé au détail.
SEP = "_"

# Limites FortiOS plus courtes que 79 (CLI reference, taille du champ name).
LIMITES = {
    ("fortigate", "calendrier"): 31,
}

# Valeurs réservées, valables comme site et comme zone :
# CTX = rien trouvé, MULTI = plusieurs sites ou zones parmi les membres.
CTX = "ctx"
MULTI = "multi"
RESERVES = frozenset({CTX, MULTI})

# Types sans site ni zone : {PREFIXE}_{DETAIL}.
SANS_LOCALISATION = frozenset({"service", "groupe-services", "calendrier"})

PREFIXE = {
    "hote": "HST",
    "reseau": "NET",
    "plage": "RNG",
    "fqdn": "FQDN",
    "groupe-adresses": "GRP",
    "service": "SVC",
    "groupe-services": "SGRP",
    "vip": "VIP",
    "pool": "POOL",
    "calendrier": "SCH",
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
    "groupe-services": "groupe de services",
    "vip": "vip",
    "pool": "pool",
    "calendrier": "calendrier",
}

LIBELLE_CONSTRUCTEUR = {
    "fortigate": "FortiGate",
    "stormshield": "Stormshield",
}

_FORME = re.compile(r"[A-Z0-9]+(?:[-_][A-Z0-9]+)*")


def lire_contextes(chemin: Path) -> tuple[str, ...]:
    return analyser_contextes(chemin.read_text(encoding="utf-8"))


def analyser_contextes(texte: str) -> tuple[str, ...]:
    """Lit les zones : clés stockées en minuscules, matching ensuite case-insensitive.

    CTX et MULTI sont toujours valables ; s'ils figurent dans le fichier, ils sont ignorés.
    """
    vus: list[str] = []
    for brut in texte.splitlines():
        ligne = brut.split("#", 1)[0].strip().lower()
        if not ligne:
            continue
        if not re.fullmatch(r"[a-z0-9]+", ligne):
            raise ErreurLecture(f"Contexte invalide : {ligne}")
        if ligne not in vus and ligne not in RESERVES:
            vus.append(ligne)
    if not vus:
        raise ErreurLecture("La liste de contextes est vide.")
    return tuple(vus)


def zone_connue(jeton: str, contextes: Sequence[str]) -> bool:
    cle = jeton.lower()
    return cle in RESERVES or cle in {contexte.lower() for contexte in contextes}


def normaliser_chaine(valeur: str) -> str:
    """Jetons internes en minuscules (matching contextes, en-têtes CSV)."""
    decompose = unicodedata.normalize("NFKD", valeur)
    sans_accent = "".join(c for c in decompose if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]+", "-", sans_accent.lower()).strip("-")


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


def tronquer(nom: str, limite: int = LONGUEUR_MAX, reserve: int = 0) -> str:
    """Raccourcit seulement le dernier segment (le détail) ; la structure reste entière."""
    if len(nom) + reserve <= limite:
        return nom
    if SEP not in nom:
        return _couper_detail(nom, max(1, limite - reserve))
    corps, detail = nom.rsplit(SEP, 1)
    place = max(1, limite - reserve - len(corps) - 1)
    return f"{corps}{SEP}{_couper_detail(detail, place)}"


def rendre_unique(base: str, reserves: set[str], limite: int = LONGUEUR_MAX) -> str:
    base = tronquer(base, limite)
    if base and base not in reserves:
        return base
    for numero in range(1, 100):
        suffixe = f"-{numero:02d}"
        candidat = f"{tronquer(base, limite, len(suffixe))}{suffixe}"
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


def est_conforme_objet(
    nom: str,
    sorte: str,
    contextes: Sequence[str],
    sites: Collection[str] = (),
    limite: int = LONGUEUR_MAX,
    vlan: int | None = None,
) -> bool:
    if not forme_valide(nom, limite):
        return False
    prefixe = PREFIXE.get(sorte)
    if prefixe is None:
        return False
    parties = nom.split(SEP)
    if any("-" in partie for partie in parties[:-1]) or parties[0] != prefixe:
        return False
    if sorte in SANS_LOCALISATION:
        return len(parties) == 2
    if len(parties) != 4:
        return False
    if not site_valide(parties[1], sites) or not zone_valide(parties[2], contextes):
        return False
    return vlan is None or f"VLAN{vlan}" in parties[3].split("-")


def _detail_depuis_nom(
    nom: str,
    prefixe: str,
    contextes: Sequence[str],
    site: str | None,
    zone: str | None,
) -> list[str]:
    """Jetons de l'ancien nom sans le préfixe, ni le site et la zone retenus."""
    jetons = [jeton for jeton in normaliser_chaine(nom).split("-") if jeton]
    if jetons and jetons[0] == prefixe.lower():
        jetons = jetons[1:]
        # Nom déjà découpé en PREFIXE, SITE, ZONE, … : le 2e segment est l'ancien site, même inconnu.
        if len(jetons) >= 3 and zone_connue(jetons[1], contextes):
            return jetons[2:]
    a_retirer = [valeur.lower() for valeur in (site, zone) if valeur]
    detail: list[str] = []
    for jeton in jetons:
        if jeton in a_retirer:
            a_retirer.remove(jeton)
        elif site is None or jeton not in RESERVES:
            detail.append(jeton)
    return detail


_VLAN = re.compile(r"v(?:la|al)n(\d+)")


def _avec_vlan(detail: list[str], vlan: int) -> list[str]:
    """VLAN ID de la config en tête du détail ; les mentions de VLAN de l'ancien nom sont retirées."""
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
    return [f"vlan{vlan}", *propre]


def proposer_objet(
    nom: str,
    prefixe: str,
    site: str | None,
    zone: str | None,
    contextes: Sequence[str],
    limite: int = LONGUEUR_MAX,
    vlan: int | None = None,
    libelle_defaut: str = "nd",
) -> str:
    """{PREFIXE}_{SITE}_{ZONE}_{DETAIL}, ou {PREFIXE}_{DETAIL} sans site ni zone."""
    localise = site is not None and zone is not None
    detail = _detail_depuis_nom(nom, prefixe, contextes, site, zone)
    if vlan is not None:
        detail = _avec_vlan(detail, vlan)
    parties = [prefixe, site, zone] if localise else [prefixe]
    parties.append("-".join(detail) or libelle_defaut)
    return tronquer(SEP.join(parties).upper(), limite)


_ICMP = {8: "echo", 0: "reply"}


def libelle_service(empreinte: tuple) -> str:
    """Protocole et port, pour un service dont l'ancien nom ne dit rien (TCP-443, UDP-67-68)."""
    if not empreinte:
        return "ip"
    proto = empreinte[0][0]
    morceaux: list[str] = []
    for protocole, plages in empreinte:
        for debut, fin, src_debut, src_fin in plages:
            if protocole in {"icmp", "icmp6"}:
                if debut < 0:
                    morceaux.append("any")
                else:
                    morceaux.append(_ICMP.get(debut, f"type{debut}"))
                continue
            morceaux.append(str(debut) if debut == fin else f"{debut}-{fin}")
            if src_debut >= 0:
                morceaux.append(str(src_debut) if src_debut == src_fin else f"s{src_debut}-{src_fin}")
    suite = [protocole for protocole, _plages in empreinte[1:]]
    return "-".join([proto, *suite, *morceaux])
