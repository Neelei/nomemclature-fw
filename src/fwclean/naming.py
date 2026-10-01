"""Convention de nommage et liste des zones (contextes.txt)."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Collection, Sequence
from pathlib import Path

from fwclean.model import ErreurLecture

LONGUEUR_MAX = 79

# Séparateur des segments (site, type, zone, détail). Le tiret reste réservé au détail.
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
    """Lit les zones : clés stockées en minuscules, matching ensuite case-insensitive.

    CTX et MULTI sont toujours valables ; s'ils figurent dans le fichier, ils sont ignorés.
    """
    zones, _correspondances = _analyser_contextes(texte)
    return zones


def lire_correspondances(chemin: Path) -> dict[str, str]:
    """Noms FortiGate (zone ou interface) → zone courte, d'après les lignes « zone = nom, nom »."""
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
    signature: tuple[str, str] | None = None,
) -> bool:
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
    if "." in nom or any("-" in partie for partie in parties[:-1]):
        return False
    if sorte in SANS_LOCALISATION:
        return len(parties) == 2 and parties[0] == prefixe
    if len(parties) != 4 or parties[1] != prefixe:
        return False
    if not site_valide(parties[0], sites) or not zone_valide(parties[2], contextes):
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
    cles = {prefixe.lower(), *(ancien.lower() for ancien in ANCIENS_PREFIXES.get(prefixe, ()))}
    # Nom déjà découpé en SITE, PREFIXE, ZONE, … ou PREFIXE, SITE, ZONE, … :
    # l'autre segment de tête est l'ancien site, même inconnu.
    if len(jetons) >= 4 and cles & set(jetons[:2]) and zone_connue(jetons[2], contextes):
        return jetons[3:]
    if jetons and jetons[0] in cles:
        jetons = jetons[1:]
    elif len(jetons) >= 2 and jetons[1] in cles and site is not None and jetons[0] == site.lower():
        jetons = [jetons[0], *jetons[2:]]
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
) -> str:
    """{SITE}_{PREFIXE}_{ZONE}_{DETAIL}, ou {PREFIXE}_{DETAIL} sans site ni zone."""
    localise = site is not None and zone is not None
    detail = _detail_depuis_nom(nom, prefixe, contextes, site, zone)
    if vlan is not None:
        detail = _avec_vlan(detail, vlan)
    parties = [site, prefixe, zone] if localise else [prefixe]
    parties.append("-".join(detail) or "nd")
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
