"""Convention de nommage et liste des zones (contextes.txt)."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Collection, Sequence
from pathlib import Path

from fwclean.model import ErreurLecture

LONGUEUR_MAX = 79

# Valeurs réservées, valables comme site et comme zone :
# CTX = rien trouvé, MULTI = plusieurs sites ou zones parmi les membres.
CTX = "ctx"
MULTI = "multi"
RESERVES = frozenset({CTX, MULTI})

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
    "regle": "règle",
}

LIBELLE_CONSTRUCTEUR = {
    "fortigate": "FortiGate",
    "stormshield": "Stormshield",
}

PROTOCOLES = frozenset({"TCP", "UDP", "ICMP", "ICMP6", "IP", "SCTP", "ANY"})

_FORME = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)*")


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


def site_connu(jeton: str, sites: Collection[str]) -> bool:
    cle = jeton.lower()
    return cle in RESERVES or cle in {site.lower() for site in sites}


def normaliser_chaine(valeur: str) -> str:
    """Jetons internes en minuscules (matching contextes, en-têtes CSV)."""
    decompose = unicodedata.normalize("NFKD", valeur)
    sans_accent = "".join(c for c in decompose if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]+", "-", sans_accent.lower()).strip("-")


def forme_valide(nom: str) -> bool:
    return bool(_FORME.fullmatch(nom)) and len(nom) <= LONGUEUR_MAX


def tronquer(nom: str, limite: int = LONGUEUR_MAX) -> str:
    if len(nom) <= limite:
        return nom
    coupe = nom[:limite]
    if "-" in coupe:
        coupe = coupe.rsplit("-", 1)[0]
    return coupe.rstrip("-") or nom[:limite]


def rendre_unique(base: str, reserves: set[str]) -> str:
    if base and base not in reserves and len(base) <= LONGUEUR_MAX:
        return base
    for numero in range(1, 100):
        suffixe = f"-{numero:02d}"
        corps = tronquer(base, LONGUEUR_MAX - len(suffixe)).rstrip("-")
        candidat = f"{corps}{suffixe}"
        if candidat not in reserves:
            return candidat
    raise ErreurLecture(f"Impossible de proposer un nom unique à partir de {base}.")


def est_conforme_objet(
    nom: str, sorte: str, contextes: Sequence[str], sites: Collection[str] = ()
) -> bool:
    if not forme_valide(nom):
        return False
    parties = nom.split("-")
    if sorte == "service":
        return len(parties) >= 3 and parties[0] == "SVC" and parties[1] in PROTOCOLES
    prefixe = PREFIXE.get(sorte)
    if prefixe is None:
        return False
    return (
        len(parties) >= 4
        and parties[0] == prefixe
        and site_connu(parties[1], sites)
        and zone_connue(parties[2], contextes)
    )


def est_conforme_regle(
    nom: str, action: str, contextes: Sequence[str], sites: Collection[str] = ()
) -> bool:
    if not forme_valide(nom):
        return False
    parties = nom.split("-")
    if len(parties) < 5 or parties[0] not in {"ALLOW", "DENY"}:
        return False
    if parties[0] != action.upper():
        return False
    if not site_connu(parties[1], sites):
        return False
    if not zone_connue(parties[2], contextes) or not zone_connue(parties[3], contextes):
        return False
    reste = parties[4:]
    if re.fullmatch(r"\d{2}", reste[-1]) and not (len(reste) >= 2 and reste[-2] in PROTOCOLES):
        if len(reste) == 1:
            return False
        reste = reste[:-1]
    return len(reste) >= 1


def proposer_objet(
    nom: str,
    prefixe: str,
    site: str,
    zone: str,
    contextes: Sequence[str],
    sites: Collection[str] = (),
) -> str:
    """Retire de l'ancien nom le préfixe, un jeton site et un jeton zone ; le reste fait le détail."""
    jetons = [jeton for jeton in normaliser_chaine(nom).split("-") if jeton]
    site_vu = zone_vue = False
    if jetons and jetons[0] == prefixe.lower():
        jetons = jetons[1:]
        # Nom déjà en {PREFIXE}-{SITE}-{ZONE}-… : le 2e segment est l'ancien site, même inconnu.
        if len(jetons) >= 3 and zone_connue(jetons[1], contextes):
            jetons = jetons[2:]
            site_vu = zone_vue = True
    detail: list[str] = []
    for jeton in jetons:
        if not site_vu and jeton in {site.lower() for site in sites}:
            site_vu = True
        elif not zone_vue and zone_connue(jeton, contextes):
            zone_vue = True
        elif jeton not in RESERVES:
            detail.append(jeton)
    if not detail:
        detail = ["nd"]
    return tronquer("-".join([prefixe, site, zone, *detail])).upper()


_ICMP = {8: "echo", 0: "reply"}


def proposer_service(empreinte: tuple) -> str:
    """Nom canonique SVC-{PROTOCOLE}-{PORT} à partir du contenu du service."""
    if not empreinte:
        return "SVC-IP-ND"
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
    if len(empreinte) > 1:
        suite = "-".join(protocole for protocole, _plages in empreinte[1:])
        detail = "-".join([suite, *morceaux]) if morceaux else suite
    else:
        detail = "-".join(morceaux) if morceaux else "service"
    return tronquer(f"svc-{proto}-{detail}").upper()


def jeton_service(noms: Sequence[str]) -> str:
    if len(noms) != 1:
        return "multi"
    normalise = normaliser_chaine(noms[0])
    if normalise.startswith("svc-"):
        normalise = normalise[len("svc-") :]
    elif normalise.startswith("sgrp-"):
        jetons = normalise[len("sgrp-") :].split("-")
        # SGRP-{SITE}-{ZONE}-{DETAIL} : seul le détail décrit le service.
        normalise = "-".join(jetons[2:] if len(jetons) >= 3 else jetons)
    return normalise or "service"


def proposer_regle(
    action: str,
    site: str,
    zone_source: str,
    zone_destination: str,
    services: Sequence[str],
) -> str:
    service = jeton_service(services)
    return tronquer(f"{action}-{site}-{zone_source}-{zone_destination}-{service}").upper()
