"""Génération de reseaux.csv depuis une sauvegarde FortiGate : réseaux directement connectés."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from fwclean.fortigate import blocs
from fwclean.model import ErreurLecture
from fwclean.naming import cle_correspondance
from fwclean.sites import analyser_reseaux

_SECTIONS = frozenset({"system interface", "system zone", "system sdwan members"})


@dataclass(frozen=True)
class Ligne:
    reseau: str
    interface: str
    alias: str
    zone_fortigate: str | None
    zone: str | None


def reseaux_connectes(
    texte: str, contextes: Sequence[str], correspondances: Mapping[str, str]
) -> tuple[Ligne, ...]:
    """Une ligne par interface qui porte une IP ; zone FortiGate traduite par contextes.txt."""
    decoupe = blocs(texte, _SECTIONS)
    if not decoupe.get("system interface"):
        raise ErreurLecture("Aucune section « config system interface » dans l'export.")
    zone_de: dict[str, str] = {}
    for zone, data in decoupe.get("system zone", []):
        for interface in data.get("interface", []):
            zone_de[interface] = zone
    for _numero, data in decoupe.get("system sdwan members", []):
        interface = (data.get("interface") or [""])[0]
        zone = (data.get("zone") or [""])[0]
        if interface and zone:
            zone_de.setdefault(interface, zone)
    lignes: list[Ligne] = []
    for nom, data in decoupe["system interface"]:
        ip = data.get("ip") or []
        if len(ip) < 2 or ip[0] == "0.0.0.0":
            continue
        reseau = ipaddress.ip_network(f"{ip[0]}/{ip[1]}", strict=False)
        zone_fortigate = zone_de.get(nom)
        lignes.append(
            Ligne(
                reseau=str(reseau),
                interface=nom,
                alias=(data.get("alias") or [""])[0],
                zone_fortigate=zone_fortigate,
                zone=_traduire(zone_fortigate or nom, contextes, correspondances),
            )
        )
    return tuple(lignes)


def _traduire(nom: str, contextes: Sequence[str], correspondances: Mapping[str, str]) -> str | None:
    cle = cle_correspondance(nom)
    if cle in correspondances:
        return correspondances[cle]
    if cle in contextes:
        return cle
    return None


def ecrire_reseaux(lignes: Sequence[Ligne], site: str, source: str, contextes: Sequence[str]) -> str:
    site = site.strip().lower()
    entete = [
        f"# Référentiel réseaux généré par fwclean depuis {source}.",
        "# Réseaux directement connectés (config system interface) ; zone = zone FortiGate",
        "# (config system zone, zones SD-WAN) ou interface hors zone, traduite par contextes.txt.",
        "# Fichier réel : ignoré par git. Relire avant usage ; ajouter à la main les réseaux",
        "# non connectés (sites distants, pools VPN, IP publiques).",
        "reseau;site;zone",
    ]
    corps: list[str] = []
    a_completer: list[str] = []
    vus: set[str] = set()
    for ligne in lignes:
        origine = ligne.interface
        if ligne.alias and ligne.alias != ligne.interface:
            origine += f" ({ligne.alias})"
        if ligne.zone_fortigate:
            origine += f", zone {ligne.zone_fortigate}"
        else:
            origine += ", hors zone"
        if ligne.reseau in vus:
            a_completer.append(f"# {ligne.reseau} : déjà déclaré, ignoré — {origine}")
            continue
        if ligne.zone is None:
            nom = ligne.zone_fortigate or ligne.interface
            a_completer.append(
                f"# {ligne.reseau};{site};?  — {origine} : ajouter « <zone> = {nom} » dans contextes.txt"
            )
            continue
        vus.add(ligne.reseau)
        corps.append(f"{ligne.reseau};{site};{ligne.zone}  # {origine}")
    texte = "\n".join([*entete, *corps, *(["", "# À compléter :", *a_completer] if a_completer else [])])
    texte += "\n"
    analyser_reseaux(texte, contextes)
    return texte
