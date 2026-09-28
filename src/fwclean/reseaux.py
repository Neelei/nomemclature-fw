"""Génération de reseaux.csv depuis les interfaces : FortiGate (.conf) ou SNS (fichier Network)."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from fwclean.fortigate import blocs
from fwclean.model import ErreurLecture
from fwclean.naming import cle_correspondance
from fwclean.sites import analyser_reseaux
from fwclean.stormshield_natif import interfaces_natives, reseaux_interface

_SECTIONS = frozenset({"system interface", "system zone", "system sdwan members"})

_ENTETES = {
    "fortigate": (
        "# Réseaux directement connectés (config system interface) ; zone = zone FortiGate",
        "# (config system zone, zones SD-WAN) ou interface hors zone, traduite par contextes.txt.",
        "# vlan = vlanid de l'interface.",
    ),
    "stormshield": (
        "# Réseaux des interfaces SNS à adresse statique (fichier Network) ; zone = nom de",
        "# l'interface (Name), traduit par contextes.txt ; vlan = Tag de l'interface VLAN.",
    ),
}


@dataclass(frozen=True)
class Ligne:
    reseau: str
    interface: str
    alias: str
    zone_fortigate: str | None
    zone: str | None
    vlan: int | None = None
    desactivee: bool = False


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
        vlanid = (data.get("vlanid") or [""])[0]
        lignes.append(
            Ligne(
                reseau=str(reseau),
                interface=nom,
                alias=(data.get("alias") or [""])[0],
                zone_fortigate=zone_fortigate,
                zone=_traduire(zone_fortigate or nom, contextes, correspondances),
                vlan=int(vlanid) if vlanid.isdigit() else None,
            )
        )
    return tuple(lignes)


def reseaux_sns(
    texte: str, contextes: Sequence[str], correspondances: Mapping[str, str]
) -> tuple[Ligne, ...]:
    """Une ligne par adresse statique d'interface SNS (loopback exclue) ; zone d'après Name."""
    interfaces = interfaces_natives(texte)
    if not interfaces:
        raise ErreurLecture("Aucune interface ([ethernetN], [vlanN]…) dans le fichier Network.")
    lignes: list[Ligne] = []
    for interface in interfaces:
        section = interface["_section"]
        if section.lower().startswith("loopback"):
            continue
        nom = interface.get("Name") or section
        tag = interface.get("Tag", "")
        for reseau in dict.fromkeys(reseaux_interface(interface)):
            lignes.append(
                Ligne(
                    reseau=str(reseau),
                    interface=nom,
                    alias=section,
                    zone_fortigate=None,
                    zone=_traduire(nom, contextes, correspondances),
                    vlan=int(tag) if tag.isdigit() else None,
                    desactivee=interface.get("State") == "0",
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


def ecrire_reseaux(
    lignes: Sequence[Ligne],
    site: str,
    source: str,
    contextes: Sequence[str],
    constructeur: str = "fortigate",
) -> str:
    site = site.strip().lower()
    entete = [
        f"# Référentiel réseaux généré par fwclean depuis {source}.",
        *_ENTETES[constructeur],
        "# Fichier réel : ignoré par git. Relire avant usage ; ajouter à la main les réseaux",
        "# non connectés (sites distants, pools VPN, IP publiques).",
        "reseau;site;zone;vlan",
    ]
    corps: list[str] = []
    a_completer: list[str] = []
    vus: set[str] = set()
    for ligne in lignes:
        origine = _origine(ligne, constructeur)
        vlan = "" if ligne.vlan is None else str(ligne.vlan)
        if ligne.reseau in vus:
            a_completer.append(f"# {ligne.reseau} : déjà déclaré, ignoré — {origine}")
            continue
        if ligne.zone is None:
            nom = ligne.zone_fortigate or ligne.interface
            a_completer.append(
                f"# {ligne.reseau};{site};?;{vlan}  — {origine} : ajouter « <zone> = {nom} » dans contextes.txt"
            )
            continue
        if ligne.desactivee:
            a_completer.append(f"# {ligne.reseau};{site};{ligne.zone};{vlan}  — {origine} : interface désactivée")
            continue
        vus.add(ligne.reseau)
        corps.append(f"{ligne.reseau};{site};{ligne.zone};{vlan}  # {origine}")
    texte = "\n".join([*entete, *corps, *(["", "# À compléter :", *a_completer] if a_completer else [])])
    texte += "\n"
    analyser_reseaux(texte, contextes)
    return texte


def _origine(ligne: Ligne, constructeur: str) -> str:
    origine = ligne.interface
    if ligne.alias and ligne.alias != ligne.interface:
        origine += f" ({ligne.alias})"
    if constructeur == "stormshield":
        return origine
    if ligne.zone_fortigate:
        return origine + f", zone {ligne.zone_fortigate}"
    return origine + ", hors zone"
