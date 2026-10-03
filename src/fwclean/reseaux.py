"""Génération de reseaux.csv depuis les interfaces : FortiGate (.conf) ou SNS (fichier Network)."""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from fwclean.fortigate import blocs
from fwclean.model import ErreurLecture
from fwclean.naming import cle_correspondance, normaliser_interface
from fwclean.sites import ENTETE_INTERFACE, ENTETES, Entree, analyser_reseaux
from fwclean.stormshield_natif import interfaces_natives, reseaux_interface

_SECTIONS = frozenset({"system interface", "system zone", "system sdwan members"})

_ENTETES = {
    "fortigate": (
        "# Réseaux directement connectés (config system interface). zone = zone FortiGate",
        "# (config system zone, zones SD-WAN) traduite par contextes.txt, vide hors zone ;",
        "# vlan = vlanid ; interface = alias de l'interface (set alias), à défaut son nom ;",
        "# à remplacer à la main s'il ne dit rien.",
    ),
    "stormshield": (
        "# Réseaux des interfaces SNS à adresse statique (fichier Network). zone toujours vide",
        "# (pas de zones SNS) ; vlan = Tag de l'interface VLAN ; interface = Name de l'interface.",
    ),
}

# Noms d'interfaces qui ne disent rien du réseau (port3, VLAN-16, ethernet4…).
_PEU_PARLANT = re.compile(r"(?:port|ethernet|eth|vlan|valn|wan|x|agg|ha|internal|ipsec|vti)[-_ ]?\d+", re.IGNORECASE)


def peu_parlant(nom: str) -> bool:
    return bool(_PEU_PARLANT.fullmatch(nom.strip()))


@dataclass(frozen=True)
class Ligne:
    """`interface` : nom technique (FortiGate) ou Name (SNS) ; `colonne` : valeur écrite dans reseaux.csv."""

    reseau: str
    interface: str
    alias: str
    zone_fortigate: str | None
    zone: str | None
    vlan: int | None = None
    desactivee: bool = False
    colonne: str | None = None

    @property
    def nom_csv(self) -> str:
        return self.colonne or self.interface

    @property
    def sans_alias(self) -> bool:
        """Interface FortiGate sans `set alias` : son nom technique est écrit à la place."""
        return self.colonne is not None and not self.alias

    @property
    def zone_non_traduite(self) -> bool:
        return self.zone_fortigate is not None and self.zone is None


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
        alias = (data.get("alias") or [""])[0].strip()
        lignes.append(
            Ligne(
                reseau=str(reseau),
                interface=nom,
                alias=alias,
                zone_fortigate=zone_fortigate,
                zone=_traduire(zone_fortigate, contextes, correspondances) if zone_fortigate else None,
                vlan=int(vlanid) if vlanid.isdigit() else None,
                colonne=alias or nom,
            )
        )
    return tuple(lignes)


def reseaux_sns(texte: str) -> tuple[Ligne, ...]:
    """Une ligne par adresse statique d'interface SNS (loopback exclue) ; interface = Name."""
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
                    zone=None,
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


def _champs(ligne: Ligne, site: str, zone: str | None = None) -> str:
    vlan = "" if ligne.vlan is None else str(ligne.vlan)
    return f"{ligne.reseau};{site};{zone or ligne.zone or ''};{vlan};{ligne.nom_csv}"


def _remarques(lignes: Sequence[Ligne]) -> dict[str, str]:
    """Interface → remarque sur la valeur écrite : sans alias, peu parlante, même nom une fois normalisé."""
    par_cle: dict[str, set[str]] = defaultdict(set)
    for ligne in lignes:
        par_cle[normaliser_interface(ligne.nom_csv)].add(ligne.nom_csv)
    remarques: dict[str, str] = {}
    for ligne in lignes:
        notes: list[str] = []
        if ligne.sans_alias:
            notes.append("sans alias : nom de l'interface")
        if peu_parlant(ligne.nom_csv):
            par_alias = ligne.nom_csv != ligne.interface
            suggestion = f" (nom : {ligne.interface})" if par_alias and not peu_parlant(ligne.interface) else ""
            notes.append(f"{'alias' if par_alias else 'nom'} peu parlant{suggestion}")
        homonymes = sorted(par_cle[normaliser_interface(ligne.nom_csv)] - {ligne.nom_csv})
        if homonymes:
            notes.append(f"même nom normalisé que {', '.join(homonymes)}")
        if notes:
            remarques[ligne.interface] = " — " + " ; ".join(notes)
    return remarques


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
        ";".join(ENTETE_INTERFACE),
    ]
    remarques = _remarques(lignes)
    corps: list[str] = []
    a_completer: list[str] = []
    vus: set[str] = set()
    for ligne in lignes:
        origine = _origine(ligne, constructeur)
        if ligne.reseau in vus:
            a_completer.append(f"# {ligne.reseau} : déjà déclaré, ignoré — {origine}")
            continue
        if ligne.zone_non_traduite:
            a_completer.append(
                f"# {_champs(ligne, site, '?')}  — {origine} : "
                f"ajouter « <zone> = {ligne.zone_fortigate} » dans contextes.txt"
            )
            continue
        if ligne.desactivee:
            a_completer.append(f"# {_champs(ligne, site)}  — {origine} : interface désactivée")
            continue
        vus.add(ligne.reseau)
        corps.append(f"{_champs(ligne, site)}  # {origine}{remarques.get(ligne.interface, '')}")
    texte = "\n".join([*entete, *corps, *(["", "# À compléter :", *a_completer] if a_completer else [])])
    texte += "\n"
    analyser_reseaux(texte, contextes)
    return texte


@dataclass(frozen=True)
class Completion:
    texte: str
    ajoutees: tuple[str, ...]
    presentes: tuple[str, ...]
    differentes: tuple[str, ...]
    ecartees: tuple[str, ...]
    migrees: tuple[str, ...] = ()
    alias_appliques: tuple[str, ...] = ()


def completer_reseaux(
    existant: str,
    lignes: Sequence[Ligne],
    site: str,
    source: str,
    contextes: Sequence[str],
    constructeur: str = "fortigate",
) -> Completion:
    """Complète un reseaux.csv existant sans toucher aux lignes déjà renseignées.

    - réseaux absents : ajoutés en fin de fichier ;
    - lignes du même site sans interface (ancien format) : réécrites avec zone, VLAN et
      interface de l'équipement, l'ancienne zone gardée en commentaire si elle change ;
    - lignes FortiGate qui portent encore le nom technique de l'interface : nom remplacé par
      l'alias (une interface renommée à la main n'est pas touchée) ;
    - en-tête à 3 ou 4 colonnes : passé à `reseau;site;zone;vlan;interface`.
    Les autres lignes, commentaires et les sites saisis à la main restent tels quels.
    """
    site = site.strip().lower()
    entrees = {entree.reseau: entree for entree in analyser_reseaux(existant, contextes).entrees}
    remarques = _remarques(lignes)
    lignes_texte = existant.splitlines()
    position = _positions(lignes_texte)
    ajoutees: list[str] = []
    presentes: list[str] = []
    differentes: list[str] = []
    ecartees: list[str] = []
    migrees: list[str] = []
    alias_appliques: list[str] = []
    for ligne in lignes:
        origine = _origine(ligne, constructeur)
        reseau = ipaddress.ip_network(ligne.reseau, strict=False)
        if ligne.zone_non_traduite:
            ecartees.append(f"{ligne.reseau} ({ligne.zone_fortigate}) : zone non traduite")
            continue
        if ligne.desactivee:
            ecartees.append(f"{ligne.reseau} ({origine}) : interface désactivée")
            continue
        voulu = Entree(reseau=reseau, site=site, zone=ligne.zone, vlan=ligne.vlan, interface=ligne.nom_csv)
        existante = entrees.get(reseau)
        commentaire = f"  # {origine}{remarques.get(ligne.interface, '')}"
        if existante is None:
            ajoutees.append(_champs(ligne, site) + commentaire)
            entrees[reseau] = voulu
            continue
        if existante.interface is None and existante.site == site and reseau in position:
            ancienne = _zone_ecrite(lignes_texte[position[reseau]])
            if ancienne and ancienne != (ligne.zone or ""):
                commentaire += f" — ancienne zone : {ancienne}"
            lignes_texte[position[reseau]] = _champs(ligne, site) + commentaire
            migrees.append(f"{reseau} ({origine})")
            entrees[reseau] = voulu
            continue
        vlan_contraire = ligne.vlan is not None and existante.vlan not in (None, ligne.vlan)
        if (
            existante.interface == ligne.interface != ligne.nom_csv
            and (existante.site, existante.zone) == (site, ligne.zone)
            and not vlan_contraire
            and reseau in position
        ):
            ancienne = re.search(r" — ancienne zone : \S+", lignes_texte[position[reseau]])
            lignes_texte[position[reseau]] = _champs(ligne, site) + commentaire + (ancienne.group(0) if ancienne else "")
            alias_appliques.append(f"{reseau} : {ligne.interface} → {ligne.nom_csv}")
            entrees[reseau] = voulu
            continue
        memes = (existante.site, existante.zone, existante.interface) == (site, ligne.zone, ligne.nom_csv)
        if memes and not vlan_contraire:
            presentes.append(f"{reseau} ({origine})")
        else:
            differentes.append(f"{reseau} : fichier {_decrire(existante)}, interface {origine} {_decrire(voulu)}")
    if not (ajoutees or migrees or alias_appliques):
        return Completion(existant, (), tuple(presentes), tuple(differentes), tuple(ecartees))
    _passer_en_5_colonnes(lignes_texte)
    texte = "\n".join(lignes_texte) + "\n"
    if ajoutees:
        texte += "\n".join(["", f"# Ajouté par fwclean reseaux --ajouter depuis {source} :", *ajoutees]) + "\n"
    analyser_reseaux(texte, contextes)
    return Completion(
        texte,
        tuple(ajoutees),
        tuple(presentes),
        tuple(differentes),
        tuple(ecartees),
        tuple(migrees),
        tuple(alias_appliques),
    )


def _decrire(entree: Entree) -> str:
    vlan = "" if entree.vlan is None else str(entree.vlan)
    return f"{entree.site};{entree.zone or ''};{vlan};{entree.interface or ''}"


def _donnees(brut: str) -> list[str]:
    ligne = brut.split("#", 1)[0].strip()
    return [champ.strip() for champ in ligne.split(";")] if ligne else []


def _positions(lignes: Sequence[str]) -> dict:
    """Réseau → index de sa ligne dans le fichier."""
    positions = {}
    for index, brut in enumerate(lignes):
        champs = _donnees(brut)
        if not champs:
            continue
        try:
            reseau = ipaddress.ip_network(champs[0], strict=False)
        except ValueError:
            continue
        positions.setdefault(reseau, index)
    return positions


def _zone_ecrite(brut: str) -> str:
    champs = _donnees(brut)
    return champs[2].lower() if len(champs) > 2 else ""


def _passer_en_5_colonnes(lignes: list[str]) -> None:
    """Premier en-tête remplacé par reseau;site;zone;vlan;interface (les lignes plus courtes restent lues)."""
    for index, brut in enumerate(lignes):
        champs = _donnees(brut)
        if not champs:
            continue
        if tuple(champ.lower() for champ in champs) in ENTETES:
            reste = brut[len(brut.split("#", 1)[0].rstrip()) :]
            lignes[index] = ";".join(ENTETE_INTERFACE) + reste
        return


def _origine(ligne: Ligne, constructeur: str) -> str:
    origine = ligne.interface
    if ligne.alias and ligne.alias != ligne.interface:
        origine += f" ({ligne.alias})"
    if constructeur == "stormshield":
        return origine
    if ligne.zone_fortigate:
        return origine + f", zone {ligne.zone_fortigate}"
    return origine + ", hors zone"
