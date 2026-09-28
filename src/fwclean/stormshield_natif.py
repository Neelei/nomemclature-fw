"""Lecture des fichiers de configuration natifs d'un SNS (/usr/Firewall/ConfigFiles).

Fichiers lus : object, objectgroup, servicegroup, Filter (ou les slots du dossier Filter/),
Network, route. Reconnus mais pas lus (non gérés) : router, dossier global/.
Format INI : sections [Host], [Network], [Service]…, une ligne « nom=valeur  # commentaire »
par objet ; une section par groupe avec un membre par ligne ; une règle par ligne.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Sequence
from dataclasses import replace

from fwclean.contenu import (
    canon_ip,
    detail_ip,
    detail_service,
    empreinte_service,
    fqdn_cle,
    membres_tries,
)
from fwclean.model import ErreurLecture, Inventaire, Lien, Objet, Regle

Reseau = ipaddress.IPv4Network | ipaddress.IPv6Network

LUS = ("object", "objectgroup", "servicegroup", "filter", "network", "route")
NON_LUS = ("router",)
FICHIERS = LUS + NON_LUS

# Sans ces fichiers, un membre de groupe paraîtrait orphelin. Routeurs et objets globaux SMC
# ne sont pas gérés (décision) : ils font l'objet d'un avertissement, pas d'une suspension.
REQUIS_POUR_RETRAITS = ("objectgroup", "servicegroup")
_RISQUES = {
    "objectgroup": "un membre de groupe d'adresses",
    "servicegroup": "un membre de groupe de services",
}

AVERTISSEMENT_NON_GERES = (
    "Objets globaux SMC (global_*, Global_*) et objets routeur non lus : un hôte qui ne sert "
    "que de passerelle dans un objet routeur, ou qui n'est cité que par des objets globaux, "
    "peut apparaître à tort comme orphelin. À vérifier avant suppression."
)
VERIFIER_USAGE = (
    "Seuls Filter, route et les groupes sont lus comme références : un objet utilisé ailleurs "
    "(VPN IPsec ou SSL, DHCP, proxys, authentification, slots de filtrage non fournis) paraît "
    "orphelin. Avant chaque suppression, lancer « Vérifier l'utilisation » sur l'objet dans le SNS."
)

# Valeurs de règle qui ne sont pas des objets de la configuration.
_IMPLICITES = {"any", "internet", "none", "original"}
# Objets créés par le SNS lui-même (adresses du firewall, réseaux des interfaces, ports du NAT).
_PREFIXES_IMPLICITES = ("firewall_", "network_", "ephemeral_fw")

# Mots-clés d'une règle suivis d'une liste d'objets (séparés par « | »).
_CHAMPS_REGLE = {"from", "to", "port", "route", "ipproto", "on", "via"}

_FIGE_DYNAMIQUE = "nom DNS résolu par le SNS (resolve=dynamic) : le renommer casserait la résolution"
_FIGE_FQDN = "objet FQDN SNS : le nom est le nom DNS résolu, le renommer casserait la résolution"


def genre_natif(nom_fichier: str, texte: str) -> str | None:
    """Type de fichier natif SNS (« object », « filter »…), d'après son nom puis son contenu."""
    base = nom_fichier.lower()
    if "." not in base and base in FICHIERS:
        return base
    premiere = next(
        (ligne.strip() for ligne in texte.splitlines() if ligne.strip() and not ligne.strip().startswith("#")),
        "",
    )
    if not re.fullmatch(r"\[[^\]]+\].*", premiere):
        return None
    sections = set(re.findall(r"^\[([^\]]+)\]", texte, re.MULTILINE))
    if sections & {"Host", "Service", "Protocol", "Fqdn"}:
        return "object"
    if sections & {"Filter", "NAT"}:
        return "filter"
    if sections & {"StaticRoutes", "ReverseRoutes"}:
        return "route"
    if any(re.fullmatch(r"(?:ethernet|vlan)\d+", section) for section in sections):
        return "network"
    return None


def assembler_natif(
    fichiers: Sequence[tuple[str, str, str]],
    non_lus: Sequence[str] = (),
) -> Inventaire:
    """Inventaire à partir de (genre, libellé, texte) ; `non_lus` : éléments fournis mais pas lus."""
    objets: list[Objet] = []
    ignores: list[str] = []
    regles: list[Regle] = []
    liens: list[Lien] = []
    vlans: list[tuple[Reseau, int]] = []
    lus: set[str] = set()
    fournis_non_lus = list(non_lus)
    filtres = [label for genre, label, _texte in fichiers if genre == "filter"]
    for genre, label, texte in fichiers:
        if genre == "object":
            lus_objets, lus_ignores = lire_objets_natifs(texte)
            objets.extend(lus_objets)
            ignores.extend(lus_ignores)
        elif genre == "objectgroup":
            objets.extend(lire_groupes_natifs(texte, "groupe-adresses"))
        elif genre == "servicegroup":
            objets.extend(lire_groupes_natifs(texte, "groupe-services"))
        elif genre == "filter":
            prefixe = f"{label.rsplit('/', 1)[-1]}:" if len(filtres) > 1 else ""
            lus_regles, lus_liens = lire_filtre_natif(texte, prefixe)
            regles.extend(lus_regles)
            liens.extend(lus_liens)
        elif genre == "route":
            liens.extend(lire_routes_natives(texte))
        elif genre == "network":
            vlans.extend(vlans_natifs(texte))
        elif genre in NON_LUS:
            if any(_sans_commentaire(ligne.strip()) for ligne in texte.splitlines()):
                fournis_non_lus.append(label)
                continue
        else:
            raise ErreurLecture(f"Fichier SNS non géré : {label} ({genre}).")
        lus.add(genre)

    objets = [_avec_vlan(objet, vlans) for objet in objets]
    non_definis = noms_non_definis(objets, regles, liens)
    manquants = [nom for nom in REQUIS_POUR_RETRAITS if nom not in lus]
    avertissements: list[str] = []
    suspension: str | None = None
    if manquants:
        pluriel = "s" if len(manquants) > 1 else ""
        risques = " ou ".join(_RISQUES[nom] for nom in manquants)
        suspension = f"fichier{pluriel} {', '.join(manquants)} non lu{pluriel} : {risques} paraîtrait orphelin"
        avertissements.append(f"Retraits d'orphelins suspendus : {suspension}.")
    elif "filter" not in lus:
        suspension = "aucun fichier Filter lu : aucune règle ne cite les objets"
        avertissements.append(f"Retraits d'orphelins suspendus : {suspension}.")
    avertissements.append(AVERTISSEMENT_NON_GERES)
    if suspension is None:
        avertissements.append(VERIFIER_USAGE)
    if fournis_non_lus:
        avertissements.append(
            f"Fournis mais non lus (non gérés) : {', '.join(fournis_non_lus)}."
        )
    if non_definis:
        globaux = sum(1 for nom in non_definis if nom.lower().startswith("global_"))
        avertissements.append(
            f"Noms cités mais non définis dans l'export : {len(non_definis)}, dont objets globaux "
            f"SMC (global_*) : {globaux} ; les autres sont des routeurs, groupes ou objets d'un "
            "fichier non fourni."
        )
    return Inventaire(
        constructeur="stormshield",
        sources=tuple(label for _genre, label, _texte in fichiers) + tuple(non_lus),
        objets=tuple(objets),
        regles=tuple(regles),
        liens=tuple(liens),
        ignores=tuple(ignores),
        avertissements=tuple(avertissements),
        non_definis=non_definis,
        retraits_suspendus=suspension,
    )


def noms_non_definis(
    objets: Iterable[Objet], regles: Iterable[Regle], liens: Iterable[Lien]
) -> tuple[str, ...]:
    """Noms cités (règles, liens, groupes) sans définition, hors objets implicites du SNS.

    Les protocoles (ipproto) ne sont pas comptés : le SNS en connaît sans objet [Protocol].
    """
    definis = {objet.nom for objet in objets}
    cites: set[str] = set()
    for regle in regles:
        cites.update(regle.sources, regle.destinations, regle.services)
    for lien in liens:
        cites.update(lien.adresses, lien.services)
    for objet in objets:
        cites.update(objet.mentions_adresses, objet.mentions_services)
    return tuple(
        sorted(
            nom
            for nom in cites
            if nom
            and nom not in definis
            and nom.lower() not in _IMPLICITES
            and not nom.lower().startswith(_PREFIXES_IMPLICITES)
        )
    )


def _sections(texte: str) -> list[tuple[str, list[str]]]:
    """Sections INI et leurs lignes, commentaires « # » (hors guillemets) retirés."""
    resultat: list[tuple[str, list[str]]] = []
    courant: list[str] | None = None
    for brut in texte.splitlines():
        ligne = _sans_commentaire(brut.strip())
        if not ligne:
            continue
        entete = re.fullmatch(r"\[([^\]]+)\]", ligne)
        if entete:
            courant = []
            resultat.append((entete.group(1).strip(), courant))
        elif courant is not None:
            courant.append(ligne)
    return resultat


def _sans_commentaire(ligne: str) -> str:
    dans_guillemets = False
    for index, caractere in enumerate(ligne):
        if caractere == '"':
            dans_guillemets = not dans_guillemets
        elif caractere == "#" and not dans_guillemets:
            return ligne[:index].strip()
    return ligne


def lire_objets_natifs(texte: str) -> tuple[tuple[Objet, ...], tuple[str, ...]]:
    objets: list[Objet] = []
    ignores: list[str] = []
    lecteurs = {
        "Host": _hote,
        "Network": _reseau,
        "Fqdn": _fqdn,
        "Service": _service,
        "Protocol": _protocole,
    }
    for section, lignes in _sections(texte):
        lecteur = lecteurs.get(section)
        if lecteur is None:
            continue
        for ligne in lignes:
            nom, egal, valeur = (partie.strip() for partie in ligne.partition("="))
            if not egal or not nom:
                continue
            try:
                objet, ignore = lecteur(nom, valeur)
            except ValueError:
                objet, ignore = None, f"{nom} ({section} « {valeur} » non reconnu, ignoré)"
            if objet is not None:
                objets.append(objet)
            if ignore:
                ignores.append(ignore)
    return tuple(objets), tuple(ignores)


def _hote(nom: str, valeur: str) -> tuple[Objet | None, str | None]:
    parties = [partie.strip() for partie in valeur.split(",") if partie.strip()]
    options = dict(partie.split("=", 1) for partie in parties if "=" in partie)
    adresses = [partie for partie in parties if "=" not in partie]
    if not adresses:
        return None, f"{nom} (hôte sans adresse IP, ignoré)"
    if "-" in adresses[0]:
        debut, fin = (borne.strip() for borne in adresses[0].split("-", 1))
        if not (_est_ip(debut) and _est_ip(fin)):
            return None, f"{nom} (plage d'adresses MAC, ignorée)"
        famille = "v4" if ipaddress.ip_address(debut).version == 4 else "v6"
        debut_ip, fin_ip = canon_ip(debut), canon_ip(fin)
        return (
            Objet(sorte="plage", nom=nom, empreinte=(famille, debut_ip, fin_ip), detail=f"{debut_ip}-{fin_ip}"),
            None,
        )
    ips = [adresse for adresse in adresses if _est_ip(adresse)]
    if not ips:
        return None, f"{nom} (adresse MAC, ignorée)"
    if options.get("resolve", "").strip().lower() == "dynamic":
        cle = fqdn_cle(nom)
        return (
            Objet(sorte="fqdn", nom=nom, empreinte=("fqdn", cle), detail=cle, fige=_FIGE_DYNAMIQUE),
            None,
        )
    elements = tuple(
        ("v4", canon_ip(ip), 32) if ipaddress.ip_address(ip).version == 4 else ("v6", canon_ip(ip), 128)
        for ip in ips
    )
    return (
        Objet(sorte="hote", nom=nom, empreinte=elements, detail=detail_ip(elements[0][1], elements[0][2])),
        None,
    )


def _reseau(nom: str, valeur: str) -> tuple[Objet, None]:
    reseau = ipaddress.ip_network(valeur.replace(" ", ""), strict=False)
    famille = "v4" if reseau.version == 4 else "v6"
    adresse, prefixe = str(reseau.network_address), reseau.prefixlen
    return (
        Objet(sorte="reseau", nom=nom, empreinte=((famille, adresse, prefixe),), detail=detail_ip(adresse, prefixe)),
        None,
    )


def _fqdn(nom: str, _valeur: str) -> tuple[Objet, None]:
    cle = fqdn_cle(nom)
    return Objet(sorte="fqdn", nom=nom, empreinte=("fqdn", cle), detail=cle, fige=_FIGE_FQDN), None


def _service(nom: str, valeur: str) -> tuple[Objet, None]:
    correspondance = re.fullmatch(r"(\d+)(?:-(\d+))?/(tcp|udp|any)", valeur.replace(" ", ""), re.IGNORECASE)
    if not correspondance:
        raise ValueError(valeur)
    debut = int(correspondance.group(1))
    fin = int(correspondance.group(2) or debut)
    debut, fin = min(debut, fin), max(debut, fin)
    protocole = correspondance.group(3).lower()
    protocoles = ("tcp", "udp") if protocole == "any" else (protocole,)
    empreinte = empreinte_service([(proto, ((debut, fin, -1, -1),)) for proto in protocoles])
    return Objet(sorte="service", nom=nom, empreinte=empreinte, detail=detail_service(empreinte)), None


def _protocole(nom: str, valeur: str) -> tuple[Objet, None]:
    numero = int(valeur)
    empreinte = empreinte_service([("ip", ((numero, numero, -1, -1),))])
    return Objet(sorte="protocole", nom=nom, empreinte=empreinte, detail=detail_service(empreinte)), None


def lire_groupes_natifs(texte: str, sorte: str) -> tuple[Objet, ...]:
    """objectgroup / servicegroup : une section [groupe] par groupe, un membre par ligne."""
    groupes: list[Objet] = []
    for nom, lignes in _sections(texte):
        membres = membres_tries([ligne.split()[0] for ligne in lignes if ligne.split()])
        detail = ", ".join(membres) or "(vide)"
        if sorte == "groupe-adresses":
            groupes.append(
                Objet(sorte=sorte, nom=nom, empreinte=(membres, ()), detail=detail, mentions_adresses=membres)
            )
        else:
            groupes.append(
                Objet(sorte=sorte, nom=nom, empreinte=(membres,), detail=detail, mentions_services=membres)
            )
    return tuple(groupes)


def lire_filtre_natif(texte: str, prefixe: str = "") -> tuple[tuple[Regle, ...], tuple[Lien, ...]]:
    """Règles de filtrage ([Filter]) et de NAT ([NAT]) ; le NAT ne compte que comme référence."""
    regles: list[Regle] = []
    liens: list[Lien] = []
    for section, lignes in _sections(texte):
        if section not in {"Filter", "NAT"}:
            continue
        for numero, ligne in enumerate(lignes, start=1):
            jetons = re.findall(r'(?:[^\s"]+|"[^"]*")+', ligne)
            active = not (jetons and jetons[0] == "off")
            if not active:
                jetons = jetons[1:]
            if not jetons or jetons[0] == "separator":
                continue
            action = jetons[0].lower()
            champs = _champs(jetons[1:])
            nom = prefixe + (champs["rulename"][0] if champs.get("rulename") else f"{section.lower()}-{numero}")
            traduits = champs.get("->from", []) + champs.get("->to", [])
            services_traduits = champs.get("->port", [])
            if section == "NAT" or action == "nat":
                liens.append(
                    Lien(
                        origine=f"nat {nom}",
                        adresses=tuple(
                            champs.get("from", []) + champs.get("to", []) + champs.get("route", []) + traduits
                        ),
                        services=tuple(champs.get("port", []) + services_traduits),
                        protocoles=tuple(champs.get("ipproto", [])),
                    )
                )
                continue
            regles.append(
                Regle(
                    nom=nom,
                    action="deny" if action in {"block", "reset"} else "allow",
                    active=active,
                    sources=tuple(champs.get("from", [])),
                    destinations=tuple(champs.get("to", [])),
                    services=tuple(champs.get("port", [])),
                    protocoles=tuple(champs.get("ipproto", [])),
                    interfaces_source=tuple(champs.get("on", [])),
                )
            )
            if champs.get("route") or traduits or services_traduits:
                liens.append(
                    Lien(
                        origine=f"routage de {nom}",
                        adresses=tuple(champs.get("route", []) + traduits),
                        services=tuple(services_traduits),
                    )
                )
    return tuple(regles), tuple(liens)


def _champs(jetons: list[str]) -> dict[str, list[str]]:
    """Listes d'objets par mot-clé ; après « -> », les champs traduits sont préfixés par « -> »."""
    champs: dict[str, list[str]] = {}
    prefixe = ""
    index = 0
    while index < len(jetons):
        jeton = jetons[index]
        if jeton == "->":
            prefixe = "->"
        elif jeton == "rulename" and index + 1 < len(jetons):
            champs["rulename"] = [jetons[index + 1].strip('"')]
            index += 1
        elif jeton in _CHAMPS_REGLE and index + 1 < len(jetons):
            valeurs = [_objet_cite(valeur) for valeur in jetons[index + 1].strip('"').split("|")]
            champs.setdefault(prefixe + jeton, []).extend(
                valeur for valeur in valeurs if valeur and valeur.lower() not in _IMPLICITES
            )
            index += 1
        index += 1
    return champs


def _objet_cite(valeur: str) -> str:
    """« !obj » → obj ; « user=login@obj » → obj (l'objet d'adresse après l'utilisateur)."""
    valeur = valeur.strip().lstrip("!")
    if "=" in valeur:
        _cle, _egal, reste = valeur.partition("=")
        return reste.rpartition("@")[2] if "@" in reste else ""
    return valeur


def lire_routes_natives(texte: str) -> tuple[Lien, ...]:
    liens: list[Lien] = []
    for section, lignes in _sections(texte):
        for numero, ligne in enumerate(lignes, start=1):
            if section == "Config":
                cle, _egal, valeur = (partie.strip() for partie in ligne.partition("="))
                if cle.startswith("DefaultRoute") and valeur and not _est_ip(valeur):
                    liens.append(Lien(origine="route par défaut", adresses=(valeur,)))
                continue
            if section != "StaticRoutes":
                continue
            corps = ligne.removeprefix("off ").strip()
            correspondance = re.fullmatch(r"([^,]+),([^,]*?)->([^,\s]+).*", corps)
            if correspondance:
                noms = (correspondance.group(1).strip(), correspondance.group(3).strip())
                liens.append(
                    Lien(
                        origine=f"route {numero}",
                        adresses=tuple(nom for nom in noms if not _est_ip(nom) and "/" not in nom),
                    )
                )
    return tuple(liens)


def interfaces_natives(texte: str) -> list[dict[str, str]]:
    """Interfaces SNS : clés du fichier Network (Name, State, Tag, Address, Mask…) + _section."""
    interfaces: list[dict[str, str]] = []
    for section, lignes in _sections(texte):
        if section in {"Config", "Global"}:
            continue
        valeurs = {"_section": section}
        for ligne in lignes:
            cle, _egal, valeur = ligne.partition("=")
            valeurs[cle.strip()] = valeur.strip().strip('"')
        interfaces.append(valeurs)
    return interfaces


def reseaux_interface(interface: dict[str, str]) -> list[Reseau]:
    """Réseaux des adresses statiques (AddressN/MaskN, IPv6AddressN/IPv6MaskN) ; dhcp ignoré."""
    reseaux: list[Reseau] = []
    for cle, adresse in interface.items():
        suffixe = re.fullmatch(r"(IPv6)?Address(\d*)", cle)
        if not suffixe or not _est_ip(adresse):
            continue
        masque = interface.get(f"{suffixe.group(1) or ''}Mask{suffixe.group(2)}", "")
        if not masque:
            continue
        try:
            reseaux.append(ipaddress.ip_network(f"{adresse}/{masque}", strict=False))
        except ValueError:
            continue
    return reseaux


def vlans_natifs(texte: str) -> list[tuple[Reseau, int]]:
    """(réseau, VLAN ID) des interfaces VLAN à adresse statique."""
    vlans: list[tuple[Reseau, int]] = []
    for interface in interfaces_natives(texte):
        tag = interface.get("Tag", "")
        if tag.isdigit():
            vlans.extend((reseau, int(tag)) for reseau in reseaux_interface(interface))
    return vlans


def _avec_vlan(objet: Objet, vlans: Sequence[tuple[Reseau, int]]) -> Objet:
    """VLAN de l'interface VLAN la plus précise qui contient le réseau."""
    if objet.sorte != "reseau" or objet.vlan is not None or not vlans:
        return objet
    _famille, adresse, prefixe = objet.empreinte[0]
    reseau = ipaddress.ip_network(f"{adresse}/{prefixe}", strict=False)
    candidats = [
        (interface.prefixlen, tag)
        for interface, tag in vlans
        if interface.version == reseau.version and reseau.subnet_of(interface)
    ]
    return replace(objet, vlan=max(candidats)[1]) if candidats else objet


def _est_ip(valeur: str) -> bool:
    try:
        ipaddress.ip_address(valeur)
    except ValueError:
        return False
    return True
