"""Lecture des CSV Stormshield : objets, règles de filtrage, routes."""

from __future__ import annotations

import csv
import io

from fwclean.contenu import (
    canon_ip,
    detail_calendrier,
    detail_ip,
    detail_service,
    empreinte_service,
    est_ip,
    fqdn_cle,
    membres_tries,
    normaliser_jours,
    resoudre_masque,
)
from fwclean.model import ErreurLecture, Inventaire, Lien, Objet, Regle
from fwclean.naming import normaliser_chaine

TYPES_OBJETS = {
    "host",
    "range",
    "network",
    "fqdn",
    "group",
    "service",
    "servicegroup",
    "protocol",
    "time",
    "router",
}

_ALIAS_COLONNES = {
    "nom": "nom",
    "name": "nom",
    "rulename": "nom",
    "nom_de_la_regle": "nom",
    "etat": "etat",
    "status": "etat",
    "state": "etat",
    "action": "action",
    "type": "type",
    "type_slot": "type",
    "source": "source",
    "src": "source",
    "destination": "destination",
    "dst": "destination",
    "reseau": "destination",
    "network": "destination",
    "service": "service",
    "port": "service",
    "dstport": "service",
    "port_destination": "service",
    "interface_source": "interface_source",
    "srcif": "interface_source",
    "srcintf": "interface_source",
    "interface_src": "interface_source",
    "source_interface": "interface_source",
    "interface_destination": "interface_destination",
    "dstif": "interface_destination",
    "dstintf": "interface_destination",
    "interface_dst": "interface_destination",
    "destination_interface": "interface_destination",
    "planification": "planification",
    "schedule": "planification",
    "time": "planification",
    "calendrier": "planification",
    "source_traduite": "source_traduite",
    "translated_src": "source_traduite",
    "nat_src": "source_traduite",
    "pool": "source_traduite",
    "destination_traduite": "destination_traduite",
    "translated_dst": "destination_traduite",
    "nat_dst": "destination_traduite",
    "vip": "destination_traduite",
    "passerelle": "passerelle",
    "gateway": "passerelle",
    "gw": "passerelle",
    "nexthop": "passerelle",
}

_ACTIF = {"on", "enable", "enabled", "actif", "oui", "yes", "1", "true"}
_INACTIF = {"off", "disable", "disabled", "inactif", "non", "no", "0", "false"}


def classer_csv(texte: str) -> str:
    lignes = _lignes(texte)
    if not lignes:
        raise ErreurLecture("Fichier CSV vide.")
    premiere = _ligne_csv(lignes[0], _separateur(texte))
    if not premiere:
        raise ErreurLecture("Fichier CSV vide.")
    cellule = premiere[0].strip().lower().lstrip("#")
    if cellule in TYPES_OBJETS:
        return "objets"
    entetes = {_norm_entete(cellule_entete) for cellule_entete in premiere}
    if "passerelle" in entetes:
        return "routes"
    if "action" in entetes or {"source", "destination"} & entetes:
        return "regles"
    raise ErreurLecture(
        "CSV non reconnu. Attendu : base objets SNS, règles de filtrage, ou routes."
    )


def lire_objets(texte: str) -> tuple[tuple[Objet, ...], tuple[str, ...]]:
    objets: list[Objet] = []
    ignores: list[str] = []
    separateur = _separateur(texte)
    for ligne in _lignes(texte):
        champs = _ligne_csv(ligne, separateur)
        if not champs or not champs[0].strip():
            continue
        type_objet = champs[0].strip().lower()
        if type_objet not in TYPES_OBJETS:
            raise ErreurLecture(f"Type d'objet Stormshield inconnu : {champs[0]}")
        if type_objet == "router":
            nom = champs[1].strip() if len(champs) > 1 else "?"
            ignores.append(f"{nom} (routeur, ignoré)")
            continue
        objets.append(_objet(type_objet, champs))
    return tuple(objets), tuple(ignores)


def lire_regles(texte: str) -> tuple[tuple[Regle, ...], tuple[Lien, ...]]:
    lignes = _lignes(texte)
    if not lignes:
        raise ErreurLecture("Export de règles vide.")
    separateur = _separateur(texte)
    entetes = [_norm_entete(cellule) for cellule in _ligne_csv(lignes[0], separateur)]
    if "action" not in entetes and "source" not in entetes:
        raise ErreurLecture("En-tête de règles absent (colonne action ou source).")
    regles: list[Regle] = []
    liens: list[Lien] = []
    numero_nat = 0
    for indice, ligne in enumerate(lignes[1:], start=1):
        champs = _ligne_csv(ligne, separateur)
        if not any(champ.strip() for champ in champs):
            continue
        ligne_map = _mapper(entetes, champs)
        if _est_nat(ligne_map):
            numero_nat += 1
            liens.append(_lien_nat(numero_nat, ligne_map))
            continue
        regles.append(_regle(indice, ligne_map))
    return tuple(regles), tuple(liens)


def lire_routes(texte: str) -> tuple[Lien, ...]:
    lignes = _lignes(texte)
    if not lignes:
        return ()
    separateur = _separateur(texte)
    entetes = [_norm_entete(cellule) for cellule in _ligne_csv(lignes[0], separateur)]
    liens: list[Lien] = []
    for indice, ligne in enumerate(lignes[1:], start=1):
        champs = _ligne_csv(ligne, separateur)
        if not any(champ.strip() for champ in champs):
            continue
        ligne_map = _mapper(entetes, champs)
        adresses = [
            nom
            for nom in (
                *(_noms(ligne_map.get("destination", ""))),
                *(_noms(ligne_map.get("passerelle", ""))),
            )
            if not est_ip(nom) and "/" not in nom
        ]
        liens.append(Lien(origine=f"route {indice}", adresses=tuple(adresses)))
    return tuple(liens)


def assembler(
    source_labels: tuple[str, ...],
    objets: tuple[Objet, ...],
    regles: tuple[Regle, ...],
    liens: tuple[Lien, ...],
    ignores: tuple[str, ...],
) -> Inventaire:
    return Inventaire(
        constructeur="stormshield",
        sources=source_labels,
        objets=objets,
        regles=regles,
        liens=liens,
        ignores=ignores,
    )


def _objet(type_objet: str, champs: list[str]) -> Objet:
    if len(champs) < 2 or not champs[1].strip():
        raise ErreurLecture(f"Objet {type_objet} sans nom.")
    nom = champs[1].strip()
    if type_objet == "host":
        return _hote(nom, champs)
    if type_objet == "network":
        return _reseau(nom, champs)
    if type_objet == "range":
        return _plage(nom, champs)
    if type_objet == "fqdn":
        cle = fqdn_cle(nom)
        return Objet(sorte="fqdn", nom=nom, empreinte=("fqdn", cle), detail=cle)
    if type_objet == "group":
        return _groupe_adresses(nom, champs)
    if type_objet == "servicegroup":
        return _groupe_services(nom, champs)
    if type_objet == "service":
        return _service(nom, champs)
    if type_objet == "protocol":
        return _protocole(nom, champs)
    if type_objet == "time":
        return _temps(nom, champs)
    raise ErreurLecture(f"Type d'objet non géré : {type_objet}")


def _hote(nom: str, champs: list[str]) -> Objet:
    ipv4 = champs[2].strip() if len(champs) > 2 else ""
    ipv6 = champs[3].strip() if len(champs) > 3 and est_ip(champs[3].strip()) else ""
    if not ipv4 and not ipv6:
        raise ErreurLecture(f"Hôte sans adresse : {nom}")
    parties: list[tuple] = []
    if ipv4:
        parties.append(("v4", canon_ip(ipv4), 32))
    if ipv6:
        parties.append(("v6", canon_ip(ipv6), 128))
    detail = detail_ip(parties[0][1], parties[0][2])
    return Objet(sorte="hote", nom=nom, empreinte=tuple(parties), detail=detail)


def _reseau(nom: str, champs: list[str]) -> Objet:
    ipv4 = champs[2].strip() if len(champs) > 2 else ""
    masque = champs[3].strip() if len(champs) > 3 else ""
    if not ipv4 or not masque:
        raise ErreurLecture(f"Réseau incomplet : {nom}")
    # Le type déclaré prime : un network, même en /32, reste un réseau.
    adresse, prefixe = resoudre_masque(ipv4, masque)
    return Objet(
        sorte="reseau",
        nom=nom,
        empreinte=(("v4", adresse, prefixe),),
        detail=detail_ip(adresse, prefixe),
    )


def _plage(nom: str, champs: list[str]) -> Objet:
    debut = champs[2].strip() if len(champs) > 2 else ""
    fin = champs[3].strip() if len(champs) > 3 else ""
    if not debut or not fin:
        raise ErreurLecture(f"Plage sans bornes : {nom}")
    debut_ip, fin_ip = canon_ip(debut), canon_ip(fin)
    return Objet(
        sorte="plage",
        nom=nom,
        empreinte=("v4", debut_ip, fin_ip),
        detail=f"{debut_ip}-{fin_ip}",
    )


def _groupe_adresses(nom: str, champs: list[str]) -> Objet:
    if len(champs) < 3:
        raise ErreurLecture(f"Groupe sans membres : {nom}")
    membres = membres_tries(_noms(champs[2]))
    if not membres:
        raise ErreurLecture(f"Groupe d'adresses sans membre : {nom}")
    return Objet(
        sorte="groupe-adresses",
        nom=nom,
        empreinte=(membres, ()),
        detail=", ".join(membres),
        mentions_adresses=membres,
    )


def _groupe_services(nom: str, champs: list[str]) -> Objet:
    if len(champs) < 3:
        raise ErreurLecture(f"Groupe de services sans membres : {nom}")
    membres = membres_tries(_noms(champs[2]))
    if not membres:
        raise ErreurLecture(f"Groupe de services sans membre : {nom}")
    return Objet(
        sorte="groupe-services",
        nom=nom,
        empreinte=(membres,),
        detail=", ".join(membres),
        mentions_services=membres,
    )


def _service(nom: str, champs: list[str]) -> Objet:
    if len(champs) < 3 or not champs[2].strip():
        raise ErreurLecture(f"Service sans protocole : {nom}")
    proto = champs[2].strip().lower()
    if proto == "any":
        proto = "any"
    rest = champs[3:]
    if rest and rest[-1].strip() and not _est_nombre(rest[-1].strip()):
        rest = rest[:-1]
    nombres = [int(champ) for champ in rest if champ.strip() and _est_nombre(champ.strip())]
    if len(nombres) >= 2 and (len(rest) < 1 or not rest[0].strip()):
        debut, fin = nombres[0], nombres[1]
    elif len(nombres) >= 2 and not (len(champs) > 3 and champs[3].strip()):
        debut, fin = nombres[0], nombres[1]
    elif len(nombres) == 1:
        debut = fin = nombres[0]
    elif len(nombres) >= 2:
        debut, fin = nombres[0], nombres[-1]
    else:
        raise ErreurLecture(f"Service sans port : {nom}")
    if debut > fin:
        debut, fin = fin, debut
    empreinte = empreinte_service([(proto, ((debut, fin, -1, -1),))])
    return Objet(
        sorte="service",
        nom=nom,
        empreinte=empreinte,
        detail=detail_service(empreinte),
    )


def _protocole(nom: str, champs: list[str]) -> Objet:
    if len(champs) < 3 or not champs[2].strip():
        raise ErreurLecture(f"Protocole sans numéro : {nom}")
    numero = int(champs[2].strip())
    empreinte = empreinte_service([("ip", ((numero, numero, -1, -1),))])
    return Objet(
        sorte="service",
        nom=nom,
        empreinte=empreinte,
        detail=detail_service(empreinte),
    )


def _temps(nom: str, champs: list[str]) -> Objet:
    horaire = champs[2].strip() if len(champs) > 2 else ""
    jours = normaliser_jours(champs[3] if len(champs) > 3 else "")
    periode = champs[4].strip() if len(champs) > 4 else ""
    empreinte = ("plage", horaire, jours, periode)
    return Objet(
        sorte="calendrier",
        nom=nom,
        empreinte=empreinte,
        detail=detail_calendrier(empreinte),
    )


def _regle(indice: int, ligne: dict[str, str]) -> Regle:
    nom = ligne.get("nom", "").strip() or f"regle-{indice}"
    etat = ligne.get("etat", "").strip().lower()
    if etat in _INACTIF:
        active = False
    else:
        active = True
    return Regle(
        nom=nom,
        action=_action(ligne.get("action", "pass")),
        active=active,
        sources=_noms(ligne.get("source", "")),
        destinations=_noms(ligne.get("destination", "")),
        services=_noms(ligne.get("service", "")),
        interfaces_source=_noms(ligne.get("interface_source", "")),
        interfaces_destination=_noms(ligne.get("interface_destination", "")),
        planification=ligne.get("planification", "").strip() or None,
    )


def _lien_nat(numero: int, ligne: dict[str, str]) -> Lien:
    # Sur SNS, la source traduite est un objet d'adresse (hôte, plage, réseau), pas un pool FortiGate.
    adresses = (
        *_noms(ligne.get("source", "")),
        *_noms(ligne.get("destination", "")),
        *_noms(ligne.get("destination_traduite", "")),
        *_noms(ligne.get("source_traduite", "")),
    )
    services = _noms(ligne.get("service", ""))
    return Lien(
        origine=f"nat {numero}",
        adresses=tuple(adresses),
        services=tuple(services),
    )


def _est_nat(ligne: dict[str, str]) -> bool:
    type_slot = ligne.get("type", "").strip().lower()
    action = ligne.get("action", "").strip().lower()
    return "nat" in type_slot or action == "nat"


def _action(valeur: str) -> str:
    normalise = valeur.strip().lower()
    if normalise in {"pass", "accept", "allow", "autoriser"}:
        return "allow"
    if normalise in {"block", "deny", "drop", "reject", "bloquer"}:
        return "deny"
    raise ErreurLecture(f"Action de règle Stormshield inconnue : {valeur}")


def _noms(cellule: str) -> tuple[str, ...]:
    if not cellule or not cellule.strip():
        return ()
    return tuple(morceau.strip() for morceau in cellule.split(",") if morceau.strip())


def _est_nombre(valeur: str) -> bool:
    return valeur.isdigit()


def _norm_entete(cellule: str) -> str:
    brut = normaliser_chaine(cellule.strip().lstrip("#")).replace("-", "_")
    return _ALIAS_COLONNES.get(brut, brut)


def _mapper(entetes: list[str], champs: list[str]) -> dict[str, str]:
    ligne: dict[str, str] = {}
    for cle, valeur in zip(entetes, champs, strict=False):
        ligne[cle] = valeur.strip()
    return ligne


def _separateur(texte: str) -> str:
    for ligne in _lignes(texte):
        if ligne.count(";") > ligne.count(","):
            return ";"
        return ","
    return ","


def _lignes(texte: str) -> list[str]:
    return [
        ligne
        for ligne in texte.splitlines()
        if ligne.strip() and not ligne.strip().startswith("#")
    ]


def _ligne_csv(ligne: str, separateur: str) -> list[str]:
    return next(csv.reader(io.StringIO(ligne), delimiter=separateur))
