"""Lecture d'une sauvegarde texte FortiGate (.conf)."""

from __future__ import annotations

from fwclean.contenu import (
    canon_ip,
    decouper_subnet,
    detail_calendrier,
    detail_ip,
    detail_service,
    empreinte_service,
    est_hote,
    fqdn_cle,
    membres_tries,
    normaliser_jours,
    parser_plages_ports,
)
from fwclean.model import ErreurLecture, Inventaire, Lien, Objet, Regle

SECTIONS = {
    "firewall address",
    "firewall addrgrp",
    "firewall service custom",
    "firewall service group",
    "firewall vip",
    "firewall ippool",
    "firewall schedule recurring",
    "firewall schedule onetime",
    "firewall policy",
    "router static",
    "router policy",
}


def lire_fortigate(texte: str, source: str) -> Inventaire:
    blocs = _blocs(texte)
    objets: list[Objet] = []
    regles: list[Regle] = []
    liens: list[Lien] = []
    ignores: list[str] = []

    for nom, data in blocs.get("firewall address", []):
        objet, ignore = _adresse(nom, data)
        if objet:
            objets.append(objet)
        elif ignore:
            ignores.append(ignore)

    for nom, data in blocs.get("firewall addrgrp", []):
        objets.append(_groupe(nom, data))

    for nom, data in blocs.get("firewall service custom", []):
        objets.append(_service(nom, data))

    for nom, data in blocs.get("firewall service group", []):
        objets.append(_groupe_services(nom, data))

    for nom, data in blocs.get("firewall vip", []):
        objets.append(_vip(nom, data))

    for nom, data in blocs.get("firewall ippool", []):
        objets.append(_pool(nom, data))

    for nom, data in blocs.get("firewall schedule recurring", []):
        objets.append(_calendrier_recurrent(nom, data))

    for nom, data in blocs.get("firewall schedule onetime", []):
        objets.append(_calendrier_unique(nom, data))

    for nom, data in blocs.get("firewall policy", []):
        regles.append(_regle(nom, data))

    for nom, data in blocs.get("router static", []):
        liens.append(_route(nom, data))

    for nom, data in blocs.get("router policy", []):
        liens.append(_route(nom, data))

    return Inventaire(
        constructeur="fortigate",
        sources=(source,),
        objets=tuple(objets),
        regles=tuple(regles),
        liens=tuple(liens),
        ignores=tuple(ignores),
    )


def _adresse(nom: str, data: dict[str, list[str]]) -> tuple[Objet | None, str | None]:
    type_objet = (data.get("type") or ["ipmask"])[0].lower()
    if type_objet == "fqdn":
        valeur = (data.get("fqdn") or [""])[0]
        if not valeur:
            raise ErreurLecture(f"Adresse fqdn sans nom DNS : {nom}")
        cle = fqdn_cle(valeur)
        return (
            Objet(sorte="fqdn", nom=nom, empreinte=("fqdn", cle), detail=cle),
            None,
        )
    if type_objet == "iprange":
        debut = (data.get("start-ip") or [""])[0]
        fin = (data.get("end-ip") or [""])[0]
        if not debut or not fin:
            raise ErreurLecture(f"Plage sans bornes : {nom}")
        debut_ip, fin_ip = canon_ip(debut), canon_ip(fin)
        return (
            Objet(
                sorte="plage",
                nom=nom,
                empreinte=("v4", debut_ip, fin_ip),
                detail=f"{debut_ip}-{fin_ip}",
            ),
            None,
        )
    if type_objet in {"geography", "dynamic", "mac"}:
        return None, f"{nom} ({type_objet}, ignoré)"
    if type_objet not in {"ipmask", "interface-subnet"}:
        return None, f"{nom} ({type_objet}, ignoré)"
    subnet = decouper_subnet(data.get("subnet", []))
    if subnet is None:
        raise ErreurLecture(f"Adresse sans sous-réseau lisible : {nom}")
    adresse, prefixe = subnet
    detail = detail_ip(adresse, prefixe)
    if est_hote(adresse, prefixe):
        return (
            Objet(sorte="hote", nom=nom, empreinte=("v4", adresse, prefixe), detail=detail),
            None,
        )
    return (
        Objet(sorte="reseau", nom=nom, empreinte=("v4", adresse, prefixe), detail=detail),
        None,
    )


def _groupe(nom: str, data: dict[str, list[str]]) -> Objet:
    membres = membres_tries(data.get("member", []))
    exclus = membres_tries(data.get("exclude-member", []))
    if not membres:
        raise ErreurLecture(f"Groupe d'adresses sans membre : {nom}")
    return Objet(
        sorte="groupe-adresses",
        nom=nom,
        empreinte=(membres, exclus),
        detail=", ".join(membres),
        mentions_adresses=membres,
    )


def _service(nom: str, data: dict[str, list[str]]) -> Objet:
    protocole = (data.get("protocol") or ["TCP/UDP/SCTP"])[0].upper()
    elements: list[tuple[str, tuple[tuple[int, int, int, int], ...]]] = []
    if protocole in {"TCP/UDP/SCTP", "TCP", "UDP", "SCTP"}:
        for cle, proto in (
            ("tcp-portrange", "tcp"),
            ("udp-portrange", "udp"),
            ("sctp-portrange", "sctp"),
        ):
            if data.get(cle):
                elements.append((proto, parser_plages_ports(" ".join(data[cle]))))
    elif protocole == "ICMP":
        type_icmp = int((data.get("icmptype") or ["-1"])[0])
        code = int((data.get("icmpcode") or ["-1"])[0])
        elements.append(("icmp", ((type_icmp, code, -1, -1),)))
    elif protocole == "IP":
        numero = int((data.get("protocol-number") or ["0"])[0])
        elements.append(("ip", ((numero, numero, -1, -1),)))
    else:
        raise ErreurLecture(f"Protocole de service non reconnu pour {nom} : {protocole}")
    empreinte = empreinte_service(elements)
    if not empreinte:
        raise ErreurLecture(f"Service sans port : {nom}")
    return Objet(
        sorte="service",
        nom=nom,
        empreinte=empreinte,
        detail=detail_service(empreinte),
    )


def _groupe_services(nom: str, data: dict[str, list[str]]) -> Objet:
    membres = membres_tries(data.get("member", []))
    if not membres:
        raise ErreurLecture(f"Groupe de services sans membre : {nom}")
    return Objet(
        sorte="groupe-services",
        nom=nom,
        empreinte=(membres,),
        detail=", ".join(membres),
        mentions_services=membres,
    )


def _vip(nom: str, data: dict[str, list[str]]) -> Objet:
    externe = (data.get("extip") or [""])[0]
    mappe = (data.get("mappedip") or [""])[0]
    if not externe or not mappe:
        raise ErreurLecture(f"VIP incomplète : {nom}")
    externe_n = canon_ip(externe) if _semble_ip(externe) else externe
    mappe_n = canon_ip(mappe) if _semble_ip(mappe) else mappe
    port_ext = (data.get("extport") or [""])[0]
    port_map = (data.get("mappedport") or [""])[0]
    proto = (data.get("protocol") or [""])[0].lower()
    mentions = () if _semble_ip(mappe) else (mappe_n,)
    return Objet(
        sorte="vip",
        nom=nom,
        empreinte=("vip", externe_n, mappe_n, port_ext, port_map, proto),
        detail=f"{externe_n} → {mappe_n}",
        mentions_adresses=mentions,
    )


def _pool(nom: str, data: dict[str, list[str]]) -> Objet:
    debut = (data.get("startip") or [""])[0]
    fin = (data.get("endip") or [""])[0]
    if not debut or not fin:
        raise ErreurLecture(f"Pool sans bornes : {nom}")
    debut_ip, fin_ip = canon_ip(debut), canon_ip(fin)
    return Objet(
        sorte="pool",
        nom=nom,
        empreinte=(debut_ip, fin_ip),
        detail=f"{debut_ip}-{fin_ip}",
    )


def _calendrier_recurrent(nom: str, data: dict[str, list[str]]) -> Objet:
    jours = normaliser_jours(" ".join(data.get("day", [])))
    debut = (data.get("start") or [""])[0]
    fin = (data.get("end") or [""])[0]
    empreinte = ("recurrent", jours, debut, fin)
    return Objet(
        sorte="calendrier",
        nom=nom,
        empreinte=empreinte,
        detail=detail_calendrier(empreinte),
    )


def _calendrier_unique(nom: str, data: dict[str, list[str]]) -> Objet:
    debut = " ".join(data.get("start", []))
    fin = " ".join(data.get("end", []))
    empreinte = ("unique", debut, fin)
    return Objet(
        sorte="calendrier",
        nom=nom,
        empreinte=empreinte,
        detail=detail_calendrier(empreinte),
    )


def _regle(nom: str, data: dict[str, list[str]]) -> Regle:
    if data.get("name"):
        nom_regle = data["name"][0]
    else:
        nom_regle = f"politique-{nom}"
    return Regle(
        nom=nom_regle,
        action=_action(data.get("action", ["accept"])[0]),
        active=(data.get("status", ["enable"])[0].lower() not in {"disable", "disabled"}),
        sources=tuple(data.get("srcaddr", ())),
        destinations=tuple(data.get("dstaddr", ())),
        services=tuple(data.get("service", ())),
        interfaces_source=tuple(data.get("srcintf", ())),
        interfaces_destination=tuple(data.get("dstintf", ())),
        planification=(data.get("schedule") or [None])[0],
        pool=(data.get("poolname") or [None])[0],
    )


def _route(nom: str, data: dict[str, list[str]]) -> Lien:
    adresses: list[str] = []
    for cle in ("dstaddr", "srcaddr", "gateway", "dst"):
        for valeur in data.get(cle, []):
            if not _semble_ip(valeur) and "/" not in valeur:
                adresses.append(valeur)
    return Lien(origine=f"route {nom}", adresses=tuple(adresses))


def _action(valeur: str) -> str:
    normalise = valeur.lower()
    if normalise in {"accept", "allow", "pass"}:
        return "allow"
    if normalise in {"deny", "drop", "reject"}:
        return "deny"
    raise ErreurLecture(f"Action de règle FortiGate inconnue : {valeur}")


def _semble_ip(valeur: str) -> bool:
    try:
        canon_ip(valeur)
    except ValueError:
        return False
    return True


def _blocs(texte: str) -> dict[str, list[tuple[str, dict[str, list[str]]]]]:
    """Découpe les sections connues. Une section inconnue est ignorée, y compris son imbrication."""
    resultat: dict[str, list[tuple[str, dict[str, list[str]]]]] = {}
    profondeur = 0
    section_par_niveau: dict[int, str | None] = {}
    edit_nom: str | None = None
    edit_data: dict[str, list[str]] = {}

    def verser() -> None:
        nonlocal edit_nom, edit_data
        section = section_par_niveau.get(profondeur)
        if edit_nom is not None and section:
            resultat.setdefault(section, []).append((edit_nom, edit_data))
        edit_nom = None
        edit_data = {}

    for brut in texte.splitlines():
        ligne = brut.strip()
        if not ligne or ligne.startswith("#"):
            continue
        if ligne.startswith("config "):
            if edit_nom is not None:
                profondeur += 1
                section_par_niveau[profondeur] = None
                continue
            profondeur += 1
            nom = ligne[len("config ") :].strip()
            section_par_niveau[profondeur] = nom if nom in SECTIONS else None
            continue
        if ligne == "end":
            if section_par_niveau.get(profondeur):
                verser()
            section_par_niveau.pop(profondeur, None)
            profondeur = max(0, profondeur - 1)
            continue
        section = section_par_niveau.get(profondeur)
        if not section:
            continue
        if ligne.startswith("edit "):
            verser()
            jetons = _tokeniser(ligne[len("edit ") :].strip())
            edit_nom = jetons[0] if jetons else ""
            edit_data = {}
            continue
        if ligne == "next":
            verser()
            continue
        if ligne.startswith("set ") and edit_nom is not None:
            cle, valeurs = _couper_set(ligne)
            if cle:
                edit_data[cle] = valeurs
    return resultat


def _couper_set(ligne: str) -> tuple[str, list[str]]:
    jetons = _tokeniser(ligne[len("set ") :].strip())
    if not jetons:
        return "", []
    return jetons[0], jetons[1:]


def _tokeniser(texte: str) -> list[str]:
    jetons: list[str] = []
    index = 0
    longueur = len(texte)
    while index < longueur:
        if texte[index].isspace():
            index += 1
            continue
        if texte[index] == '"':
            index += 1
            tampon: list[str] = []
            while index < longueur and texte[index] != '"':
                tampon.append(texte[index])
                index += 1
            index += 1
            jetons.append("".join(tampon))
            continue
        fin = index
        while fin < longueur and not texte[fin].isspace():
            fin += 1
        jetons.append(texte[index:fin])
        index = fin
    return jetons
