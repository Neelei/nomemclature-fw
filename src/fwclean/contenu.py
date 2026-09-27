"""Empreintes de contenu : ce qui rend deux objets strictement identiques."""

from __future__ import annotations

import ipaddress

JOURS = (
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
)

_ALIAS_JOURS = {
    "monday": "monday",
    "mon": "monday",
    "lundi": "monday",
    "tuesday": "tuesday",
    "tue": "tuesday",
    "mardi": "tuesday",
    "wednesday": "wednesday",
    "wed": "wednesday",
    "mercredi": "wednesday",
    "thursday": "thursday",
    "thu": "thursday",
    "jeudi": "thursday",
    "friday": "friday",
    "fri": "friday",
    "vendredi": "friday",
    "saturday": "saturday",
    "sat": "saturday",
    "samedi": "saturday",
    "sunday": "sunday",
    "sun": "sunday",
    "dimanche": "sunday",
}


def est_ip(valeur: str) -> bool:
    try:
        ipaddress.ip_address(valeur)
    except ValueError:
        return False
    return True


def est_reference_objet(valeur: str) -> bool:
    if not valeur or valeur.lower() in {"any", "all", "none", "internet"}:
        return False
    if est_ip(valeur):
        return False
    try:
        ipaddress.ip_network(valeur, strict=False)
    except ValueError:
        return True
    return False


def canon_ip(valeur: str) -> str:
    return str(ipaddress.ip_address(valeur))


def resoudre_masque(ip: str, masque: str) -> tuple[str, int]:
    if masque.isdigit() and 0 <= int(masque) <= 128:
        reseau = ipaddress.ip_network(f"{ip}/{int(masque)}", strict=False)
    else:
        reseau = ipaddress.ip_network(f"{ip}/{masque}", strict=False)
    return str(reseau.network_address), reseau.prefixlen


def decouper_subnet(valeurs: list[str]) -> tuple[str, int] | None:
    if not valeurs:
        return None
    if len(valeurs) == 1 and "/" in valeurs[0]:
        try:
            reseau = ipaddress.ip_network(valeurs[0], strict=False)
        except ValueError:
            return None
        return str(reseau.network_address), reseau.prefixlen
    if not est_ip(valeurs[0]):
        return None
    if len(valeurs) == 1:
        adresse = ipaddress.ip_address(valeurs[0])
        prefixe = 32 if adresse.version == 4 else 128
        return str(adresse), prefixe
    try:
        return resoudre_masque(valeurs[0], valeurs[1])
    except ValueError:
        return None


def empreinte_ip(version_ou_famille: str, adresse: str, prefixe: int) -> tuple:
    return (version_ou_famille, adresse, prefixe)


def detail_ip(adresse: str, prefixe: int) -> str:
    return f"{adresse}/{prefixe}"


def est_hote(adresse: str, prefixe: int) -> bool:
    version = ipaddress.ip_address(adresse).version
    return prefixe == (32 if version == 4 else 128)


def normaliser_jours(brut: str) -> tuple[str, ...]:
    if not brut or not brut.strip():
        return ()
    texte = brut.replace(",", " ").replace(";", " ")
    trouves: list[str] = []
    for jeton in texte.split():
        if "-" in jeton and jeton.count("-") == 1:
            gauche, droite = jeton.split("-", 1)
            if gauche.lower() in _ALIAS_JOURS and droite.lower() in _ALIAS_JOURS:
                debut = JOURS.index(_ALIAS_JOURS[gauche.lower()])
                fin = JOURS.index(_ALIAS_JOURS[droite.lower()])
                if debut <= fin:
                    trouves.extend(JOURS[debut : fin + 1])
                else:
                    trouves.extend(JOURS[debut:])
                    trouves.extend(JOURS[: fin + 1])
                continue
        alias = _ALIAS_JOURS.get(jeton.lower())
        trouves.append(alias or jeton.lower())
    ordonnes = [jour for jour in JOURS if jour in trouves]
    for jour in trouves:
        if jour not in ordonnes:
            ordonnes.append(jour)
    return tuple(ordonnes)


def parser_plages_ports(texte: str) -> tuple[tuple[int, int, int, int], ...]:
    plages: list[tuple[int, int, int, int]] = []
    for item in texte.split():
        if ":" in item:
            destination, source = item.split(":", 1)
        else:
            destination, source = item, ""
        dest_debut, dest_fin = _bornes(destination)
        if source:
            src_debut, src_fin = _bornes(source)
        else:
            src_debut, src_fin = -1, -1
        plages.append((dest_debut, dest_fin, src_debut, src_fin))
    return tuple(plages)


def _bornes(texte: str) -> tuple[int, int]:
    if "-" in texte:
        gauche, droite = texte.split("-", 1)
        debut, fin = int(gauche), int(droite)
        if debut > fin:
            debut, fin = fin, debut
        return debut, fin
    valeur = int(texte)
    return valeur, valeur


def empreinte_service(
    elements: list[tuple[str, tuple[tuple[int, int, int, int], ...]]],
) -> tuple:
    propre = tuple(sorted((proto, tuple(sorted(plages))) for proto, plages in elements if plages))
    return propre


def detail_service(empreinte: tuple) -> str:
    morceaux: list[str] = []
    for proto, plages in empreinte:
        for debut, fin, src_debut, src_fin in plages:
            if proto == "icmp":
                if debut < 0:
                    morceaux.append("icmp")
                else:
                    morceaux.append(f"icmp/{debut}")
                continue
            coeur = f"{proto}/{debut}" if debut == fin else f"{proto}/{debut}-{fin}"
            if src_debut >= 0:
                source = str(src_debut) if src_debut == src_fin else f"{src_debut}-{src_fin}"
                coeur = f"{coeur}:{source}"
            morceaux.append(coeur)
    return ", ".join(morceaux)


def fqdn_cle(valeur: str) -> str:
    return valeur.strip().rstrip(".").casefold()


def membres_tries(noms: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(nom.strip() for nom in noms if nom.strip()))


def detail_calendrier(empreinte: tuple) -> str:
    genre = empreinte[0]
    if genre == "recurrent":
        _genre, jours, debut, fin = empreinte
        jours_txt = ",".join(jours) if jours else "tous-les-jours"
        return f"{jours_txt} {debut}-{fin}".strip()
    if genre == "plage":
        _genre, horaire, jours, periode = empreinte
        jours_txt = ",".join(jours)
        morceaux = [morceau for morceau in (horaire, jours_txt, periode) if morceau]
        return " ".join(morceaux)
    _genre, debut, fin = empreinte
    return f"{debut} → {fin}"
