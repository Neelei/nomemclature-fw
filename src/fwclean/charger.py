"""Assemblage des exports en un inventaire."""

from __future__ import annotations

from pathlib import Path

from fwclean.fortigate import lire_fortigate
from fwclean.model import ErreurLecture, Inventaire
from fwclean.naming import ESPACE, LIBELLE
from fwclean.stormshield import (
    assembler,
    classer_csv,
    lire_objets,
    lire_regles,
    lire_routes,
)
from fwclean.stormshield_natif import FICHIERS as FICHIERS_NATIFS
from fwclean.stormshield_natif import FICHIERS_GLOBAUX
from fwclean.stormshield_natif import assembler_natif, genre_natif

_SUFFIXES = {".conf", ".csv", ".na"}
_NATIF = "sns:"


def charger(chemins: list[Path]) -> Inventaire:
    fichiers, non_lus = _developper(chemins)
    if not fichiers:
        raise ErreurLecture("Aucun export .conf, .csv ou fichier natif SNS (object, Filter…) à lire.")

    genres: list[str] = []
    textes: list[str] = []
    labels: list[str] = []
    for chemin in fichiers:
        if chemin.suffix.lower() == ".na":
            raise ErreurLecture(
                f"{chemin.name} : sauvegarde Stormshield chiffrée (.na) non lue. "
                "Copiez les fichiers de /usr/Firewall/ConfigFiles (object, objectgroup, "
                "servicegroup, Filter, Network, route…) ou exportez objets et règles en CSV."
            )
        texte = _lire(chemin)
        labels.append(_afficher(chemin))
        textes.append(texte)
        genres.append(_genre(chemin, texte))

    familles = {_famille(genre) for genre in genres}
    if len(familles) > 1:
        if "fortigate" in familles:
            raise ErreurLecture("Un audit porte sur un seul constructeur à la fois.")
        raise ErreurLecture(
            "CSV Stormshield et fichiers natifs SNS mélangés : auditer l'un ou l'autre."
        )

    if genres[0] == "fortigate":
        inventaires = [
            lire_fortigate(texte, label) for texte, label in zip(textes, labels, strict=True)
        ]
        return _verifier(_fusionner("fortigate", inventaires))

    if genres[0].startswith(_NATIF):
        return _verifier(
            assembler_natif(
                [
                    (genre.removeprefix(_NATIF), label, texte)
                    for genre, label, texte in zip(genres, labels, textes, strict=True)
                ],
                non_lus,
            )
        )

    objets = []
    regles = []
    liens = []
    ignores = []
    for genre, texte in zip(genres, textes, strict=True):
        if genre == "objets":
            lus, ignores_csv = lire_objets(texte)
            objets.extend(lus)
            ignores.extend(ignores_csv)
        elif genre == "regles":
            lus_regles, lus_liens = lire_regles(texte)
            regles.extend(lus_regles)
            liens.extend(lus_liens)
        elif genre == "routes":
            liens.extend(lire_routes(texte))
        else:
            raise ErreurLecture(f"Export non reconnu ({genre}).")
    inventaire = assembler(
        tuple(labels),
        tuple(objets),
        tuple(regles),
        tuple(liens),
        tuple(ignores),
    )
    if not inventaire.objets and not inventaire.regles and not inventaire.liens and not inventaire.ignores:
        raise ErreurLecture("Aucun objet, aucune règle et aucune route reconnus dans l'export.")
    return _verifier(inventaire)


def _famille(genre: str) -> str:
    if genre == "fortigate":
        return "fortigate"
    return "natif" if genre.startswith(_NATIF) else "csv"


def _fusionner(constructeur: str, inventaires: list[Inventaire]) -> Inventaire:
    return Inventaire(
        constructeur=constructeur,
        sources=tuple(source for inv in inventaires for source in inv.sources),
        objets=tuple(objet for inv in inventaires for objet in inv.objets),
        regles=tuple(regle for inv in inventaires for regle in inv.regles),
        liens=tuple(lien for inv in inventaires for lien in inv.liens),
        ignores=tuple(ignore for inv in inventaires for ignore in inv.ignores),
        interfaces=tuple(interface for inv in inventaires for interface in inv.interfaces),
    )


def _verifier(inventaire: Inventaire) -> Inventaire:
    if (
        not inventaire.objets
        and not inventaire.regles
        and not inventaire.liens
        and not inventaire.ignores
    ):
        raise ErreurLecture("Aucun objet, aucune règle et aucune route reconnus dans l'export.")
    vus: dict[tuple[str, str], str] = {}
    for objet in inventaire.objets:
        cle = (ESPACE[objet.sorte], objet.nom)
        if cle in vus:
            raise ErreurLecture(
                f"Nom déjà utilisé ({LIBELLE[objet.sorte]}) : {objet.nom}"
            )
        vus[cle] = objet.sorte
    noms_regles: set[str] = set()
    for regle in inventaire.regles:
        if regle.nom in noms_regles:
            raise ErreurLecture(f"Règle en double : {regle.nom}")
        noms_regles.add(regle.nom)
    return inventaire


def _developper(chemins: list[Path]) -> tuple[list[Path], list[str]]:
    """Fichiers à lire, et éléments SNS reconnus mais pas lus (reste du dossier Global/)."""
    fichiers: list[Path] = []
    non_lus: list[str] = []
    for chemin in chemins:
        if not chemin.exists():
            raise ErreurLecture(f"Introuvable : {chemin}")
        if not chemin.is_dir():
            fichiers.append(chemin)
            continue
        for enfant in sorted(chemin.iterdir()):
            nom = enfant.name.lower()
            if enfant.is_file() and (enfant.suffix.lower() in _SUFFIXES or nom in FICHIERS_NATIFS):
                fichiers.append(enfant)
            elif enfant.is_dir() and nom == "filter":
                # Slots numérotés (00, 01…) ; slotinfo et filter (options [Config]) ne sont pas des règles.
                for slot in sorted(enfant.iterdir()):
                    if slot.is_file() and slot.name.isdigit():
                        fichiers.append(slot)
                    else:
                        non_lus.append(_afficher(slot) + ("/" if slot.is_dir() else ""))
            elif enfant.is_dir() and nom == "global":
                for fichier in sorted(enfant.iterdir()):
                    if fichier.is_file() and fichier.name.lower() in FICHIERS_GLOBAUX:
                        fichiers.append(fichier)
                    else:
                        non_lus.append(_afficher(fichier) + ("/" if fichier.is_dir() else ""))
    return fichiers, non_lus


def _genre(chemin: Path, texte: str) -> str:
    if chemin.suffix.lower() == ".conf":
        return "fortigate"
    if (
        not chemin.suffix
        and chemin.parent.name.lower() == "global"
        and chemin.name.lower() in FICHIERS_GLOBAUX
    ):
        return f"{_NATIF}global-{chemin.name.lower()}"
    if not chemin.suffix:
        natif = genre_natif(chemin.name, texte)
        if natif is None and chemin.parent.name.lower() == "filter":
            if not texte.strip():
                return _NATIF + "filter"
            raise ErreurLecture(f"{_afficher(chemin)} : slot de filtrage SNS sans section [Filter] ni [NAT].")
        if natif is not None:
            return _NATIF + natif
    apercu = texte.lstrip()
    if apercu.startswith("#config-version") or apercu.startswith("config "):
        return "fortigate"
    if "\nconfig firewall" in texte or "\nconfig router" in texte:
        return "fortigate"
    natif = genre_natif(chemin.name, texte)
    if natif is not None:
        return _NATIF + natif
    return classer_csv(texte)


def _lire(chemin: Path) -> str:
    donnees = chemin.read_bytes()
    try:
        return donnees.decode("utf-8-sig")
    except UnicodeDecodeError:
        return donnees.decode("latin-1")


def _afficher(chemin: Path) -> str:
    try:
        return chemin.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return chemin.as_posix()
