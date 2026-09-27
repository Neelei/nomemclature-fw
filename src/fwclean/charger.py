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

_SUFFIXES = {".conf", ".csv", ".na"}


def charger(chemins: list[Path]) -> Inventaire:
    fichiers = _developper(chemins)
    if not fichiers:
        raise ErreurLecture("Aucun export .conf ou .csv à lire.")

    genres: list[str] = []
    textes: list[str] = []
    labels: list[str] = []
    for chemin in fichiers:
        if chemin.suffix.lower() == ".na":
            raise ErreurLecture(
                f"{chemin.name} : sauvegarde Stormshield chiffrée (.na) non lue. "
                "Exportez la base objets (Objets > OBJETS RÉSEAU / TEMPS) et les règles "
                "de filtrage en CSV."
            )
        texte = chemin.read_text(encoding="utf-8-sig")
        labels.append(_afficher(chemin))
        textes.append(texte)
        genres.append(_genre(chemin, texte))

    if any(genre == "fortigate" for genre in genres) and any(genre != "fortigate" for genre in genres):
        raise ErreurLecture("Un audit porte sur un seul constructeur à la fois.")

    if genres[0] == "fortigate":
        inventaires = [
            lire_fortigate(texte, label) for texte, label in zip(textes, labels, strict=True)
        ]
        return _verifier(_fusionner("fortigate", inventaires))

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


def _fusionner(constructeur: str, inventaires: list[Inventaire]) -> Inventaire:
    return Inventaire(
        constructeur=constructeur,
        sources=tuple(source for inv in inventaires for source in inv.sources),
        objets=tuple(objet for inv in inventaires for objet in inv.objets),
        regles=tuple(regle for inv in inventaires for regle in inv.regles),
        liens=tuple(lien for inv in inventaires for lien in inv.liens),
        ignores=tuple(ignore for inv in inventaires for ignore in inv.ignores),
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


def _developper(chemins: list[Path]) -> list[Path]:
    fichiers: list[Path] = []
    for chemin in chemins:
        if not chemin.exists():
            raise ErreurLecture(f"Introuvable : {chemin}")
        if chemin.is_dir():
            for enfant in sorted(chemin.iterdir()):
                if enfant.is_file() and enfant.suffix.lower() in _SUFFIXES:
                    fichiers.append(enfant)
        else:
            fichiers.append(chemin)
    return fichiers


def _genre(chemin: Path, texte: str) -> str:
    if chemin.suffix.lower() == ".conf":
        return "fortigate"
    apercu = texte.lstrip()
    if apercu.startswith("#config-version") or apercu.startswith("config "):
        return "fortigate"
    if "\nconfig firewall" in texte or "\nconfig router" in texte:
        return "fortigate"
    return classer_csv(texte)


def _afficher(chemin: Path) -> str:
    try:
        return chemin.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return chemin.as_posix()
