"""Rapport Markdown et plan JSON. Écriture seule dans le dossier de sortie."""

from __future__ import annotations

import json
from pathlib import Path

from fwclean import __version__
from fwclean.model import Resultat
from fwclean.naming import LIBELLE, LIBELLE_CONSTRUCTEUR

AVERTISSEMENT = (
    "Aucune modification n'a été appliquée. Ce plan est une proposition à relire : "
    "il ne change ni l'action, ni la source, ni la destination, ni le service d'une règle."
)


def ecrire(resultat: Resultat, dossier: Path) -> tuple[Path, Path]:
    dossier.mkdir(parents=True, exist_ok=True)
    rapport = dossier / "rapport.md"
    plan = dossier / "plan.json"
    rapport.write_text(_markdown(resultat), encoding="utf-8")
    plan.write_text(_json(resultat), encoding="utf-8")
    return rapport, plan


def plan_dict(resultat: Resultat) -> dict:
    return {
        "avertissement": AVERTISSEMENT,
        "constructeur": resultat.inventaire.constructeur,
        "sources": list(resultat.inventaire.sources),
        "renommages": [
            {
                "sorte": item.sorte,
                "ancien": item.ancien,
                "nouveau": item.nouveau,
                "references": list(item.references),
            }
            for item in resultat.renommages
        ],
        "fusions": [
            {
                "sorte": item.sorte,
                "contenu": item.contenu,
                "conserve": item.conserve,
                "nouveau_nom": item.nouveau_nom,
                "supprimes": list(item.supprimes),
                "references_reecrites": list(item.references_reecrites),
            }
            for item in resultat.fusions
        ],
        "retraits": [
            {"sorte": item.sorte, "nom": item.nom, "motif": item.motif}
            for item in resultat.retraits
        ],
        "a_revoir": [
            {"sorte": item.sorte, "nom": item.nom, "commentaire": item.commentaire}
            for item in resultat.non_conformes
            if item.traitement == "revoir"
        ],
    }


def _json(resultat: Resultat) -> str:
    return json.dumps(plan_dict(resultat), ensure_ascii=False, indent=2) + "\n"


def _markdown(resultat: Resultat) -> str:
    inventaire = resultat.inventaire
    constructeur = LIBELLE_CONSTRUCTEUR.get(inventaire.constructeur, inventaire.constructeur)
    sources = ", ".join(inventaire.sources) if inventaire.sources else "—"
    lignes = [
        "# Rapport d'audit de nomenclature",
        "",
        f"Constructeur : {constructeur}",
        f"Sources : {sources}",
        f"Référentiel réseaux : {_cell(resultat.referentiel)}",
        "",
        AVERTISSEMENT,
        "",
        "L'outil ne se connecte à aucun équipement.",
        "",
        "## Compteurs",
        "",
        "| Indicateur | Nombre |",
        "| --- | ---: |",
        f"| Objets | {len(inventaire.objets)} |",
        f"| Règles | {len(inventaire.regles)} |",
        f"| Noms non conformes | {len(resultat.non_conformes)} |",
        f"| Groupes de doublons | {len(resultat.fusions)} |",
        f"| Orphelins | {len(resultat.retraits)} |",
        f"| Objets ignorés | {len(inventaire.ignores)} |",
        "",
        "## Noms non conformes",
        "",
    ]
    if resultat.non_conformes:
        lignes.extend(
            [
                "| Sorte | Nom | Traitement | Nom proposé | Commentaire |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for item in resultat.non_conformes:
            propose = item.nom_propose or "—"
            commentaire = item.commentaire or ""
            lignes.append(
                f"| {_cell(LIBELLE.get(item.sorte, item.sorte))} | {_cell(item.nom)} | "
                f"{_cell(item.traitement)} | {_cell(propose)} | {_cell(commentaire)} |"
            )
    else:
        lignes.append("Aucun.")
    lignes.extend(["", "## Doublons stricts", ""])
    if resultat.fusions:
        for fusion in resultat.fusions:
            lignes.append(
                f"### {_cell(LIBELLE.get(fusion.sorte, fusion.sorte))} — {_cell(fusion.contenu)}"
            )
            lignes.append("")
            lignes.append(f"- Conservé : `{fusion.conserve}`")
            if fusion.nouveau_nom != fusion.conserve:
                lignes.append(f"- Nom après renommage : `{fusion.nouveau_nom}`")
            supprimes = ", ".join(f"`{nom}`" for nom in fusion.supprimes)
            lignes.append(f"- Fusionnés : {supprimes}")
            if fusion.references_reecrites:
                cibles = ", ".join(f"`{nom}`" for nom in fusion.references_reecrites)
                lignes.append(f"- Références à réécrire : {cibles}")
            else:
                lignes.append("- Références à réécrire : aucune")
            lignes.append("")
    else:
        lignes.append("Aucun.")
        lignes.append("")
    lignes.extend(
        [
            "## Orphelins",
            "",
            "Un objet utilisé seulement par une règle désactivée n'est pas orphelin. "
            "Les références comptées sont les règles (actives ou désactivées), les groupes, "
            "les VIP, le NAT et les routes.",
            "",
        ]
    )
    if resultat.retraits:
        lignes.extend(["| Sorte | Nom |", "| --- | --- |"])
        for retrait in resultat.retraits:
            lignes.append(
                f"| {_cell(LIBELLE.get(retrait.sorte, retrait.sorte))} | {_cell(retrait.nom)} |"
            )
    else:
        lignes.append("Aucun.")
    if inventaire.ignores:
        lignes.extend(["", "## Objets ignorés", ""])
        for ignore in inventaire.ignores:
            lignes.append(f"- {_cell(ignore)}")
    lignes.extend(
        [
            "",
            "## Hors périmètre",
            "",
            "Chevauchements de réseaux, fusion de règles, changement de NAT, "
            "utilisateurs, certificats, poussée vers l'équipement : non traités.",
            "",
            f"fwclean {__version__} — proposition seulement.",
            "",
        ]
    )
    return "\n".join(lignes)


def _cell(valeur: str) -> str:
    return valeur.replace("|", "\\|").replace("\n", " ")
