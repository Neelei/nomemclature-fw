"""Interface en ligne de commande."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from fwclean import __version__
from fwclean.audit import auditer
from fwclean.charger import charger
from fwclean.model import ErreurLecture
from fwclean.naming import lire_contextes
from fwclean.report import ecrire

_CONTEXTES_DEFAUT = ("dmz", "lan", "wan", "vpn", "ctx")


def main(argv: list[str] | None = None) -> None:
    raise SystemExit(executer(argv))


def executer(argv: list[str] | None = None) -> int:
    analyseur = argparse.ArgumentParser(
        prog="fwclean",
        description=(
            "Audit de nomenclature FortiGate et Stormshield. "
            "Signale les noms non conformes, les doublons stricts et les orphelins. "
            "N'applique aucun changement et ne se connecte à aucun équipement."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "exemples :\n"
            "  fwclean audit examples/fortigate/nomenclature.conf --sortie out/fortigate\n"
            "  fwclean audit examples/stormshield --sortie out/stormshield\n"
            "  fwclean audit inbox/pare-feu.conf --sortie out"
        ),
    )
    analyseur.add_argument("--version", action="version", version=f"fwclean {__version__}")
    sous = analyseur.add_subparsers(dest="commande", required=True)

    audit = sous.add_parser(
        "audit",
        help="Produire un rapport Markdown et un plan JSON",
        description=(
            "Lit un export et écrit out/rapport.md et out/plan.json "
            "(ou le dossier indiqué par --sortie). Aucune modification n'est appliquée."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    audit.add_argument(
        "chemins",
        nargs="+",
        metavar="CHEMIN",
        help="Fichier .conf FortiGate, CSV Stormshield, ou dossier d'export",
    )
    audit.add_argument(
        "--sortie",
        default="out",
        help="Dossier du rapport et du plan (défaut : out)",
    )
    audit.add_argument(
        "--contextes",
        help="Fichier de contextes autorisés, un par ligne (défaut : ./contextes.txt)",
    )
    args = analyseur.parse_args(argv)
    if args.commande == "audit":
        return _auditer(args)
    analyseur.print_help()
    return 2


def _auditer(args: argparse.Namespace) -> int:
    try:
        contextes = _resoudre_contextes(args.contextes)
        inventaire = charger([Path(chemin) for chemin in args.chemins])
        resultat = auditer(inventaire, contextes)
        rapport, plan = ecrire(resultat, Path(args.sortie))
    except ErreurLecture as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"Rapport : {rapport}")
    print(f"Plan : {plan}")
    print(
        f"Objets : {len(resultat.inventaire.objets)}, "
        f"règles : {len(resultat.inventaire.regles)}, "
        f"non conformes : {len(resultat.non_conformes)}, "
        f"doublons : {len(resultat.fusions)}, "
        f"orphelins : {len(resultat.retraits)}."
    )
    print("Aucune modification appliquée.")
    return 0


def _resoudre_contextes(chemin: str | None) -> tuple[str, ...]:
    if chemin:
        return lire_contextes(Path(chemin))
    local = Path.cwd() / "contextes.txt"
    if local.is_file():
        return lire_contextes(local)
    return _CONTEXTES_DEFAUT
