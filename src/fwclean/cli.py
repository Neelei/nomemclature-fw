"""Interface en ligne de commande."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from fwclean import __version__
from fwclean.audit import auditer
from fwclean.charger import charger
from fwclean.model import ErreurLecture
from fwclean.naming import lire_contextes, lire_correspondances
from fwclean.report import ecrire
from fwclean.reseaux import ecrire_reseaux, reseaux_connectes
from fwclean.script import generer_script
from fwclean.sites import Referentiel, lire_reseaux

_CONTEXTES_DEFAUT = ("dmz", "lan", "wan", "vpn")


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
            "  fwclean audit inbox/pare-feu.conf --sortie out\n"
            "  fwclean audit inbox/pare-feu.conf --reseaux reseaux.exemple.csv\n"
            "  fwclean reseaux inbox/pare-feu.conf --site siege\n"
            "  fwclean script inbox/pare-feu.conf --plan out/plan.json"
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
        help="Fichier des zones autorisées, une par ligne (défaut : ./contextes.txt)",
    )
    audit.add_argument(
        "--reseaux",
        help=(
            "Référentiel reseau;site;zone qui donne le site et la zone des objets "
            "(défaut : ./reseaux.csv s'il existe, sinon site CTX)"
        ),
    )
    reseaux = sous.add_parser(
        "reseaux",
        help="Écrire reseaux.csv depuis les interfaces d'une sauvegarde FortiGate",
        description=(
            "Lit config system interface, config system zone et les zones SD-WAN, et écrit "
            "un réseau par interface qui porte une IP. La zone FortiGate est traduite par "
            "les correspondances de contextes.txt (« mgmt = MGMT NETWORKS »)."
        ),
    )
    reseaux.add_argument("chemin", metavar="CONF", help="Sauvegarde FortiGate .conf")
    reseaux.add_argument("--site", required=True, help="Site de ce firewall, en minuscules (ex. siege)")
    reseaux.add_argument("--sortie", default="reseaux.csv", help="Fichier écrit (défaut : ./reseaux.csv)")
    reseaux.add_argument("--ecraser", action="store_true", help="Remplacer le fichier s'il existe")
    reseaux.add_argument("--contextes", help="Fichier des zones (défaut : ./contextes.txt)")

    script = sous.add_parser(
        "script",
        help="Écrire le script CLI FortiGate qui applique un plan relu",
        description=(
            "Relit la sauvegarde et le plan, et écrit trois fichiers de commandes : "
            "01-renommages.txt, 02-fusions.txt, 03-retraits.txt, découpés en lots. "
            "Les objets par défaut de FortiGate sont exclus. Rien n'est envoyé à l'équipement."
        ),
    )
    script.add_argument("chemin", metavar="CONF", help="Sauvegarde FortiGate .conf auditée")
    script.add_argument("--plan", default="out/plan.json", help="Plan relu (défaut : out/plan.json)")
    script.add_argument("--sortie", default="out/script", help="Dossier des scripts (défaut : out/script)")
    script.add_argument("--lot", type=int, default=20, help="Objets par lot (défaut : 20)")
    script.add_argument(
        "--inclure-defauts",
        action="store_true",
        help="Traiter aussi les objets par défaut de FortiGate (ALL, HTTP, always, …)",
    )

    args = analyseur.parse_args(argv)
    if args.commande == "audit":
        return _auditer(args)
    if args.commande == "reseaux":
        return _reseaux(args)
    if args.commande == "script":
        return _script(args)
    analyseur.print_help()
    return 2


def _auditer(args: argparse.Namespace) -> int:
    try:
        contextes = _resoudre_contextes(args.contextes)
        referentiel = _resoudre_reseaux(args.reseaux, contextes)
        inventaire = charger([Path(chemin) for chemin in args.chemins])
        resultat = auditer(inventaire, contextes, referentiel)
        rapport, plan = ecrire(resultat, Path(args.sortie))
    except ErreurLecture as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"Référentiel réseaux : {resultat.referentiel}")
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


def _resoudre_reseaux(chemin: str | None, contextes: tuple[str, ...]) -> Referentiel:
    if chemin:
        return lire_reseaux(Path(chemin), contextes)
    local = Path.cwd() / "reseaux.csv"
    if local.is_file():
        return lire_reseaux(local, contextes)
    return Referentiel()


def _reseaux(args: argparse.Namespace) -> int:
    try:
        chemin_contextes = Path(args.contextes) if args.contextes else Path.cwd() / "contextes.txt"
        if chemin_contextes.is_file():
            contextes = lire_contextes(chemin_contextes)
            correspondances = lire_correspondances(chemin_contextes)
        else:
            contextes, correspondances = _CONTEXTES_DEFAUT, {}
        sortie = Path(args.sortie)
        if sortie.exists() and not args.ecraser:
            raise ErreurLecture(f"{sortie} existe déjà : relancer avec --ecraser pour le remplacer.")
        source = Path(args.chemin)
        lignes = reseaux_connectes(source.read_text(encoding="utf-8-sig"), contextes, correspondances)
        texte = ecrire_reseaux(lignes, args.site, source.name, contextes)
    except (ErreurLecture, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    sortie.write_text(texte, encoding="utf-8")
    sans_zone = [ligne for ligne in lignes if ligne.zone is None]
    print(f"Référentiel : {sortie}")
    print(f"Réseaux connectés : {len(lignes)}, sans zone traduite : {len(sans_zone)}.")
    for ligne in sans_zone:
        print(f"  à compléter : {ligne.reseau} ({ligne.zone_fortigate or ligne.interface})")
    return 0


def _script(args: argparse.Namespace) -> int:
    try:
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
        texte = Path(args.chemin).read_text(encoding="utf-8-sig")
        resultat = generer_script(texte, plan, args.lot, args.inclure_defauts)
    except (ErreurLecture, OSError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    dossier = Path(args.sortie)
    dossier.mkdir(parents=True, exist_ok=True)
    (dossier / "01-renommages.txt").write_text(resultat.renommages, encoding="utf-8")
    (dossier / "02-fusions.txt").write_text(resultat.fusions, encoding="utf-8")
    (dossier / "03-retraits.txt").write_text(resultat.retraits, encoding="utf-8")
    ignores = "\n".join(f"- {ligne}" for ligne in resultat.ignores) or "Aucun."
    (dossier / "ignores.txt").write_text(
        "Opérations du plan non reprises dans le script :\n\n" + ignores + "\n", encoding="utf-8"
    )
    c = resultat.compteurs
    print(f"Scripts : {dossier}")
    print(
        f"Renommages : {c['renommages']}, fusions : {c['fusions']}, retraits : {c['retraits']}, "
        f"ignorés : {len(resultat.ignores)} (voir ignores.txt)."
    )
    print("Rien n'a été envoyé au firewall.")
    return 0
