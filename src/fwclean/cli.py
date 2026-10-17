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
from fwclean.report import ecrire
from fwclean.reseaux import (
    Completion,
    completer_reseaux,
    ecrire_reseaux,
    peu_parlant,
    reseaux_connectes,
    reseaux_sns,
)
from fwclean.script import generer_script
from fwclean.script_sns import generer_script_sns
from fwclean.sites import Referentiel, lire_reseaux
from fwclean.stormshield_natif import genre_natif

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
            "  fwclean audit examples/stormshield-natif --sortie out/sns\n"
            "  fwclean audit inbox/pare-feu.conf --sortie out\n"
            "  fwclean audit inbox/pare-feu.conf --reseaux reseaux.exemple.csv\n"
            "  fwclean reseaux inbox/pare-feu.conf --site siege\n"
            "  fwclean script inbox/pare-feu.conf --plan out/plan.json\n"
            "  fwclean script inbox/stormshield --plan out/stormshield/plan.json --sortie out/stormshield"
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
        help=(
            "Fichier .conf FortiGate, CSV Stormshield, fichiers natifs SNS "
            "(object, objectgroup, servicegroup, Filter, Network, route) ou dossier d'export"
        ),
    )
    audit.add_argument(
        "--sortie",
        default="out",
        help="Dossier du rapport et du plan (défaut : out)",
    )
    audit.add_argument(
        "--reseaux",
        help=(
            "Référentiel reseau;site;vlan;interface qui donne le site et l'interface des "
            "objets, et le VLAN des réseaux (défaut : ./reseaux.csv s'il existe, "
            "sinon objets à adresse IP à revoir)"
        ),
    )
    reseaux = sous.add_parser(
        "reseaux",
        help="Écrire reseaux.csv depuis les interfaces d'une sauvegarde FortiGate ou d'un SNS",
        description=(
            "FortiGate : lit config system interface et écrit un réseau par interface qui porte "
            "une IP. SNS : lit le fichier Network (interfaces à adresse statique). Colonnes "
            "reseau;site;vlan;interface : vlan = vlanid ou Tag ; interface = alias FortiGate "
            "(set alias), à défaut nom de l'interface, et Name côté SNS ; à remplacer à la main "
            "s'il ne dit rien (port3, VLAN-131…)."
        ),
    )
    reseaux.add_argument(
        "chemin",
        metavar="CHEMIN",
        help="Sauvegarde FortiGate .conf, fichier Network SNS ou dossier qui le contient",
    )
    reseaux.add_argument("--site", required=True, help="Site de ce firewall, en minuscules (ex. siege)")
    reseaux.add_argument("--sortie", default="reseaux.csv", help="Fichier écrit (défaut : ./reseaux.csv)")
    remplacement = reseaux.add_mutually_exclusive_group()
    remplacement.add_argument("--ecraser", action="store_true", help="Remplacer le fichier s'il existe")
    remplacement.add_argument(
        "--ajouter",
        action="store_true",
        help=(
            "Compléter le fichier existant : ajoute les réseaux absents, remplit VLAN et "
            "interface des lignes du même site qui n'ont pas d'interface, remplace par l'alias "
            "un nom technique FortiGate encore en place, retire l'ancienne colonne zone, garde "
            "les autres lignes et commentaires, signale sans les modifier les réseaux déjà "
            "présents avec un autre site, VLAN ou interface"
        ),
    )

    script = sous.add_parser(
        "script",
        help="Écrire les scripts d'application d'un plan relu (FortiGate CLI ou SNS Python)",
        description=(
            "Relit la sauvegarde et le plan. FortiGate : 01-renommages.txt, 02-fusions.txt, "
            "03-retraits.txt. Stormshield : 01-renommages.py, 02-fusions.py, 03-retraits.py, "
            "et 04-globaux.py si des objets globaux SMC sont lus (python-SNS-API, --dry-run). "
            "Rien n'est envoyé à l'équipement."
        ),
    )
    script.add_argument(
        "chemin",
        metavar="CHEMIN",
        help="Sauvegarde FortiGate .conf, ou dossier d'export natif SNS (inbox/stormshield)",
    )
    script.add_argument("--plan", default="out/plan.json", help="Plan relu (défaut : out/plan.json)")
    script.add_argument(
        "--sortie",
        default="out/fortigate",
        help="Dossier des scripts (défaut : out/fortigate, ou out/stormshield si plan SNS)",
    )
    script.add_argument("--lot", type=int, default=20, help="Objets par lot (défaut : 20)")
    script.add_argument(
        "--deja-applique",
        action="append",
        default=[],
        metavar="SCRIPT",
        help=(
            "FortiGate seulement : script déjà collé (répétable, dans l'ordre) ; rejoué sur la "
            "sauvegarde, et seuls 02b-rattrapage.txt et 03-retraits.txt sont écrits pour la suite"
        ),
    )
    script.add_argument(
        "--inclure-defauts",
        action="store_true",
        help="FortiGate : traiter aussi les objets par défaut (ALL, HTTP, always, …)",
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
        referentiel = _resoudre_reseaux(args.reseaux)
        inventaire = charger([Path(chemin) for chemin in args.chemins])
        resultat = auditer(inventaire, referentiel)
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
        f"orphelins : {'suspendus' if resultat.inventaire.retraits_suspendus else len(resultat.retraits)}."
    )
    if resultat.inventaire.constructeur == "stormshield":
        print(f"Objets natifs SNS ignorés : {len(resultat.natifs)}.")
    if resultat.globaux:
        actions: dict[str, int] = {}
        for item in resultat.globaux:
            actions[item.action] = actions.get(item.action, 0) + 1
        detail = ", ".join(f"{action} {nombre}" for action, nombre in sorted(actions.items()))
        print(f"Objets globaux SMC : {len(resultat.globaux)} ({detail}).")
    for message in resultat.inventaire.avertissements:
        print(f"Avertissement : {message}")
    print("Aucune modification appliquée.")
    return 0


def _resoudre_reseaux(chemin: str | None) -> Referentiel:
    if chemin:
        return lire_reseaux(Path(chemin))
    local = Path.cwd() / "reseaux.csv"
    if local.is_file():
        return lire_reseaux(local)
    return Referentiel()


def _reseaux(args: argparse.Namespace) -> int:
    try:
        sortie = Path(args.sortie)
        completer = args.ajouter and sortie.exists()
        if sortie.exists() and not (args.ecraser or completer):
            raise ErreurLecture(
                f"{sortie} existe déjà : relancer avec --ajouter pour le compléter "
                "ou --ecraser pour le remplacer."
            )
        source = _source_reseaux(Path(args.chemin))
        contenu = source.read_text(encoding="utf-8-sig")
        if not source.suffix and genre_natif(source.name, contenu) == "network":
            constructeur = "stormshield"
            lignes = reseaux_sns(contenu)
        else:
            constructeur = "fortigate"
            lignes = reseaux_connectes(contenu)
        if completer:
            completion = completer_reseaux(
                sortie.read_text(encoding="utf-8-sig"), lignes, args.site, source.name, constructeur
            )
        else:
            texte = ecrire_reseaux(lignes, args.site, source.name, constructeur)
    except (ErreurLecture, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if completer:
        code = _afficher_completion(sortie, completion)
    else:
        sortie.write_text(texte, encoding="utf-8")
        print(f"Référentiel : {sortie}")
        print(f"Réseaux connectés : {len(lignes)}.")
        desactivees = [ligne for ligne in lignes if ligne.desactivee]
        if desactivees:
            print(f"Interfaces désactivées, laissées en commentaire : {len(desactivees)}.")
        code = 0
    sans_alias = sorted({ligne.interface for ligne in lignes if ligne.sans_alias})
    if sans_alias:
        print(f"Interfaces FortiGate sans alias, nom technique écrit à la place : {', '.join(sans_alias)}.")
    peu_parlantes = sorted({ligne.nom_csv for ligne in lignes if peu_parlant(ligne.nom_csv)})
    if peu_parlantes:
        print(
            f"Noms d'interfaces peu parlants, à remplacer dans la colonne interface : "
            f"{', '.join(peu_parlantes)}."
        )
    return code


def _afficher_completion(sortie: Path, completion: Completion) -> int:
    if completion.ajoutees or completion.migrees or completion.alias_appliques:
        sortie.write_text(completion.texte, encoding="utf-8")
    print(f"Référentiel complété : {sortie}")
    print(
        f"Ajoutés : {len(completion.ajoutees)}, interface complétée : {len(completion.migrees)}, "
        f"alias appliqué : {len(completion.alias_appliques)}, "
        f"déjà présents : {len(completion.presentes)}, "
        f"différents (non modifiés) : {len(completion.differentes)}, "
        f"écartés : {len(completion.ecartees)}."
    )
    for libelle, liste in (
        ("ajouté", completion.ajoutees),
        ("interface complétée", completion.migrees),
        ("alias appliqué", completion.alias_appliques),
        ("déjà présent", completion.presentes),
        ("différent, non modifié", completion.differentes),
        ("écarté", completion.ecartees),
    ):
        for ligne in liste:
            print(f"  {libelle} : {ligne}")
    return 0


def _source_reseaux(chemin: Path) -> Path:
    if not chemin.is_dir():
        return chemin
    for enfant in sorted(chemin.iterdir()):
        if enfant.is_file() and enfant.name.lower() == "network":
            return enfant
    raise ErreurLecture(f"{chemin} : aucun fichier Network SNS dans ce dossier.")


def _script(args: argparse.Namespace) -> int:
    try:
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
        if plan.get("constructeur") == "stormshield":
            if args.deja_applique:
                raise ErreurLecture("--deja-applique n'est pas géré pour Stormshield.")
            inventaire = charger([Path(args.chemin)])
            resultat = generer_script_sns(inventaire, plan, args.lot)
            dossier = Path(args.sortie)
            if args.sortie == "out/fortigate":
                dossier = Path("out/stormshield")
            dossier.mkdir(parents=True, exist_ok=True)
            (dossier / "01-renommages.py").write_text(resultat.renommages, encoding="utf-8")
            (dossier / "02-fusions.py").write_text(resultat.fusions, encoding="utf-8")
            (dossier / "03-retraits.py").write_text(resultat.retraits, encoding="utf-8")
            if plan.get("globaux"):
                (dossier / "04-globaux.py").write_text(resultat.globaux, encoding="utf-8")
            ignores = "\n".join(f"- {ligne}" for ligne in resultat.ignores) or "Aucun."
            (dossier / "ignores.txt").write_text(
                "Opérations du plan non reprises dans les scripts SNS :\n\n" + ignores + "\n",
                encoding="utf-8",
            )
            c = resultat.compteurs
            print(f"Scripts SNS : {dossier}")
            print(
                f"Commandes renommages : {c.get('commandes_renommages', c['renommages'])}, "
                f"fusions : {c.get('commandes_fusions', c['fusions'])} "
                f"({c['fusions']} DELETE), "
                f"retraits : {c['retraits']}, "
                f"ignorés : {len(resultat.ignores)} (voir ignores.txt)."
            )
            ordre = "01 → 02 → 03"
            if plan.get("globaux"):
                print(
                    f"Objets globaux SMC : {c['globaux_crees']} objet(s) local(aux) créé(s), "
                    f"{c['globaux_remplaces']} remplacé(s) dans les règles et groupes, "
                    f"{c['globaux_supprimes']} suppression(s) global=1 "
                    f"({c['commandes_globaux']} commandes)."
                )
                ordre += " → 04"
            print(f"Exécuter avec --dry-run puis sans, dans l'ordre {ordre}. Rien n'a été envoyé.")
            return 0

        texte = Path(args.chemin).read_text(encoding="utf-8-sig")
        appliques = tuple(Path(chemin).read_text(encoding="utf-8") for chemin in args.deja_applique)
        resultat = generer_script(texte, plan, args.lot, args.inclure_defauts, appliques)
    except (ErreurLecture, OSError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    dossier = Path(args.sortie)
    dossier.mkdir(parents=True, exist_ok=True)
    if appliques:
        (dossier / "02b-rattrapage.txt").write_text(resultat.rattrapage, encoding="utf-8")
        refus = "\n".join(f"- {ligne}" for ligne in resultat.erreurs_deja_appliquees) or "Aucune."
        (dossier / "deja-applique.txt").write_text(
            "Commandes des scripts déjà appliqués que FortiOS a dû refuser (simulation sur la sauvegarde) :\n\n"
            + refus
            + "\n",
            encoding="utf-8",
        )
    else:
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
