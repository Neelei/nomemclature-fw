"""Scripts Python (stormshield.sns.sslclient) à partir d'un plan Stormshield. Rien n'est envoyé à l'équipement."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, replace

from fwclean.model import ErreurLecture, Inventaire, Objet, Regle
from fwclean.naming import ESPACE
from fwclean.script import Script
from fwclean.sns_natifs import est_natif
from fwclean.stormshield_natif import FIGE_DYNAMIQUE, PREFIXE_GLOBAL

ACTIVATE = ("CONFIG OBJECT ACTIVATE", "CONFIG FILTER ACTIVATE")

# sorte fwclean → type RENAME SNS / module DELETE.
TYPES_RENAME = {
    "hote": "host",
    "reseau": "network",
    "plage": "range",
    "fqdn": "fqdn",
    "groupe-adresses": "group",
    "service": "service",
    "groupe-services": "servicegroup",
    "protocole": "protocol",
}
# DELETE : plage → HOST (CLI SNS).
MODULES_DELETE = {
    "hote": "HOST",
    "reseau": "NETWORK",
    "plage": "HOST",
    "fqdn": "FQDN",
    "groupe-adresses": "GROUP",
    "service": "SERVICE",
    "groupe-services": "SERVICEGROUP",
    "protocole": "PROTOCOL",
}

_CHAMPS_REGLE = (
    ("srctarget", "sources", "sources_brutes"),
    ("dsttarget", "destinations", "destinations_brutes"),
    ("dstport", "services", "services_brutes"),
)

_GABARIT = '''\
#!/usr/bin/env python3
\"\"\"__TITRE__

AVERTISSEMENT SMC : ne pas redéployer depuis SMC après exécution, sinon les
modifications locales sur le SNS sont écrasées.

Dépendance : pip install stormshield.sns.sslclient
Mot de passe : variable d'environnement SNS_PASS, sinon demandé au lancement.
Rien n'est envoyé avec --dry-run. Arrêt à la première erreur hors suppression,
sans activation ; reprendre ensuite avec --depuis N. --jusqua N borne l'envoi.
\"\"\"

from __future__ import annotations

import argparse
import getpass
import os
import sys

COMMANDES: list[tuple[str, str]] = [
__COMMANDES__
]

ACTIVATE = (
__ACTIVATE__
)


def _succes(reponse) -> tuple[bool, int | None, str]:
    code = getattr(reponse, "ret", None)
    texte = str(getattr(reponse, "output", reponse))
    if code is None:
        premiere = texte.splitlines()[0].split() if texte.strip() else []
        code = int(premiere[0]) if premiere and premiere[0].isdigit() else None
    return code is not None and 100 <= code < 200, code, texte


def main(argv: list[str] | None = None) -> int:
    analyseur = argparse.ArgumentParser(description=__doc__)
    analyseur.add_argument("--host", default="192.168.0.254", help="Adresse du SNS")
    analyseur.add_argument("--port", type=int, default=443, help="Port HTTPS (défaut 443)")
    analyseur.add_argument("--user", default="admin", help="Compte admin SNS")
    analyseur.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Vérifier le certificat TLS (désactivé par défaut)",
    )
    analyseur.add_argument(
        "--dry-run",
        action="store_true",
        help="Afficher les commandes sans se connecter",
    )
    analyseur.add_argument(
        "--depuis",
        type=int,
        default=1,
        help="Reprendre à la commande N (numéro affiché), après un arrêt sur erreur",
    )
    analyseur.add_argument(
        "--jusqua",
        type=int,
        default=None,
        help="S'arrêter après la commande N (incluse), puis activer : test sur quelques commandes",
    )
    args = analyseur.parse_args(argv)
    total = len(COMMANDES)
    fin = total if args.jusqua is None else args.jusqua
    if not 1 <= args.depuis <= max(fin, 1) or not 1 <= fin <= max(total, 1):
        print(f"--depuis / --jusqua : 1 <= depuis <= jusqua <= {total}", file=sys.stderr)
        return 2
    a_envoyer = list(enumerate(COMMANDES, start=1))[args.depuis - 1 : fin]

    if args.dry_run:
        print("MODIFY ON")
        for numero, (commande, origine) in a_envoyer:
            print(f"# [{numero}/{total}] {origine}")
            print(commande)
        for commande in ACTIVATE:
            print(commande)
        print(f"# dry-run : {len(a_envoyer)} commande(s) sur {total}, non envoyées", file=sys.stderr)
        return 0

    try:
        from stormshield.sns.sslclient import SSLClient
    except ImportError:
        print("Installez le client SNS : pip install stormshield.sns.sslclient", file=sys.stderr)
        return 2

    mot_de_passe = os.environ.get("SNS_PASS") or getpass.getpass(f"Mot de passe {args.user}@{args.host} : ")
    try:
        client = SSLClient(
            host=args.host,
            port=args.port,
            user=args.user,
            password=mot_de_passe,
            sslverifyhost=args.verify_ssl,
            sslverifypeer=args.verify_ssl,
        )
    except Exception as exc:  # noqa: BLE001 — connexion, TLS ou authentification
        print(f"Connexion impossible à {args.host}:{args.port} : {exc}", file=sys.stderr)
        return 2
    ok = ignore = 0
    arret: int | None = None
    try:
        reussi, code, texte = _succes(client.send_command("MODIFY ON"))
        if not reussi:
            print(f"MODIFY ON refusé (code={code}) : un autre administrateur a-t-il la main ?", file=sys.stderr)
            print(texte, file=sys.stderr)
            return 1
        for numero, (commande, origine) in a_envoyer:
            reussi, code, texte = _succes(client.send_command(commande))
            if reussi:
                ok += 1
                avertissement = "" if code == 100 else f"  [code {code}] " + texte.strip().splitlines()[-1]
                print(f"OK  [{numero}/{total}] {commande}  # {origine}{avertissement}")
            elif " DELETE " in commande:
                ignore += 1
                print(f"IGN [{numero}/{total}] {commande}  # non supprimé (code={code}) — {origine}")
                print(texte.strip(), file=sys.stderr)
            else:
                arret = numero
                print(f"ERR [{numero}/{total}] {commande}  # code={code} {origine}", file=sys.stderr)
                print(texte.strip(), file=sys.stderr)
                break
        if arret is None:
            for commande in ACTIVATE:
                reussi, code, texte = _succes(client.send_command(commande))
                print(f"ACT {commande} -> code={code}")
                if not reussi:
                    print(texte.strip(), file=sys.stderr)
                    arret = 0
    finally:
        client.disconnect()
    print(f"Résumé : ok={ok}, suppressions refusées={ignore}", file=sys.stderr)
    if arret:
        print(
            f"Arrêt sur la commande {arret} : rien n'a été activé. Les commandes 1 à {arret - 1} "
            "sont écrites mais pas activées : corriger puis relancer avec "
            f"--depuis {arret}, ou restaurer la sauvegarde.",
            file=sys.stderr,
        )
        return 1
    if arret == 0:
        print("Activation en erreur : vérifier la configuration sur le SNS.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


@dataclass
class _Etat:
    objets: dict[tuple[str, str], Objet]
    groupes: dict[tuple[str, str], list[str]]
    regles: list[Regle]
    cites_route_nat: set[tuple[str, str]]


def generer_script_sns(inventaire: Inventaire, plan: dict, lot: int = 20) -> Script:
    """Produit les quatre scripts Python SNS et la liste des ignorés."""
    if plan.get("constructeur") != "stormshield":
        raise ErreurLecture("Le script SNS ne concerne que Stormshield.")
    if lot < 1:
        raise ErreurLecture("--lot doit valoir au moins 1.")

    etat = _charger(inventaire)
    ignores: list[str] = []
    renommes: dict[tuple[str, str], str] = {}
    supprimes: set[tuple[str, str]] = set()

    def courant(espace: str, nom: str) -> str | None:
        nom = renommes.get((espace, nom), nom)
        if (espace, nom) in etat.objets:
            return nom
        return None

    doublons = {
        (ESPACE[f["sorte"]], d)
        for f in plan.get("fusions", [])
        for d in f["supprimes"]
        if not est_natif(f["sorte"], d)
    }

    cmds_renom: list[tuple[str, str]] = []
    for item in plan.get("renommages", []):
        sorte, ancien, nouveau = item["sorte"], item["ancien"], item["nouveau"]
        if sorte not in TYPES_RENAME:
            ignores.append(f"renommage de {ancien} : sorte non gérée ({sorte})")
            continue
        espace = ESPACE[sorte]
        if est_natif(sorte, ancien):
            ignores.append(f"renommage de {ancien} : objet natif SNS")
        elif (espace, ancien) in doublons:
            ignores.append(f"renommage de {ancien} : doublon supprimé à l'étape 02")
        elif (espace, ancien) not in etat.objets:
            ignores.append(f"renommage de {ancien} : absent de l'export")
        elif (espace, nouveau) in etat.objets:
            ignores.append(f"renommage de {ancien} : {nouveau} existe déjà")
        else:
            typ = TYPES_RENAME[sorte]
            cmds_renom.append(
                (
                    f"CONFIG OBJECT RENAME type={typ} oldname={_q(ancien)} newname={_q(nouveau)}",
                    f"renommage {ancien} -> {nouveau}",
                )
            )
            objet = etat.objets.pop((espace, ancien))
            etat.objets[(espace, nouveau)] = replace(objet, nom=nouveau)
            _renommer_refs(etat, espace, ancien, nouveau)
            renommes[(espace, ancien)] = nouveau

    cmds_fusion: list[tuple[str, str]] = []
    for fusion in plan.get("fusions", []):
        sorte = fusion["sorte"]
        if sorte not in TYPES_RENAME:
            ignores.append(f"fusion vers {fusion['conserve']} : sorte non gérée ({sorte})")
            continue
        espace = ESPACE[sorte]
        cible = courant(espace, fusion["conserve"])
        if cible is None:
            ignores.append(f"fusion vers {fusion['conserve']} : objet conservé absent de l'export")
            continue
        for doublon in fusion["supprimes"]:
            if est_natif(sorte, doublon):
                ignores.append(f"fusion de {doublon} : objet natif SNS")
                continue
            nom = courant(espace, doublon)
            if nom is None:
                ignores.append(f"fusion de {doublon} : absent de l'export")
                continue
            if nom == cible:
                ignores.append(f"fusion de {doublon} : c'est l'objet conservé")
                continue
            origine = f"doublon {nom} -> conservé {cible}"
            if fusion.get("contenu"):
                origine += f" ({fusion['contenu']})"
            if (espace, nom) in etat.cites_route_nat:
                ignores.append(
                    f"fusion de {nom} : cité dans une route ou un NAT, à reprendre à la main"
                )
                continue
            cmds_fusion.extend(_reecrire_groupes(etat, espace, nom, cible, origine))
            cmds_fusion.extend(_reecrire_regles(etat, espace, nom, cible, origine))
            if _encore_cite(etat, espace, nom):
                ignores.append(
                    f"suppression de {nom} : encore référencé après réécriture, à reprendre à la main"
                )
                continue
            cmds_fusion.append((_commande_delete(_sorte_sns(etat, espace, nom, sorte), nom), f"suppression doublon — {origine}"))
            _oublier(etat, espace, nom)
            supprimes.add((espace, nom))

    cmds_retrait: list[tuple[str, str]] = []
    ordre = list(TYPES_RENAME)
    for item in sorted(plan.get("retraits", []), key=lambda i: (ordre.index(i["sorte"]) if i["sorte"] in ordre else 99, i["nom"])):
        sorte, nom_plan = item["sorte"], item["nom"]
        if sorte not in TYPES_RENAME:
            ignores.append(f"retrait de {nom_plan} : sorte non gérée ({sorte})")
            continue
        espace = ESPACE[sorte]
        if est_natif(sorte, nom_plan):
            ignores.append(f"retrait de {nom_plan} : objet natif SNS")
            continue
        nom = courant(espace, nom_plan)
        if nom is None:
            ignores.append(f"retrait de {nom_plan} : absent de l'export")
        elif _encore_cite(etat, espace, nom) or (espace, nom) in etat.cites_route_nat:
            ignores.append(f"retrait de {nom} : encore référencé dans l'export")
        else:
            cmds_retrait.append((_commande_delete(_sorte_sns(etat, espace, nom, sorte), nom), f"retrait — {item.get('motif', 'orphelin')}"))
            _oublier(etat, espace, nom)

    cmds_globaux, cmds_suppr_globaux, compteurs_globaux = _globaux(
        etat, plan.get("globaux", []), courant, ignores
    )
    cmds_natifs, compteurs_natifs = _natifs(etat, plan.get("natifs_interfaces", []), courant, ignores)

    cli = {
        "01-renommages": _rendre_cli(cmds_renom, lot),
        "02-fusions": _rendre_cli(cmds_fusion, lot),
        "03-retraits": _rendre_cli(cmds_retrait, lot),
        "04-globaux": _rendre_cli(cmds_globaux, lot),
        "05-suppression-globaux": _rendre_cli(cmds_suppr_globaux, lot),
        "06-natifs": _rendre_cli(cmds_natifs, lot),
    }
    return Script(
        cli=cli,
        renommages=_rendre_script("01 — Renommages SNS", cmds_renom, lot),
        fusions=_rendre_script("02 — Fusions de doublons SNS", cmds_fusion, lot),
        retraits=_rendre_script("03 — Retraits d'orphelins SNS", cmds_retrait, lot),
        ignores=tuple(ignores),
        compteurs={
            "renommages": len(cmds_renom),
            "fusions": len([c for c, _o in cmds_fusion if " DELETE " in c]),
            "retraits": len(cmds_retrait),
            "commandes_renommages": len(cmds_renom),
            "commandes_fusions": len(cmds_fusion),
            "commandes_retraits": len(cmds_retrait),
            "commandes_globaux": len(cmds_globaux),
            "commandes_suppression_globaux": len(cmds_suppr_globaux),
            "commandes_natifs": len(cmds_natifs),
            **compteurs_globaux,
            **compteurs_natifs,
        },
        globaux=_rendre_script(
            "04 — Remplacement des objets globaux SMC par des objets locaux",
            cmds_globaux,
            lot,
        ),
        suppression_globaux=_rendre_script(
            "05 — Suppression des objets globaux SMC remplacés (CONFIG GLOBAL OBJECT … DELETE)",
            cmds_suppr_globaux,
            lot,
        ),
        natifs=_rendre_script(
            "06 — Natifs d'interface (Network_X, Firewall_X) remplacés dans les règles, sans suppression",
            cmds_natifs,
            lot,
        ),
    )


def _globaux(
    etat: _Etat,
    items: list[dict],
    courant: Callable[[str, str], str | None],
    ignores: list[str],
) -> tuple[list[tuple[str, str]], list[tuple[str, str]], dict[str, int]]:
    """Lot 04 : création des objets locaux, réécriture des règles et groupes locaux.
    Lot 05 : suppression des objets globaux remplacés ou cités par rien (groupes d'abord)."""
    commandes: list[tuple[str, str]] = []
    globaux = {cle for cle, objet in etat.objets.items() if objet.globale}
    remplacants: dict[tuple[str, str], str] = {}
    a_supprimer: list[tuple[str, str]] = []
    crees = 0

    for item in items:
        sorte, ancien, action = item["sorte"], item["ancien"], item["action"]
        if sorte not in TYPES_RENAME:
            ignores.append(f"global {ancien} : sorte non gérée ({sorte})")
            continue
        espace = ESPACE[sorte]
        if (espace, ancien) not in globaux:
            ignores.append(f"global {ancien} : absent de l'export")
            continue
        if action == "supprimer":
            a_supprimer.append((espace, ancien))
            continue
        if action not in {"reutiliser", "creer"}:
            ignores.append(f"global {ancien} : à revoir — {item.get('commentaire') or 'sans remplaçant'}")
            continue
        nouveau = item["nouveau"]
        if action == "reutiliser":
            local = courant(espace, nouveau)
            if local is None:
                ignores.append(f"global {ancien} : objet local {nouveau} absent après les lots 01 à 03")
                continue
            remplacants[(espace, ancien)] = local
            continue
        if (espace, nouveau) in etat.objets:
            ignores.append(f"global {ancien} : {nouveau} existe déjà, à reprendre à la main")
            continue
        objet = etat.objets[(espace, ancien)]
        membres: list[str] = []
        if sorte in {"groupe-adresses", "groupe-services"}:
            manquants = [m for m in item.get("membres", []) if (espace, m) not in etat.objets]
            if manquants:
                ignores.append(
                    f"global {ancien} : membre(s) {', '.join(manquants)} non créé(s), groupe à reprendre à la main"
                )
                continue
            membres = list(item.get("membres", []))
        creation = _commandes_new(objet, nouveau, membres, ancien)
        if creation is None:
            ignores.append(f"global {ancien} : création de {sorte} non gérée ({objet.detail}), à faire à la main")
            continue
        commandes.extend(creation)
        crees += 1
        etat.objets[(espace, nouveau)] = replace(objet, nom=nouveau, globale=False)
        if membres:
            etat.groupes[(espace, nouveau)] = membres
        remplacants[(espace, ancien)] = nouveau

    groupes_globaux = {cle for cle in etat.groupes if cle in globaux}
    remplaces = 0
    for (espace, ancien), local in remplacants.items():
        origine = f"{ancien} -> {local}"
        if (espace, ancien) in etat.cites_route_nat:
            ignores.append(
                f"global {ancien} : cité dans une route ou un NAT, remplacer par {local} à la main"
            )
            continue
        commandes.extend(_reecrire_groupes(etat, espace, ancien, local, origine, groupes_globaux))
        commandes.extend(_reecrire_regles(etat, espace, ancien, local, origine))
        remplaces += 1
        a_supprimer.append((espace, ancien))

    suppressions: list[tuple[str, str]] = []
    supprimes = 0
    restants = sorted(set(a_supprimer), key=lambda cle: (cle not in groupes_globaux, cle[0], cle[1]))
    progres = True
    while restants and progres:
        progres = False
        for cle in list(restants):
            espace, nom = cle
            if cle in etat.cites_route_nat or _encore_cite(etat, espace, nom) or _cite_ipproto(etat, espace, nom):
                continue
            objet = etat.objets[cle]
            suppressions.append(
                (
                    _commande_delete(_sorte_sns(etat, espace, nom, objet.sorte), nom.removeprefix(PREFIXE_GLOBAL), globale=True),
                    f"suppression objet global — {nom}",
                )
            )
            _oublier(etat, espace, nom)
            restants.remove(cle)
            supprimes += 1
            progres = True
    for espace, nom in restants:
        ignores.append(f"suppression de {nom} : encore référencé après remplacement, à reprendre à la main")
    return commandes, suppressions, {
        "globaux_crees": crees,
        "globaux_remplaces": remplaces,
        "globaux_supprimes": supprimes,
    }


def _commandes_new(
    objet: Objet, nom: str, membres: list[str], ancien: str, provenance: str = "SMC"
) -> list[tuple[str, str]] | None:
    """Commandes CONFIG OBJECT … NEW d'un objet local (guide CLI serverd v5)."""
    origine = f"création {nom} (remplace {ancien})"
    commentaire = f"comment={_q('remplace ' + ancien + ' (' + provenance + ')')}"
    nom_q = _q(nom)
    sorte = objet.sorte
    if sorte == "hote":
        v4 = [ip for famille, ip, _p in objet.empreinte if famille == "v4"]
        v6 = [ip for famille, ip, _p in objet.empreinte if famille == "v6"]
        if len(v4) > 1 or len(v6) > 1:
            return None
        adresses = (f" ip={v4[0]}" if v4 else "") + (f" ipv6={v6[0]}" if v6 else "")
        commande = f"CONFIG OBJECT HOST NEW name={nom_q}{adresses} resolve=static {commentaire}"
    elif sorte == "fqdn":
        v4 = [ip for ip in objet.adresses if ipaddress.ip_address(ip).version == 4]
        v6 = [ip for ip in objet.adresses if ipaddress.ip_address(ip).version == 6]
        if not objet.adresses or len(v4) > 1 or len(v6) > 1:
            return None
        adresses = (f" ip={v4[0]}" if v4 else "") + (f" ipv6={v6[0]}" if v6 else "")
        if objet.fige == FIGE_DYNAMIQUE:
            commande = f"CONFIG OBJECT HOST NEW name={nom_q}{adresses} resolve=dynamic {commentaire}"
        else:
            commande = f"CONFIG OBJECT FQDN NEW name={nom_q}{adresses} {commentaire}"
    elif sorte == "reseau":
        famille, adresse, prefixe = objet.empreinte[0]
        if famille != "v4" or len(objet.empreinte) > 1:
            return None
        masque = ipaddress.ip_network(f"{adresse}/{prefixe}").netmask
        commande = f"CONFIG OBJECT NETWORK NEW name={nom_q} ip={adresse} mask={masque} {commentaire}"
    elif sorte == "plage":
        famille, debut, fin = objet.empreinte
        bornes = f"begin={debut} end={fin}" if famille == "v4" else f"beginv6={debut} endv6={fin}"
        commande = f"CONFIG OBJECT HOST NEW name={nom_q} {bornes} {commentaire}"
    elif sorte == "service":
        protos = {proto for proto, _plages in objet.empreinte}
        plages = {plages for _proto, plages in objet.empreinte}
        if len(plages) != 1 or protos not in ({"tcp"}, {"udp"}, {"tcp", "udp"}):
            return None
        (plage,) = plages
        if len(plage) != 1 or plage[0][2] >= 0:
            return None
        debut, fin, _sd, _sf = plage[0]
        proto = "any" if len(protos) == 2 else protos.pop()
        bornes = f"port={debut}" + (f" toport={fin}" if fin != debut else "")
        commande = f"CONFIG OBJECT SERVICE NEW name={nom_q} {bornes} proto={proto} {commentaire}"
    elif sorte == "protocole":
        ((_proto, ((numero, _f, _sd, _sf),)),) = objet.empreinte
        commande = f"CONFIG OBJECT PROTOCOL NEW name={nom_q} protonumber={numero} {commentaire}"
    elif sorte in {"groupe-adresses", "groupe-services"}:
        module = "GROUP" if sorte == "groupe-adresses" else "SERVICEGROUP"
        commandes = [(f"CONFIG OBJECT {module} NEW name={nom_q} {commentaire}", origine)]
        commandes.extend(
            (f"CONFIG OBJECT {module} ADDTO group={nom_q} node={_q(membre)}", f"ADDTO — {origine}")
            for membre in membres
        )
        return commandes
    else:
        return None
    return [(commande, origine)]


def _natifs(
    etat: _Etat,
    items: list[dict],
    courant: Callable[[str, str], str | None],
    ignores: list[str],
) -> tuple[list[tuple[str, str]], dict[str, int]]:
    """Lot 06 : objet local à la place de Network_X / Firewall_X dans les règles de filtrage et
    les groupes locaux. Aucun DELETE : le natif reste, le NAT et les routes le citent encore."""
    commandes: list[tuple[str, str]] = []
    espace = "adresse"
    crees = reutilises = 0
    for item in items:
        natif, action = item["natif"], item.get("action")
        if action not in {"reutiliser", "creer"}:
            ignores.append(f"natif {natif} : laissé natif, à revoir — {item.get('commentaire') or 'sans remplaçant'}")
            continue
        nouveau = item["nouveau"]
        if action == "reutiliser":
            local = courant(espace, nouveau)
            if local is None or (espace, local) not in etat.objets:
                ignores.append(f"natif {natif} : objet local {nouveau} absent après les lots 01 à 05")
                continue
            reutilises += 1
        else:
            if (espace, nouveau) in etat.objets:
                ignores.append(f"natif {natif} : {nouveau} existe déjà, à reprendre à la main")
                continue
            objet = _objet_natif(item)
            creation = _commandes_new(objet, nouveau, [], natif, "natif SNS")
            if creation is None:
                ignores.append(f"natif {natif} : création de {nouveau} non gérée ({item.get('contenu')})")
                continue
            commandes.extend(creation)
            etat.objets[(espace, nouveau)] = replace(objet, nom=nouveau)
            local = nouveau
            crees += 1
        origine = f"{natif} -> {local}"
        globaux = {cle for cle, objet in etat.objets.items() if objet.globale}
        commandes.extend(_reecrire_groupes(etat, espace, natif, local, origine, globaux))
        commandes.extend(_reecrire_regles(etat, espace, natif, local, origine))
        if item.get("nat"):
            nat = item["nat"]
            exemples = ", ".join(nat[:3]) + (" …" if len(nat) > 3 else "")
            ignores.append(
                f"natif {natif} : encore cité par {len(nat)} NAT ou route ({exemples}), laissé natif "
                f"(remplacer par {local} à la main si souhaité)"
            )
    return commandes, {"natifs_crees": crees, "natifs_reutilises": reutilises}


def _objet_natif(item: dict) -> Objet:
    """Objet local (réseau ou hôte IPv4) au contenu du natif, d'après le plan."""
    if item["sorte"] == "reseau":
        reseau = ipaddress.ip_network(item["contenu"], strict=False)
        empreinte = (("v4", str(reseau.network_address), reseau.prefixlen),)
    else:
        empreinte = (("v4", str(ipaddress.ip_address(item["contenu"])), 32),)
    return Objet(sorte=item["sorte"], nom=item["natif"], empreinte=empreinte, detail=item["contenu"])


def _cite_ipproto(etat: _Etat, espace: str, nom: str) -> bool:
    return espace == "protocole" and any(nom in regle.protocoles for regle in etat.regles)


def _charger(inventaire: Inventaire) -> _Etat:
    objets: dict[tuple[str, str], Objet] = {}
    groupes: dict[tuple[str, str], list[str]] = {}
    for objet in inventaire.objets:
        espace = ESPACE[objet.sorte]
        objets[(espace, objet.nom)] = objet
        if objet.sorte == "groupe-adresses":
            groupes[(espace, objet.nom)] = list(objet.mentions_adresses)
        elif objet.sorte == "groupe-services":
            groupes[(espace, objet.nom)] = list(objet.mentions_services)
    cites: set[tuple[str, str]] = set()
    for lien in inventaire.liens:
        for nom in lien.adresses:
            cites.add(("adresse", nom))
        for nom in lien.services:
            cites.add(("service", nom))
        for nom in lien.protocoles:
            cites.add(("protocole", nom))
    return _Etat(
        objets=objets,
        groupes=groupes,
        regles=list(inventaire.regles),
        cites_route_nat=cites,
    )


def _renommer_refs(etat: _Etat, espace: str, ancien: str, nouveau: str) -> None:
    for cle, membres in list(etat.groupes.items()):
        etat.groupes[cle] = [nouveau if m == ancien else m for m in membres]
        if cle == (espace, ancien):
            etat.groupes[(espace, nouveau)] = etat.groupes.pop(cle)
    nouvelles: list[Regle] = []
    for regle in etat.regles:
        nouvelles.append(
            replace(
                regle,
                sources=tuple(nouveau if n == ancien else n for n in regle.sources),
                destinations=tuple(nouveau if n == ancien else n for n in regle.destinations),
                services=tuple(nouveau if n == ancien else n for n in regle.services),
                sources_brutes=tuple(nouveau if n == ancien else n for n in regle.sources_brutes),
                destinations_brutes=tuple(nouveau if n == ancien else n for n in regle.destinations_brutes),
                services_brutes=tuple(nouveau if n == ancien else n for n in regle.services_brutes),
            )
        )
    etat.regles = nouvelles
    if (espace, ancien) in etat.cites_route_nat:
        etat.cites_route_nat.discard((espace, ancien))
        etat.cites_route_nat.add((espace, nouveau))


def _reecrire_groupes(
    etat: _Etat,
    espace: str,
    doublon: str,
    cible: str,
    origine: str,
    sauf: set[tuple[str, str]] | frozenset = frozenset(),
) -> list[tuple[str, str]]:
    commandes: list[tuple[str, str]] = []
    module = "GROUP" if espace == "adresse" else "SERVICEGROUP" if espace == "service" else None
    if module is None:
        return commandes
    for (esp_g, nom_g), membres in list(etat.groupes.items()):
        if esp_g != espace or doublon not in membres or (esp_g, nom_g) in sauf:
            continue
        if cible not in membres:
            commandes.append(
                (
                    f"CONFIG OBJECT {module} ADDTO group={_q(nom_g)} node={_q(cible)}",
                    f"ADDTO — {origine}",
                )
            )
            membres.append(cible)
        commandes.append(
            (
                f"CONFIG OBJECT {module} REMOVEFROM group={_q(nom_g)} node={_q(doublon)}",
                f"REMOVEFROM — {origine}",
            )
        )
        etat.groupes[(esp_g, nom_g)] = [m for m in membres if m != doublon]
    return commandes


def _reecrire_regles(
    etat: _Etat, espace: str, doublon: str, cible: str, origine: str
) -> list[tuple[str, str]]:
    commandes: list[tuple[str, str]] = []
    nouvelles: list[Regle] = []
    for regle in etat.regles:
        remplacements: list[tuple[str, tuple[str, ...]]] = []
        kwargs: dict = {}
        for champ_cli, attr, attr_brut in _CHAMPS_REGLE:
            valeurs = getattr(regle, attr)
            brutes = getattr(regle, attr_brut) or valeurs
            if espace == "adresse" and attr == "services":
                continue
            if espace == "service" and attr != "services":
                continue
            if espace == "protocole":
                continue
            if doublon not in valeurs and doublon not in brutes:
                continue
            finale = _remplacer_liste(brutes or valeurs, doublon, cible)
            remplacements.append((champ_cli, finale))
            kwargs[attr] = tuple(x for x in finale if x.lower() not in {"any", "internet", "none", "original"})
            kwargs[attr_brut] = finale
        if remplacements and regle.slot and regle.position is not None:
            for champ_cli, finale in remplacements:
                commandes.append(
                    (
                        "CONFIG FILTER RULE UPDATE "
                        f"index={regle.slot} global=0 type=filter position={regle.position} "
                        f"{champ_cli}={_liste(finale)} output=xml",
                        f"RULE UPDATE {champ_cli} — {origine} ({regle.nom})",
                    )
                )
            nouvelles.append(replace(regle, **kwargs))
        else:
            if remplacements and (regle.slot is None or regle.position is None):
                # Pas de slot/position : on met à jour l'état local sans commande.
                nouvelles.append(replace(regle, **kwargs))
            else:
                nouvelles.append(regle)
    etat.regles = nouvelles
    return commandes


def _remplacer_liste(valeurs: tuple[str, ...] | list[str], doublon: str, cible: str) -> tuple[str, ...]:
    vus: list[str] = []
    for nom in valeurs:
        remplace = cible if nom == doublon else nom
        if remplace not in vus:
            vus.append(remplace)
    return tuple(vus)


def _encore_cite(etat: _Etat, espace: str, nom: str) -> bool:
    for membres in etat.groupes.values():
        if nom in membres:
            return True
    for regle in etat.regles:
        if espace == "adresse" and (nom in regle.sources or nom in regle.destinations):
            return True
        if espace == "service" and nom in regle.services:
            return True
    return False


def _oublier(etat: _Etat, espace: str, nom: str) -> None:
    etat.objets.pop((espace, nom), None)
    etat.groupes.pop((espace, nom), None)


def _sorte_sns(etat: _Etat, espace: str, nom: str, sorte: str) -> str:
    """Un hôte resolve=dynamic est lu comme FQDN mais reste un HOST pour le SNS."""
    objet = etat.objets.get((espace, nom))
    return "hote" if objet is not None and objet.fige == FIGE_DYNAMIQUE else sorte


def _commande_delete(sorte: str, nom: str, globale: bool = False) -> str:
    espace = "CONFIG GLOBAL OBJECT" if globale else "CONFIG OBJECT"
    return f"{espace} {MODULES_DELETE[sorte]} DELETE name={_q(nom)}"


def _q(valeur: str) -> str:
    if re.search(r'[\s="\\\\]', valeur):
        return '"' + valeur.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return valeur


def _liste(valeurs: tuple[str, ...]) -> str:
    # Le fichier Filter sépare les objets par `|`, la CLI (RULE UPDATE) par `,`.
    return _q(",".join(valeurs)) if valeurs else '""'


def _rendre_cli(commandes: list[tuple[str, str]], lot: int, activate: tuple[str, ...] = ACTIVATE) -> str:
    """Commandes brutes à coller dans la console CLI du SNS : MODIFY ON, blocs de `lot` séparés
    par une ligne vide, puis l'activation. Aucun commentaire : la console ne les accepte pas."""
    lignes = ["MODIFY ON", ""]
    for index, (commande, _origine) in enumerate(commandes):
        if index and index % lot == 0:
            lignes.append("")
        lignes.append(commande)
    lignes.extend(["", *activate])
    return "\n".join(lignes) + "\n"


def _rendre_script(
    titre: str, commandes: list[tuple[str, str]], lot: int, activate: tuple[str, ...] = ACTIVATE
) -> str:
    lignes: list[str] = []
    for index, (commande, origine) in enumerate(commandes):
        if index and index % lot == 0:
            lignes.append(f"    # --- lot {index // lot + 1} ---")
        cmd = commande.replace("\\", "\\\\").replace('"', '\\"')
        org = origine.replace("\\", "\\\\").replace('"', '\\"')
        lignes.append(f'    ("{cmd}", "{org}"),')
    corps = "\n".join(lignes) if lignes else "    # (aucune commande)"
    activation = "\n".join(f'    "{commande}",' for commande in activate)
    return (
        _GABARIT.replace("__TITRE__", titre)
        .replace("__COMMANDES__", corps)
        .replace("__ACTIVATE__", activation)
    )
