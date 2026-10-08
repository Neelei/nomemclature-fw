"""Scripts Python python-SNS-API à partir d'un plan Stormshield. Rien n'est envoyé à l'équipement."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

from fwclean.model import ErreurLecture, Inventaire, Objet, Regle
from fwclean.naming import ESPACE
from fwclean.script import Script
from fwclean.sns_natifs import est_natif

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
"""__TITRE__

AVERTISSEMENT SMC : ne pas redéployer depuis SMC après exécution, sinon les
modifications locales sur le SNS sont écrasées.

Dépendance : pip install python-SNS-API
Rien n'est appliqué avec --dry-run.
"""

from __future__ import annotations

import argparse
import sys

COMMANDES: list[tuple[str, str]] = [
__COMMANDES__
]

ACTIVATE = (
    "CONFIG OBJECT ACTIVATE",
    "CONFIG FILTER ACTIVATE",
)


def main(argv: list[str] | None = None) -> int:
    analyseur = argparse.ArgumentParser(description=__doc__)
    analyseur.add_argument("--host", default="192.168.0.254", help="Adresse du SNS")
    analyseur.add_argument("--port", type=int, default=443, help="Port HTTPS (défaut 443)")
    analyseur.add_argument("--user", default="admin", help="Compte admin SNS")
    analyseur.add_argument("--password", default="", help="Mot de passe")
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
    args = analyseur.parse_args(argv)

    if args.dry_run:
        for commande, origine in COMMANDES:
            print(f"# {origine}")
            print(commande)
        for commande in ACTIVATE:
            print(commande)
        print(f"# dry-run : {len(COMMANDES)} commande(s), non envoyées", file=sys.stderr)
        return 0

    try:
        from stormshield.sns.sslclient import SSLClient
    except ImportError:
        print("Installez python-SNS-API : pip install python-SNS-API", file=sys.stderr)
        return 2

    client = SSLClient(
        host=args.host,
        port=args.port,
        user=args.user,
        password=args.password,
        sslverify=args.verify_ssl,
    )
    ok = ignore = erreur = 0
    try:
        for commande, origine in COMMANDES:
            reponse = client.send_command(commande)
            code = getattr(reponse, "ret", None)
            if code is None and hasattr(reponse, "output"):
                premiere = str(reponse.output).splitlines()[0] if reponse.output else ""
                code = int(premiere.split()[0]) if premiere.split() else None
            texte = str(getattr(reponse, "output", reponse))
            if code == 100:
                ok += 1
                print(f"OK  {commande}  # {origine}")
            elif code == 200 and "00e01c00" in texte:
                ignore += 1
                print(f"IGN {commande}  # encore utilisé — {origine}")
            else:
                erreur += 1
                print(f"ERR {commande}  # code={code} {origine}", file=sys.stderr)
                print(texte, file=sys.stderr)
        for commande in ACTIVATE:
            reponse = client.send_command(commande)
            print(f"ACT {commande} -> {getattr(reponse, 'ret', reponse)}")
    finally:
        close = getattr(client, "close", None) or getattr(client, "disconnect", None)
        if callable(close):
            close()
    print(f"Résumé : ok={ok}, ignorés={ignore}, erreurs={erreur}", file=sys.stderr)
    return 1 if erreur else 0


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
    """Produit les trois scripts Python SNS et la liste des ignors."""
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
            cmds_fusion.append((_commande_delete(sorte, nom), f"suppression doublon — {origine}"))
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
            cmds_retrait.append((_commande_delete(sorte, nom), f"retrait — {item.get('motif', 'orphelin')}"))
            _oublier(etat, espace, nom)

    return Script(
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
        },
    )


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
    etat: _Etat, espace: str, doublon: str, cible: str, origine: str
) -> list[tuple[str, str]]:
    commandes: list[tuple[str, str]] = []
    module = "GROUP" if espace == "adresse" else "SERVICEGROUP" if espace == "service" else None
    if module is None:
        return commandes
    for (esp_g, nom_g), membres in list(etat.groupes.items()):
        if esp_g != espace or doublon not in membres:
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


def _commande_delete(sorte: str, nom: str) -> str:
    return f"CONFIG OBJECT {MODULES_DELETE[sorte]} DELETE name={_q(nom)}"


def _q(valeur: str) -> str:
    if re.search(r'[\s="\\\\]', valeur):
        return '"' + valeur.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return valeur


def _liste(valeurs: tuple[str, ...]) -> str:
    return _q("|".join(valeurs)) if valeurs else '""'


def _rendre_script(titre: str, commandes: list[tuple[str, str]], lot: int) -> str:
    lignes: list[str] = []
    for index, (commande, origine) in enumerate(commandes):
        if index and index % lot == 0:
            lignes.append(f"    # --- lot {index // lot + 1} ---")
        cmd = commande.replace("\\", "\\\\").replace('"', '\\"')
        org = origine.replace("\\", "\\\\").replace('"', '\\"')
        lignes.append(f'    ("{cmd}", "{org}"),')
    corps = "\n".join(lignes) if lignes else "    # (aucune commande)"
    return _GABARIT.replace("__TITRE__", titre).replace("__COMMANDES__", corps)
