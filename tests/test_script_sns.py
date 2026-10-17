"""Génération des scripts Python SNS (python-SNS-API)."""

import ast
import json
from pathlib import Path

from fwclean.charger import charger
from fwclean.cli import executer
from fwclean.script_sns import generer_script_sns
from fwclean.stormshield_natif import lire_filtre_natif

EXEMPLE = Path(__file__).resolve().parents[1] / "examples" / "stormshield-natif"


def test_filtre_slot_et_position():
    texte = (EXEMPLE / "Filter").read_text(encoding="utf-8")
    regles, _liens = lire_filtre_natif(texte, prefixe="05:", slot="05")
    assert regles
    assert all(r.slot == "05" and isinstance(r.position, int) for r in regles)
    assert any(r.sources_brutes or r.destinations_brutes for r in regles)


def test_rename_host_et_compile():
    inventaire = charger([EXEMPLE])
    plan = {
        "constructeur": "stormshield",
        "renommages": [
            {
                "sorte": "hote",
                "ancien": "srv_web",
                "nouveau": "SIEGE_HST_LAN-USERS_SRV-WEB",
                "references": [],
            }
        ],
        "fusions": [],
        "retraits": [],
    }
    script = generer_script_sns(inventaire, plan, lot=20)
    assert "CONFIG OBJECT RENAME type=host oldname=srv_web newname=SIEGE_HST_LAN-USERS_SRV-WEB" in script.renommages
    ast.parse(script.renommages)
    ns: dict = {}
    exec(script.renommages, ns)
    assert ns["main"](["--dry-run"]) == 0


def test_fusion_groupe_addto_removefrom():
    inventaire = charger([EXEMPLE])
    plan = {
        "constructeur": "stormshield",
        "renommages": [],
        "fusions": [
            {
                "sorte": "hote",
                "contenu": "10.0.0.10/32",
                "conserve": "srv_web",
                "nouveau_nom": "srv_web",
                "supprimes": ["Web_DMZ"],
                "references_reecrites": ["grp_web"],
            }
        ],
        "retraits": [],
    }
    script = generer_script_sns(inventaire, plan)
    # srv_web est déjà membre : pas d'ADDTO, seulement REMOVEFROM puis DELETE.
    assert "ADDTO group=grp_web node=srv_web" not in script.fusions
    assert "CONFIG OBJECT GROUP REMOVEFROM group=grp_web node=Web_DMZ" in script.fusions
    assert "CONFIG OBJECT HOST DELETE name=Web_DMZ" in script.fusions
    ast.parse(script.fusions)


def test_fusion_citee_route_ignoree():
    inventaire = charger([EXEMPLE])
    # passerelle_lan ou équivalent cité en route
    cites_route = {a for lien in inventaire.liens if "route" in lien.origine for a in lien.adresses}
    assert cites_route
    nom = next(n for n in cites_route if any(o.nom == n for o in inventaire.objets))
    objet = next(o for o in inventaire.objets if o.nom == nom)
    autre = next(o for o in inventaire.objets if o.sorte == objet.sorte and o.nom != nom)
    plan = {
        "constructeur": "stormshield",
        "renommages": [],
        "fusions": [
            {
                "sorte": objet.sorte,
                "contenu": "x",
                "conserve": autre.nom,
                "nouveau_nom": autre.nom,
                "supprimes": [nom],
                "references_reecrites": [],
            }
        ],
        "retraits": [],
    }
    script = generer_script_sns(inventaire, plan)
    assert any("route ou un NAT" in i for i in script.ignores)
    assert f"DELETE name={nom}" not in script.fusions


def test_plage_delete_host():
    from fwclean.script_sns import _commande_delete

    assert _commande_delete("plage", "plage1") == "CONFIG OBJECT HOST DELETE name=plage1"
    assert _commande_delete("hote", "x") == "CONFIG OBJECT HOST DELETE name=x"
    assert _commande_delete("reseau", "x") == "CONFIG OBJECT NETWORK DELETE name=x"


def test_cli_sns_ecrit_py(tmp_path):
    plan = {
        "constructeur": "stormshield",
        "renommages": [],
        "fusions": [],
        "retraits": [{"sorte": "hote", "nom": "__absent__", "motif": "test"}],
    }
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    sortie = tmp_path / "out"
    code = executer(
        ["script", str(EXEMPLE), "--plan", str(plan_path), "--sortie", str(sortie)]
    )
    assert code == 0
    for nom in ("01-renommages.py", "02-fusions.py", "03-retraits.py", "ignores.txt"):
        assert (sortie / nom).is_file()


def _export_slot_05(tmp_path):
    import shutil

    dossier = tmp_path / "sns"
    shutil.copytree(EXEMPLE, dossier, ignore=shutil.ignore_patterns("Filter"))
    (dossier / "Filter").mkdir()
    shutil.copy(EXEMPLE / "Filter", dossier / "Filter" / "05")
    return dossier


def test_lot_globaux(tmp_path, contextes, referentiel):
    from fwclean.audit import auditer
    from fwclean.report import plan_dict

    inventaire = charger([_export_slot_05(tmp_path)])
    plan = plan_dict(auditer(inventaire, contextes, referentiel))
    script = generer_script_sns(inventaire, plan)
    lot = script.globaux
    assert "CONFIG OBJECT HOST NEW name=SIEGE_HST_SERVEURS_SRV-APPLI ip=10.1.2.20 resolve=static" in lot
    assert "CONFIG OBJECT SERVICE NEW name=SVC_TCP_8080_HTTP-APPLI port=8080 proto=tcp" in lot
    assert "CONFIG OBJECT GROUP ADDTO group=SIEGE_GRP_MULTI_IMBRIQUE node=SIEGE_GRP_MULTI_SERVEURS" in lot
    # Le groupe imbriqué est créé après le groupe qu'il contient.
    assert lot.index("GROUP NEW name=SIEGE_GRP_MULTI_SERVEURS") < lot.index("GROUP NEW name=SIEGE_GRP_MULTI_IMBRIQUE")
    # Règles g1 (position 10) et g2 (position 11) réécrites vers les objets locaux.
    assert "index=05 global=0 type=filter position=10 srctarget=SIEGE_GRP_MULTI_IMBRIQUE output=xml" in lot
    assert "position=10 dsttarget=SIEGE_HST_DMZ_SRV-WEB output=xml" in lot
    assert "position=10 dstport=SG_WEB-APPLI output=xml" in lot
    assert "position=11 dstport=SVC_TCP_8080_HTTP-APPLI output=xml" in lot
    # Suppressions global=1, groupe englobant avant le groupe contenu, après les réécritures.
    assert lot.index("RULE UPDATE") < lot.index("DELETE name=GRP_IMBRIQUE global=1")
    assert lot.index("DELETE name=GRP_IMBRIQUE global=1") < lot.index("DELETE name=GRP_SERVEURS global=1")
    assert "CONFIG OBJECT HOST DELETE name=SRV_RETIRE global=1" in lot
    assert "CONFIG OBJECT NETWORK DELETE name=LAN_USERS global=1" in lot
    # Cité par une route, membre d'un groupe global à revoir, ou à revoir : pas supprimés.
    for nom in ("PASSERELLE_SECOURS", "SRV_APPLI", "NAS_INCONNU", "GRP_A_REVOIR"):
        assert f"DELETE name={nom} global=1" not in lot
    assert any("global_PASSERELLE_SECOURS : cité dans une route" in i for i in script.ignores)
    assert any("global_GRP_A_REVOIR : à revoir" in i for i in script.ignores)
    assert '"CONFIG OBJECT ACTIVATE global=1",' in lot
    assert "global=1" not in script.retraits
    ns: dict = {}
    exec(lot, ns)
    assert ns["main"](["--dry-run"]) == 0


def test_lot_globaux_objet_local_existant(tmp_path, contextes, referentiel):
    from fwclean.audit import auditer
    from fwclean.report import plan_dict

    inventaire = charger([_export_slot_05(tmp_path)])
    plan = plan_dict(auditer(inventaire, contextes, referentiel))
    for item in plan["globaux"]:
        if item["ancien"] == "global_SRV_APPLI":
            item["nouveau"] = "SIEGE_HST_DMZ_SRV-WEB"
    script = generer_script_sns(inventaire, plan)
    assert any("global_SRV_APPLI : SIEGE_HST_DMZ_SRV-WEB existe déjà" in i for i in script.ignores)
    assert any("global_GRP_SERVEURS : membre(s) SIEGE_HST_SERVEURS_SRV-APPLI non créé(s)" in i for i in script.ignores)
    assert "DELETE name=GRP_SERVEURS global=1" not in script.globaux


def test_cli_sns_ecrit_lot_globaux(tmp_path, racine):
    sortie = tmp_path / "out"
    dossier = _export_slot_05(tmp_path)
    assert executer(
        [
            "audit",
            str(dossier),
            "--sortie",
            str(sortie),
            "--contextes",
            str(racine / "contextes.txt"),
            "--reseaux",
            str(racine / "reseaux.exemple.csv"),
        ]
    ) == 0
    assert executer(
        ["script", str(dossier), "--plan", str(sortie / "plan.json"), "--sortie", str(sortie / "sns")]
    ) == 0
    assert "global=1" in (sortie / "sns" / "04-globaux.py").read_text(encoding="utf-8")
