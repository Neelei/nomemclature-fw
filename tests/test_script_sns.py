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
