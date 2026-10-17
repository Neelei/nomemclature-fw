"""Génération des scripts Python SNS (stormshield.sns.sslclient)."""

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
    assert _commande_delete("groupe-adresses", "g", globale=True) == "CONFIG GLOBAL OBJECT GROUP DELETE name=g"


def test_commandes_new_conformes_au_guide_cli():
    """Guide CLI serverd v5 : HOST NEW et FQDN NEW exigent une adresse ; pas de RANGE NEW."""
    from fwclean.model import Objet
    from fwclean.script_sns import _commandes_new
    from fwclean.stormshield_natif import FIGE_DYNAMIQUE

    def new(objet):
        resultat = _commandes_new(objet, "local", [], "global_x")
        return resultat and resultat[0][0]

    dynamique = Objet(
        sorte="fqdn", nom="pc.lan", empreinte=("fqdn", "pc.lan"), detail="pc.lan",
        fige=FIGE_DYNAMIQUE, adresses=("10.210.0.57",),
    )
    assert new(dynamique) == (
        'CONFIG OBJECT HOST NEW name=local ip=10.210.0.57 resolve=dynamic comment="remplace global_x (SMC)"'
    )
    fqdn = Objet(sorte="fqdn", nom="k.com", empreinte=("fqdn", "k.com"), detail="k.com", adresses=("fe80::1",))
    assert new(fqdn) == 'CONFIG OBJECT FQDN NEW name=local ipv6=fe80::1 comment="remplace global_x (SMC)"'
    sans_ip = Objet(sorte="fqdn", nom="k.com", empreinte=("fqdn", "k.com"), detail="k.com")
    assert new(sans_ip) is None
    plage = Objet(sorte="plage", nom="p", empreinte=("v4", "10.0.0.1", "10.0.0.9"), detail="")
    assert new(plage) == (
        'CONFIG OBJECT HOST NEW name=local begin=10.0.0.1 end=10.0.0.9 comment="remplace global_x (SMC)"'
    )


def test_lecture_garde_l_adresse_des_noms_dns(tmp_path):
    from fwclean.stormshield_natif import _fqdn, _hote

    dynamique, _ = _hote("pc.lan", "10.210.0.57,resolve=dynamic")
    assert dynamique.sorte == "fqdn" and dynamique.adresses == ("10.210.0.57",)
    fqdn, _ = _fqdn("Kelio", "84.239.81.6")
    assert fqdn.adresses == ("84.239.81.6",)


def test_hote_dynamique_supprime_comme_host(tmp_path):
    from fwclean.model import Inventaire
    from fwclean.stormshield_natif import _hote

    dynamique, _ = _hote("pc.lan", "10.0.0.85,resolve=dynamic")
    inventaire = Inventaire(constructeur="stormshield", sources=("test",), objets=(dynamique,))
    plan = {
        "constructeur": "stormshield",
        "renommages": [],
        "fusions": [],
        "retraits": [{"sorte": "fqdn", "nom": "pc.lan", "motif": "orphelin"}],
    }
    script = generer_script_sns(inventaire, plan)
    assert "CONFIG OBJECT HOST DELETE name=pc.lan" in script.retraits
    assert "FQDN DELETE" not in script.retraits


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


def test_lot_globaux(tmp_path, referentiel):
    from fwclean.audit import auditer
    from fwclean.report import plan_dict

    inventaire = charger([_export_slot_05(tmp_path)])
    plan = plan_dict(auditer(inventaire, referentiel))
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
    # Lot 04 : aucune suppression ; elles sont dans le lot 05, groupe englobant d'abord.
    assert "global=1" not in lot and "DELETE name=" not in lot
    suppr = script.suppression_globaux
    assert suppr.index("GROUP DELETE name=GRP_IMBRIQUE\"") < suppr.index("GROUP DELETE name=GRP_SERVEURS\"")
    assert "CONFIG GLOBAL OBJECT HOST DELETE name=SRV_RETIRE" in suppr
    assert "CONFIG GLOBAL OBJECT NETWORK DELETE name=LAN_USERS" in suppr
    # Cité par une route, membre d'un groupe global à revoir, ou à revoir : pas supprimés.
    for nom in ("PASSERELLE_SECOURS", "SRV_APPLI", "NAS_INCONNU", "GRP_A_REVOIR"):
        assert f"DELETE name={nom}\"" not in suppr
    assert any("global_PASSERELLE_SECOURS : cité dans une route" in i for i in script.ignores)
    assert any("global_GRP_A_REVOIR : à revoir" in i for i in script.ignores)
    assert "global=1" not in suppr and "CONFIG GLOBAL" not in script.retraits
    for texte in (lot, suppr):
        ns: dict = {}
        exec(texte, ns)
        assert ns["main"](["--dry-run"]) == 0


def test_lot_globaux_objet_local_existant(tmp_path, referentiel):
    from fwclean.audit import auditer
    from fwclean.report import plan_dict

    inventaire = charger([_export_slot_05(tmp_path)])
    plan = plan_dict(auditer(inventaire, referentiel))
    for item in plan["globaux"]:
        if item["ancien"] == "global_SRV_APPLI":
            item["nouveau"] = "SIEGE_HST_DMZ_SRV-WEB"
    script = generer_script_sns(inventaire, plan)
    assert any("global_SRV_APPLI : SIEGE_HST_DMZ_SRV-WEB existe déjà" in i for i in script.ignores)
    assert any("global_GRP_SERVEURS : membre(s) SIEGE_HST_SERVEURS_SRV-APPLI non créé(s)" in i for i in script.ignores)
    assert "DELETE name=GRP_SERVEURS\"" not in script.suppression_globaux


def test_cli_sns_ecrit_lot_globaux(tmp_path, racine):
    sortie = tmp_path / "out"
    dossier = _export_slot_05(tmp_path)
    assert executer(
        [
            "audit",
            str(dossier),
            "--sortie",
            str(sortie),
            "--reseaux",
            str(racine / "reseaux.exemple.csv"),
        ]
    ) == 0
    assert executer(
        ["script", str(dossier), "--plan", str(sortie / "plan.json"), "--sortie", str(sortie / "sns")]
    ) == 0
    assert "CONFIG GLOBAL" not in (sortie / "sns" / "04-globaux.py").read_text(encoding="utf-8")
    assert "CONFIG GLOBAL OBJECT" in (sortie / "sns" / "05-suppression-globaux.py").read_text(encoding="utf-8")


def test_global_avec_homonyme_local_supprime_dans_l_espace_global(tmp_path, referentiel):
    """CONFIG GLOBAL OBJECT … DELETE ne vise que le global : l'homonyme local n'est pas touché."""
    from dataclasses import replace

    from fwclean.audit import auditer
    from fwclean.model import Objet
    from fwclean.report import plan_dict

    inventaire = charger([_export_slot_05(tmp_path)])
    plan = plan_dict(auditer(inventaire, referentiel))
    homonyme = Objet(sorte="hote", nom="SRV_RETIRE", empreinte=(("v4", "10.9.9.9", 32),), detail="10.9.9.9")
    inventaire = replace(inventaire, objets=inventaire.objets + (homonyme,))
    script = generer_script_sns(inventaire, plan)
    assert "CONFIG GLOBAL OBJECT HOST DELETE name=SRV_RETIRE" in script.suppression_globaux
    assert "CONFIG OBJECT HOST DELETE name=SRV_RETIRE" not in script.suppression_globaux


def test_liste_cli_separee_par_des_virgules():
    from fwclean.script_sns import _liste

    assert _liste(("a", "b c")) == '"a,b c"'
    assert _liste(("a", "b")) == "a,b"


class _Reponse:
    def __init__(self, ret: int, output: str = ""):
        self.ret = ret
        self.output = output or f'{ret} code=00a00100 msg="x"'


def _executer_lot(monkeypatch, commandes, refus=(), argv=()):
    """Exécute un script généré contre un faux SSLClient ; renvoie (code, commandes envoyées, kwargs)."""
    import sys
    import types

    from fwclean.script_sns import _rendre_script

    envoyees: list[str] = []
    connexion: dict = {}

    class FauxClient:
        def __init__(self, **kwargs):
            connexion.update(kwargs)

        def send_command(self, commande):
            envoyees.append(commande)
            return _Reponse(200 if commande in refus else 100)

        def disconnect(self):
            envoyees.append("<disconnect>")

    module = types.ModuleType("stormshield.sns.sslclient")
    module.SSLClient = FauxClient
    for nom in ("stormshield", "stormshield.sns"):
        monkeypatch.setitem(sys.modules, nom, types.ModuleType(nom))
    monkeypatch.setitem(sys.modules, "stormshield.sns.sslclient", module)
    monkeypatch.setenv("SNS_PASS", "secret-de-test")
    ns: dict = {}
    exec(_rendre_script("test", [(c, "o") for c in commandes], 20), ns)
    code = ns["main"](["--host", "10.0.0.1", *argv])
    return code, envoyees, connexion


def test_execution_modify_on_et_connexion(monkeypatch):
    code, envoyees, connexion = _executer_lot(monkeypatch, ["CONFIG OBJECT RENAME type=host oldname=a newname=b"])
    assert code == 0
    assert envoyees == [
        "MODIFY ON",
        "CONFIG OBJECT RENAME type=host oldname=a newname=b",
        "CONFIG OBJECT ACTIVATE",
        "CONFIG FILTER ACTIVATE",
        "<disconnect>",
    ]
    assert connexion["password"] == "secret-de-test"
    assert connexion["sslverifyhost"] is False and connexion["sslverifypeer"] is False
    assert "sslverify" not in connexion


def test_execution_arret_sans_activation(monkeypatch, capsys):
    commandes = [
        "CONFIG OBJECT HOST DELETE name=deja_utilise",
        "CONFIG FILTER RULE UPDATE index=05 global=0 type=filter position=1 srctarget=x output=xml",
        "CONFIG OBJECT HOST DELETE name=y",
    ]
    code, envoyees, _ = _executer_lot(monkeypatch, commandes, refus={commandes[0], commandes[1]})
    assert code == 1
    # DELETE refusé : on continue ; RULE UPDATE refusé : arrêt, ni DELETE suivant ni ACTIVATE.
    assert envoyees == ["MODIFY ON", *commandes[:2], "<disconnect>"]
    erreurs = capsys.readouterr().err
    assert "--depuis 2" in erreurs and "secret-de-test" not in erreurs


def test_execution_reprise_depuis(monkeypatch):
    commandes = ["CONFIG OBJECT HOST DELETE name=a", "CONFIG OBJECT HOST DELETE name=b"]
    code, envoyees, _ = _executer_lot(monkeypatch, commandes, argv=("--depuis", "2"))
    assert code == 0
    assert envoyees[:2] == ["MODIFY ON", "CONFIG OBJECT HOST DELETE name=b"]


def test_execution_modify_on_refuse(monkeypatch):
    code, envoyees, _ = _executer_lot(monkeypatch, ["CONFIG OBJECT HOST DELETE name=a"], refus={"MODIFY ON"})
    assert code == 1
    assert envoyees == ["MODIFY ON", "<disconnect>"]


def test_execution_jusqua(monkeypatch):
    commandes = ["CONFIG GLOBAL OBJECT HOST DELETE name=a", "CONFIG GLOBAL OBJECT HOST DELETE name=b"]
    code, envoyees, _ = _executer_lot(monkeypatch, commandes, argv=("--jusqua", "1"))
    assert code == 0
    assert envoyees == ["MODIFY ON", commandes[0], "CONFIG OBJECT ACTIVATE", "CONFIG FILTER ACTIVATE", "<disconnect>"]


def test_version_cli_a_coller(tmp_path, referentiel):
    from fwclean.audit import auditer
    from fwclean.report import plan_dict

    inventaire = charger([_export_slot_05(tmp_path)])
    plan = plan_dict(auditer(inventaire, referentiel))
    script = generer_script_sns(inventaire, plan, lot=2)
    assert set(script.cli) == {
        "01-renommages", "02-fusions", "03-retraits", "04-globaux", "05-suppression-globaux", "06-natifs"
    }
    for nom, texte in script.cli.items():
        lignes = texte.splitlines()
        assert lignes[:2] == ["MODIFY ON", ""]
        assert not any(ligne.startswith("#") for ligne in lignes)
        assert lignes[-2:] == ["CONFIG OBJECT ACTIVATE", "CONFIG FILTER ACTIVATE"]
    # Mêmes commandes que le script Python, dans le même ordre.
    ns: dict = {}
    exec(script.globaux, ns)
    commandes = [ligne for ligne in script.cli["04-globaux"].splitlines() if ligne.startswith("CONFIG ") and "ACTIVATE" not in ligne]
    assert commandes == [c for c, _o in ns["COMMANDES"]]
    # Blocs de 2 commandes séparés par une ligne vide.
    assert "\n\n" in script.cli["04-globaux"].split("MODIFY ON\n\n", 1)[1].rsplit("\n\nCONFIG OBJECT ACTIVATE", 1)[0]


def test_cli_sns_ecrit_les_fichiers_cli(tmp_path, racine):
    sortie = tmp_path / "out"
    dossier = _export_slot_05(tmp_path)
    executer(["audit", str(dossier), "--sortie", str(sortie), "--reseaux", str(racine / "reseaux.exemple.csv")])
    assert executer(["script", str(dossier), "--plan", str(sortie / "plan.json"), "--sortie", str(sortie / "sns")]) == 0
    noms = {chemin.name for chemin in (sortie / "sns").iterdir()}
    assert {f"{n}.cli.txt" for n in ("01-renommages", "02-fusions", "03-retraits", "04-globaux", "05-suppression-globaux")} <= noms


def test_lot_natifs(tmp_path, referentiel):
    from fwclean.audit import auditer
    from fwclean.report import plan_dict

    inventaire = charger([_export_slot_05(tmp_path)])
    plan = plan_dict(auditer(inventaire, referentiel))
    script = generer_script_sns(inventaire, plan)
    lot = script.natifs
    assert (
        'CONFIG OBJECT HOST NEW name=SIEGE_HST_FW_LAN-USERS ip=10.0.0.254 resolve=static '
        'comment=\\"remplace Firewall_LAN (natif SNS)\\"' in lot
    )
    assert "CONFIG OBJECT HOST NEW name=SIEGE_HST_FW_WAN ip=203.0.113.2 resolve=static" in lot
    # r8 (position 12) : Network_LAN réutilise le réseau conservé, Firewall_LAN l'hôte créé.
    assert "position=12 srctarget=SIEGE_NET_V10_LAN-USERS output=xml" in lot
    assert "position=12 dsttarget=SIEGE_HST_FW_LAN-USERS output=xml" in lot
    # r9 : Network_internals reste ; Firewall_in (DHCP) reste, Firewall_out remplacé.
    assert "position=13 dsttarget=Firewall_in,SIEGE_HST_FW_WAN output=xml" in lot
    assert "Network_internals" not in lot and "NETWORK NEW" not in lot
    assert "DELETE name=" not in lot and "DELETE" not in script.cli["06-natifs"]
    assert any("natif Firewall_in : laissé natif" in i and "DHCP" in i for i in script.ignores)
    assert any("natif Firewall_out : encore cité par 1 NAT" in i for i in script.ignores)
    assert script.compteurs["natifs_crees"] == 2 and script.compteurs["natifs_reutilises"] == 1
    lignes = script.cli["06-natifs"].splitlines()
    assert lignes[:2] == ["MODIFY ON", ""] and lignes[-2:] == ["CONFIG OBJECT ACTIVATE", "CONFIG FILTER ACTIVATE"]
    ns: dict = {}
    exec(lot, ns)
    assert ns["main"](["--dry-run"]) == 0


def test_lot_natifs_reecrit_les_groupes_locaux_seulement():
    from fwclean.model import Objet
    from fwclean.script_sns import _Etat, _natifs

    local = Objet(sorte="groupe-adresses", nom="GRP_L", empreinte=(), detail="", mentions_adresses=("Network_LAN",))
    globale = Objet(
        sorte="groupe-adresses", nom="global_G", empreinte=(), detail="", mentions_adresses=("Network_LAN",), globale=True
    )
    etat = _Etat(
        objets={("adresse", "GRP_L"): local, ("adresse", "global_G"): globale},
        groupes={("adresse", "GRP_L"): ["Network_LAN"], ("adresse", "global_G"): ["Network_LAN"]},
        regles=[],
        cites_route_nat=set(),
    )
    item = {"natif": "Network_LAN", "sorte": "reseau", "action": "creer", "nouveau": "S_NET_LAN", "contenu": "10.0.0.0/24"}
    commandes, _compteurs = _natifs(etat, [item], lambda _e, nom: nom, [])
    textes = [c for c, _o in commandes]
    assert textes[0].startswith("CONFIG OBJECT NETWORK NEW name=S_NET_LAN ip=10.0.0.0 mask=255.255.255.0")
    assert "CONFIG OBJECT GROUP ADDTO group=GRP_L node=S_NET_LAN" in textes
    assert "CONFIG OBJECT GROUP REMOVEFROM group=GRP_L node=Network_LAN" in textes
    assert not any("global_G" in texte for texte in textes)


def test_cli_sns_ecrit_lot_natifs(tmp_path, racine):
    sortie = tmp_path / "out"
    dossier = _export_slot_05(tmp_path)
    assert executer(
        ["audit", str(dossier), "--sortie", str(sortie), "--reseaux", str(racine / "reseaux.exemple.csv")]
    ) == 0
    assert executer(
        ["script", str(dossier), "--plan", str(sortie / "plan.json"), "--sortie", str(sortie / "sns")]
    ) == 0
    assert "HST_FW_LAN-USERS" in (sortie / "sns" / "06-natifs.py").read_text(encoding="utf-8")
    assert (sortie / "sns" / "06-natifs.cli.txt").is_file()
