import json

import pytest

from fwclean.cli import executer
from fwclean.model import ErreurLecture
from fwclean.naming import analyser_contextes, cle_correspondance
from fwclean.reseaux import Ligne, ecrire_reseaux, reseaux_connectes
from fwclean.script import generer_script
from fwclean.sites import analyser_reseaux

CONTEXTES = """
lan
dmz
wan
mgmt = MGMT NETWORKS
"""

CONFIG = """
config system interface
    edit "mgmt"
        set ip 192.168.1.99 255.255.255.0
    next
    edit "VLAN-11"
        set ip 10.0.0.220 255.255.255.0
        set alias "SRV-ESX"
        set vlanid 11
    next
    edit "IDRAC"
        set ip 10.118.131.252 255.255.255.0
        set vlanid 131
    next
    edit "VLAN-777"
        set ip 172.16.255.253 255.255.255.252
        set vlanid 777
    next
    edit "PreProd FR"
        set ip 10.0.111.252 255.255.255.0
    next
    edit "wan1"
        set ip 0.0.0.0 0.0.0.0
    next
end
config system zone
    edit "LAN"
        set interface "VLAN-11"
    next
    edit "MGMT NETWORKS"
        set interface "IDRAC"
    next
    edit "PreProd FRANCE"
        set interface "PreProd FR"
    next
end
config system sdwan
    set status enable
    config zone
        edit "WAN"
        next
    end
    config members
        edit 1
            set interface "VLAN-777"
            set zone "WAN"
        next
    end
end
"""


def _contextes():
    zones = analyser_contextes(CONTEXTES)
    correspondances = {
        cle_correspondance("MGMT NETWORKS"): "mgmt",
    }
    return zones, correspondances


def test_reseaux_connectes_et_zones():
    zones, correspondances = _contextes()
    lignes = {ligne.interface: ligne for ligne in reseaux_connectes(CONFIG, zones, correspondances)}
    assert set(lignes) == {"mgmt", "VLAN-11", "IDRAC", "VLAN-777", "PreProd FR"}
    assert (lignes["VLAN-11"].reseau, lignes["VLAN-11"].zone) == ("10.0.0.0/24", "lan")
    assert lignes["IDRAC"].zone == "mgmt"
    assert (lignes["VLAN-777"].zone_fortigate, lignes["VLAN-777"].zone) == ("WAN", "wan")
    # Hors zone : zone vide, ce n'est pas un oubli.
    assert (lignes["mgmt"].zone_fortigate, lignes["mgmt"].zone) == (None, None)
    assert not lignes["mgmt"].zone_non_traduite
    assert lignes["PreProd FR"].zone is None and lignes["PreProd FR"].zone_non_traduite


def test_ecriture_du_referentiel():
    zones, correspondances = _contextes()
    texte = ecrire_reseaux(reseaux_connectes(CONFIG, zones, correspondances), "SIEGE", "test.conf", zones)
    assert "reseau;site;zone;vlan;interface" in texte
    assert (
        "10.0.0.0/24;siege;lan;11;VLAN-11  # VLAN-11 (SRV-ESX), zone LAN — nom peu parlant (alias : SRV-ESX)"
    ) in texte
    assert "10.118.131.0/24;siege;mgmt;131;IDRAC  # IDRAC, zone MGMT NETWORKS\n" in texte
    assert "192.168.1.0/24;siege;;;mgmt  # mgmt, hors zone\n" in texte
    assert "# 10.0.111.0/24;siege;?;;PreProd FR" in texte and "« <zone> = PreProd FRANCE »" in texte
    referentiel = analyser_reseaux(texte, zones)
    assert referentiel.sites == ("siege",)
    assert len(referentiel.entrees) == 4
    assert {str(entree.reseau): entree.vlan for entree in referentiel.entrees}["10.118.131.0/24"] == 131


def test_interfaces_peu_parlantes_et_homonymes():
    zones, _correspondances = _contextes()
    lignes = [
        Ligne("192.168.50.0/24", "VLAN-20", "VLAN-52", "LAN", "lan", 52),
        Ligne("10.0.20.0/22", "VLAN_20", "LAN-EP-PC", "LAN", "lan", 20),
        Ligne("10.0.16.0/24", "Cabines", "", "LAN", "lan", 16),
    ]
    texte = ecrire_reseaux(lignes, "hq", "test.conf", zones)
    assert "VLAN-20 (VLAN-52), zone LAN — nom peu parlant ; même nom normalisé que VLAN_20\n" in texte
    assert "— nom peu parlant (alias : LAN-EP-PC) ; même nom normalisé que VLAN-20\n" in texte
    assert "10.0.16.0/24;hq;lan;16;Cabines  # Cabines, zone LAN\n" in texte


def test_commande_reseaux(tmp_path, capsys, monkeypatch):
    (tmp_path / "contextes.txt").write_text(CONTEXTES, encoding="utf-8")
    (tmp_path / "fw.conf").write_text(CONFIG, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert executer(["reseaux", "fw.conf", "--site", "siege"]) == 0
    sortie = capsys.readouterr().out
    assert "Réseaux connectés : 5, zone FortiGate non traduite : 1." in sortie
    assert "à compléter : 10.0.111.0/24 (PreProd FRANCE)" in sortie
    assert "peu parlants, à remplacer dans la colonne interface : VLAN-11, VLAN-777." in sortie
    assert "192.168.1.0/24;siege;;;mgmt" in (tmp_path / "reseaux.csv").read_text(encoding="utf-8")
    assert executer(["reseaux", "fw.conf", "--site", "siege"]) == 2
    assert "--ecraser" in capsys.readouterr().err
    assert executer(["reseaux", "fw.conf", "--site", "siege", "--ecraser"]) == 0


OBJETS = """
config firewall address
    edit "SIEGE_HST_DMZ_WEB-01"
        set subnet 10.1.1.10 255.255.255.255
    next
    edit "Web_DMZ"
        set subnet 10.1.1.10 255.255.255.255
    next
    edit "srv-oublie"
        set subnet 10.9.9.9 255.255.255.255
    next
    edit "all"
    next
end
config firewall addrgrp
    edit "Groupe web"
        set member "Web_DMZ" "SIEGE_HST_DMZ_WEB-01"
    next
end
config firewall service custom
    edit "HTTP"
        set tcp-portrange 80
    next
end
config firewall schedule recurring
    edit "Bureau"
        set day monday
    next
end
config firewall policy
    edit 7
        set srcaddr "all"
        set dstaddr "Web_DMZ" "Groupe web"
        set service "HTTP"
        set schedule "Bureau"
    next
end
config router static
    edit 3
        set dstaddr "Web_DMZ"
    next
end
"""

PLAN = {
    "constructeur": "fortigate",
    "renommages": [
        {"sorte": "groupe-adresses", "ancien": "Groupe web", "nouveau": "SIEGE_GRP_DMZ_WEB", "references": []},
        {"sorte": "service", "ancien": "HTTP", "nouveau": "SVC_TCP_80_HTTP", "references": []},
        {"sorte": "calendrier", "ancien": "Bureau", "nouveau": "SCH_BUREAU", "references": []},
        {"sorte": "hote", "ancien": "absent", "nouveau": "HST_X", "references": []},
    ],
    "fusions": [
        {
            "sorte": "hote",
            "contenu": "10.1.1.10/32",
            "conserve": "SIEGE_HST_DMZ_WEB-01",
            "nouveau_nom": "SIEGE_HST_DMZ_WEB-01",
            "supprimes": ["Web_DMZ"],
            "references_reecrites": [],
        }
    ],
    "retraits": [
        {"sorte": "hote", "nom": "srv-oublie", "motif": "aucune reference"},
        {"sorte": "hote", "nom": "SIEGE_HST_DMZ_WEB-01", "motif": "aucune reference"},
    ],
}


def test_script_renommages_fusions_retraits():
    script = generer_script(OBJETS, PLAN)
    assert 'config firewall addrgrp\n    rename "Groupe web" to "SIEGE_GRP_DMZ_WEB"\nend' in script.renommages
    assert 'config firewall schedule recurring\n    rename "Bureau" to "SCH_BUREAU"' in script.renommages
    assert "HTTP" not in script.renommages
    assert "# --- lot 1/1 ---" in script.renommages
    # Le groupe a déjà son nouveau nom, et contient déjà l'objet conservé : unselect seul.
    assert (
        'config firewall addrgrp\n    edit "SIEGE_GRP_DMZ_WEB"\n        unselect member "Web_DMZ"\n'
        in script.fusions
    )
    assert (
        "    edit 7\n"
        '        append dstaddr "SIEGE_HST_DMZ_WEB-01"\n'
        '        unselect dstaddr "Web_DMZ"\n'
    ) in script.fusions
    assert '    edit 3\n        set dstaddr "SIEGE_HST_DMZ_WEB-01"\n' in script.fusions
    assert script.fusions.index("edit 3") < script.fusions.index('delete "Web_DMZ"')
    assert 'delete "srv-oublie"' in script.retraits
    assert 'delete "SIEGE_HST_DMZ_WEB-01"' not in script.retraits
    assert set(script.ignores) == {
        "renommage de HTTP : objet par défaut FortiGate",
        "renommage de absent : absent de l'export",
        "retrait de SIEGE_HST_DMZ_WEB-01 : encore référencé dans l'export",
    }
    assert script.compteurs == {"renommages": 2, "fusions": 1, "retraits": 1}


def test_script_defauts_inclus_et_lots():
    script = generer_script(OBJETS, PLAN, lot=1, inclure_defauts=True)
    assert 'rename "HTTP" to "SVC_TCP_80_HTTP"' in script.renommages
    assert "# --- lot 3/3 ---" in script.renommages


def test_script_refuse_stormshield():
    with pytest.raises(ErreurLecture):
        generer_script(OBJETS, {"constructeur": "stormshield"})


def test_commande_script(racine, tmp_path, capsys):
    source = racine / "examples" / "fortigate" / "nomenclature.conf"
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(PLAN), encoding="utf-8")
    sortie = tmp_path / "fortigate"
    assert executer(["script", str(source), "--plan", str(plan), "--sortie", str(sortie)]) == 0
    assert {chemin.name for chemin in sortie.iterdir()} == {
        "01-renommages.txt",
        "02-fusions.txt",
        "03-retraits.txt",
        "ignores.txt",
    }
    assert "Rien n'a été envoyé au firewall." in capsys.readouterr().out


def test_script_sortie_defaut(capsys):
    with pytest.raises(SystemExit) as sortie:
        executer(["script", "--help"])
    assert sortie.value.code == 0
    texte = capsys.readouterr().out
    assert "out/fortigate" in texte
    assert "out/script" not in texte
