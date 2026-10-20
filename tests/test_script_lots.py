"""Chaque lot doit passer sur l'état laissé par les lots précédents (cas EPFRFORTI01)."""

import json

from fwclean.cli import executer
from fwclean.script import _lire, appliquer, generer_script

CONF = """
config firewall address
    edit "EPES01"
        set subnet 192.168.203.10 255.255.255.255
    next
    edit "EPESS01-bis"
        set subnet 192.168.203.10 255.255.255.255
    next
    edit "Res-VLAN11"
        set subnet 10.0.0.0 255.255.255.0
    next
    edit "SRV-ESX-MSA [vlan11]"
        set subnet 10.0.0.0 255.255.255.0
    next
    edit "Vieux-nom"
        set subnet 10.9.9.9 255.255.255.255
    next
    edit "Copie-vieux"
        set subnet 10.9.9.9 255.255.255.255
    next
    edit "orphelin"
        set subnet 10.7.7.7 255.255.255.255
    next
    edit "sdwan-dst"
        set subnet 10.6.6.6 255.255.255.255
    next
    edit "sdwan-copie"
        set subnet 10.6.6.6 255.255.255.255
    next
    edit "HQ_HST_LAN_PRIS"
        set subnet 10.5.5.5 255.255.255.255
    next
    edit "Pris"
        set subnet 10.5.5.6 255.255.255.255
    next
    edit "Pris-copie"
        set subnet 10.5.5.6 255.255.255.255
    next
end
config firewall addrgrp
    edit "LAN"
        set member "SRV-ESX-MSA [vlan11]" "Res-VLAN11"
    next
end
config vpn ssl settings
    set source-address "SRV-ESX-MSA [vlan11]"
end
config vpn ssl web portal
    edit "PORTAL_NOMADE"
        set split-tunneling-routing-address "SRV-ESX-MSA [vlan11]"
    next
end
config system sdwan
    config service
        edit 1
            set dst "sdwan-copie"
        next
    end
end
config firewall policy
    edit 46
        set srcaddr "SRV-ESX-MSA [vlan11]"
        set dstaddr "Copie-vieux" "Pris-copie"
        set service "ALL"
        set schedule "always"
    next
end
"""

PLAN = {
    "constructeur": "fortigate",
    "renommages": [
        {"sorte": "reseau", "ancien": "Res-VLAN11", "nouveau": "HQ_NET_LAN_VLAN11-RES"},
        {"sorte": "groupe-adresses", "ancien": "LAN", "nouveau": "HQ_GRP_LAN_ND"},
        {"sorte": "hote", "ancien": "EPESS01-bis", "nouveau": "HQ_HST_LAN_EPESS01-BIS"},
        {"sorte": "hote", "ancien": "Vieux-nom", "nouveau": "HQ_HST_LAN_VIEUX"},
        {"sorte": "hote", "ancien": "orphelin", "nouveau": "HQ_HST_LAN_ORPHELIN"},
        {"sorte": "hote", "ancien": "Pris", "nouveau": "HQ_HST_LAN_PRIS"},
    ],
    "fusions": [
        {"sorte": "hote", "contenu": "192.168.203.10/32", "conserve": "EPES01", "supprimes": ["EPESS01-bis"]},
        {"sorte": "reseau", "contenu": "10.0.0.0/24", "conserve": "Res-VLAN11", "supprimes": ["SRV-ESX-MSA [vlan11]"]},
        {"sorte": "hote", "contenu": "10.9.9.9/32", "conserve": "Vieux-nom", "supprimes": ["Copie-vieux"]},
        {"sorte": "hote", "contenu": "10.6.6.6/32", "conserve": "sdwan-dst", "supprimes": ["sdwan-copie"]},
        {"sorte": "hote", "contenu": "10.5.5.6/32", "conserve": "Pris", "supprimes": ["Pris-copie"]},
    ],
    "retraits": [
        {"sorte": "hote", "nom": "EPESS01-bis", "motif": "aucune reference"},
        {"sorte": "hote", "nom": "orphelin", "motif": "aucune reference"},
    ],
}


def _rejouer(*scripts: str) -> list[str]:
    config = _lire(CONF)
    erreurs = []
    for script in scripts:
        erreurs += appliquer(config, script)
    return erreurs


def test_lots_successifs_sans_erreur():
    script = generer_script(CONF, PLAN)
    assert _rejouer(script.renommages, script.fusions, script.retraits) == []


def test_doublon_ni_renomme_ni_supprime_deux_fois():
    script = generer_script(CONF, PLAN)
    assert "EPESS01-bis" not in script.renommages
    assert script.fusions.count('delete "EPESS01-bis"') == 1
    assert "EPESS01-bis" not in script.retraits
    assert "renommage de EPESS01-bis : doublon supprimé à l'étape 02" in script.ignores
    assert "retrait de EPESS01-bis : déjà supprimé à l'étape 02 (doublon de EPES01)" in script.ignores
    assert '# doublon "EPESS01-bis" -> conservé "EPES01" (192.168.203.10/32)' in script.fusions


def test_fusions_et_retraits_avec_les_noms_de_01():
    script = generer_script(CONF, PLAN)
    assert 'edit "HQ_GRP_LAN_ND"' in script.fusions
    assert 'edit "LAN"' not in script.fusions
    assert 'append srcaddr "HQ_NET_LAN_VLAN11-RES"' in script.fusions
    assert 'append dstaddr "HQ_HST_LAN_VIEUX"' in script.fusions
    assert 'delete "HQ_HST_LAN_ORPHELIN"' in script.retraits
    assert 'delete "orphelin"' not in script.retraits


def test_renommage_refuse_ne_detourne_pas_la_fusion():
    script = generer_script(CONF, PLAN)
    assert "renommage de Pris : HQ_HST_LAN_PRIS existe déjà" in script.ignores
    assert 'append dstaddr "Pris"' in script.fusions
    assert 'append dstaddr "HQ_HST_LAN_PRIS"' not in script.fusions


def test_references_vpn_ssl_reportees_avant_le_delete():
    fusions = generer_script(CONF, PLAN).fusions
    supprime = fusions.index('delete "SRV-ESX-MSA [vlan11]"')
    for commande in (
        (
            '    edit "PORTAL_NOMADE"\n'
            '        append split-tunneling-routing-address "HQ_NET_LAN_VLAN11-RES"\n'
            '        unselect split-tunneling-routing-address "SRV-ESX-MSA [vlan11]"\n'
        ),
        (
            'config vpn ssl settings\n    append source-address "HQ_NET_LAN_VLAN11-RES"\n'
            '    unselect source-address "SRV-ESX-MSA [vlan11]"\nend'
        ),
        '    edit "HQ_GRP_LAN_ND"\n        unselect member "SRV-ESX-MSA [vlan11]"\n',
        '        append srcaddr "HQ_NET_LAN_VLAN11-RES"\n        unselect srcaddr "SRV-ESX-MSA [vlan11]"\n',
    ):
        assert commande in fusions
        assert fusions.index(commande) < supprime


def test_objet_cite_ailleurs_pas_supprime():
    script = generer_script(CONF, PLAN)
    assert 'delete "sdwan-copie"' not in script.fusions + script.retraits
    assert any(i.startswith("suppression de sdwan-copie : encore cité dans system sdwan service") for i in script.ignores)


def test_ancien_lot_02_reproduit_le_refus_et_le_rattrapage_le_finit():
    ancien_01 = generer_script(CONF, PLAN).renommages
    # Lot 02 de l'ancienne version : le portail VPN SSL n'était pas réécrit.
    ancien_02 = (
        'config firewall address\n    delete "EPESS01-bis"\nend\n'
        'config firewall addrgrp\n    edit "HQ_GRP_LAN_ND"\n        unselect member "SRV-ESX-MSA [vlan11]"\n    next\nend\n'
        'config firewall policy\n    edit 46\n        append srcaddr "HQ_NET_LAN_VLAN11-RES"\n'
        '        unselect srcaddr "SRV-ESX-MSA [vlan11]"\n    next\nend\n'
        'config firewall address\n    delete "SRV-ESX-MSA [vlan11]"\nend\n'
        'config firewall address\n    delete "EPESS01-bis"\nend\n'
    )
    script = generer_script(CONF, PLAN, deja_appliques=(ancien_01, ancien_02))
    assert len(script.erreurs_deja_appliquees) == 2
    assert "encore utilisé" in script.erreurs_deja_appliquees[0]
    assert "objet introuvable" in script.erreurs_deja_appliquees[1]
    assert "rename" not in script.rattrapage
    assert 'delete "EPESS01-bis"' not in script.rattrapage
    assert 'unselect split-tunneling-routing-address "SRV-ESX-MSA [vlan11]"' in script.rattrapage
    assert 'delete "SRV-ESX-MSA [vlan11]"' in script.rattrapage
    assert "fusion de EPESS01-bis : déjà supprimé par un script déjà appliqué" in script.ignores
    assert _rejouer(ancien_01, ancien_02, script.rattrapage, script.retraits)[2:] == []


def test_commande_script_deja_applique(tmp_path):
    conf, plan, sortie = tmp_path / "fw.conf", tmp_path / "plan.json", tmp_path / "out"
    conf.write_text(CONF, encoding="utf-8")
    plan.write_text(json.dumps(PLAN), encoding="utf-8")
    assert executer(["script", str(conf), "--plan", str(plan), "--sortie", str(sortie)]) == 0
    ancien_01 = sortie / "01-renommages.txt"
    assert (
        executer(["script", str(conf), "--plan", str(plan), "--sortie", str(sortie), "--deja-applique", str(ancien_01)])
        == 0
    )
    assert {chemin.name for chemin in sortie.iterdir()} == {
        "01-renommages.txt",
        "02-fusions.txt",
        "02b-rattrapage.txt",
        "03-retraits.txt",
        "deja-applique.txt",
        "ignores.txt",
    }
    assert (sortie / "02b-rattrapage.txt").read_text(encoding="utf-8").count("delete") == 4
