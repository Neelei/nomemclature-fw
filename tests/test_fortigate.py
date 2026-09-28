from fwclean.audit import auditer
from fwclean.charger import charger
from fwclean.fortigate import lire_fortigate


def test_exemple_fortigate(racine, contextes, referentiel):
    inventaire = charger([racine / "examples" / "fortigate" / "nomenclature.conf"])
    resultat = auditer(inventaire, contextes, referentiel)

    assert inventaire.constructeur == "fortigate"
    assert len(inventaire.regles) == 7
    assert {item.nom for item in resultat.non_conformes} == {
        "Acces web",
        "Bureau",
        "Clients vers web",
        "Clients web",
        "Vlan210",
        "fenetre-oubliee",
        "Groupe Web",
        "groupe-oublie",
        "updates.example.com",
        "HTTPS custom",
        "SNAT_POOL",
        "LAN Utilisateurs",
        "Web_DMZ",
        "web_dmz_backup",
        "srv-oublie",
    }
    assert [(item.sorte, item.ancien, item.nouveau) for item in resultat.renommages] == [
        ("groupe-adresses", "Clients web", "GRP_MULTI_LAN_CLIENTS-WEB"),
        ("hote", "web_dmz_backup", "HST_EPFR_DMZ_WEB-BACKUP"),
        ("regle", "Acces web", "ALLOW_EPFR_LAN_DMZ_TCP-443"),
        ("regle", "Clients vers web", "ALLOW_MULTI_LAN_DMZ_TCP-443"),
        ("reseau", "Vlan210", "NET_GRAS_LAN_VLAN210"),
    ]
    assert resultat.renommages[1].references == ("Acces web",)
    assert [(item.sorte, item.conserve, item.supprimes, item.references_reecrites) for item in resultat.fusions] == [
        ("calendrier", "SCH_CTX_LAN_BUREAU", ("Bureau",), ("ALLOW_EPFR_LAN_DMZ_DOUBLON",)),
        ("fqdn", "FQDN_CTX_WAN_UPDATES", ("updates.example.com",), ("route 1",)),
        ("groupe-adresses", "GRP_EPFR_DMZ_WEB", ("Groupe Web",), ("ALLOW_EPFR_LAN_DMZ_DOUBLON",)),
        ("hote", "HST_EPFR_DMZ_WEB-01", ("Web_DMZ",), ("ALLOW_EPFR_LAN_DMZ_DOUBLON",)),
        ("pool", "POOL_EPFR_WAN_SORTANT", ("SNAT_POOL",), ("ALLOW_EPFR_LAN_DMZ_DOUBLON",)),
        ("reseau", "NET_EPFR_LAN_UTILISATEURS", ("LAN Utilisateurs",), ("ALLOW_EPFR_LAN_DMZ_DOUBLON",)),
        ("service", "SVC_TCP_443", ("HTTPS custom",), ("ALLOW_EPFR_LAN_DMZ_DOUBLON",)),
    ]
    assert resultat.fusions[3].contenu == "10.1.1.10/32"
    assert resultat.fusions[5].contenu == "10.0.0.0/24"
    assert resultat.fusions[6].contenu == "tcp/443"
    assert all(item.nouveau_nom == item.conserve for item in resultat.fusions)
    assert [(item.sorte, item.nom) for item in resultat.retraits] == [
        ("calendrier", "fenetre-oubliee"),
        ("groupe-adresses", "groupe-oublie"),
        ("hote", "srv-oublie"),
    ]
    assert "HST_EPFR_LAN_LEGACY" not in {item.nom for item in resultat.retraits}
    assert "Web_DMZ" not in {item.ancien for item in resultat.renommages}
    assert "srv-oublie" not in {item.ancien for item in resultat.renommages}


def test_doublon_quelle_que_soit_l_ordre_des_membres(contextes, referentiel):
    texte = """
config firewall addrgrp
    edit "GRP_EPFR_DMZ_WEB"
        set member "hst-a" "hst-b"
    next
    edit "Groupe_inverse"
        set member "hst-b" "hst-a"
    next
end
"""
    resultat = auditer(lire_fortigate(texte, "memoire"), contextes, referentiel)
    assert len(resultat.fusions) == 1
    fusion = resultat.fusions[0]
    assert fusion.conserve == "GRP_EPFR_DMZ_WEB"
    assert fusion.supprimes == ("Groupe_inverse",)
    assert [item.nom for item in resultat.retraits] == ["GRP_EPFR_DMZ_WEB"]
    assert resultat.renommages == ()


def test_masques_equivalents_et_types_ignores(contextes, referentiel):
    texte = """
config firewall address
    edit "HST_EPFR_DMZ_WEB-01"
        set subnet 10.1.1.10/32
    next
    edit "Web_DMZ"
        set subnet 10.1.1.10 255.255.255.255
    next
    edit "France"
        set type geography
        set country FR
    next
end
config firewall schedule onetime
    edit "SCH_CTX_WAN_MAINTENANCE"
        set start 00:00 2026/01/01
        set end 06:00 2026/01/01
    next
end
"""
    inventaire = lire_fortigate(texte, "memoire")
    resultat = auditer(inventaire, contextes, referentiel)
    assert any("France" in ignore for ignore in inventaire.ignores)
    assert "France" not in {item.nom for item in resultat.retraits}
    assert resultat.fusions[0].conserve == "HST_EPFR_DMZ_WEB-01"
    assert resultat.fusions[0].supprimes == ("Web_DMZ",)
    assert "SCH_CTX_WAN_MAINTENANCE" not in {item.nom for item in resultat.non_conformes}
    assert "SCH_CTX_WAN_MAINTENANCE" in {item.nom for item in resultat.retraits}


def test_objets_systeme_et_protocoles_reels(contextes, referentiel):
    """Cas rencontrés sur un export FortiGate 7.4 réel (all sans subnet, ICMP6, ALL)."""
    texte = """
config firewall address
    edit "all"
    next
    edit "FABRIC_DEVICE"
        set comment "IPv4 addresses of Fabric Devices."
    next
    edit "HST_EPFR_DMZ_WEB-01"
        set subnet 10.1.1.10 255.255.255.255
    next
end
config firewall service custom
    edit "PING6"
        set protocol ICMP6
        set icmptype 128
    next
    edit "webproxy"
        set protocol ALL
        set tcp-portrange 0-65535:0-65535
    next
    edit "ALL"
        set protocol IP
    next
end
config firewall policy
    edit 1
        set name "ALLOW_EPFR_WAN_DMZ_HTTPS"
        set srcintf "wan"
        set dstintf "dmz"
        set action accept
        set srcaddr "all"
        set dstaddr "HST_EPFR_DMZ_WEB-01"
        set schedule "always"
        set service "PING6" "webproxy" "ALL"
    next
end
"""
    inventaire = lire_fortigate(texte, "memoire")
    noms = {objet.nom for objet in inventaire.objets}
    assert "all" not in noms
    assert "FABRIC_DEVICE" not in noms
    assert any("all" in ignore for ignore in inventaire.ignores)
    assert any("FABRIC_DEVICE" in ignore for ignore in inventaire.ignores)
    assert "HST_EPFR_DMZ_WEB-01" in noms
    assert "PING6" in noms
    assert "webproxy" in noms
    assert "ALL" in noms
    ping6 = next(objet for objet in inventaire.objets if objet.nom == "PING6")
    assert ping6.detail == "icmp6/128"
    webproxy = next(objet for objet in inventaire.objets if objet.nom == "webproxy")
    assert "tcp/0-65535" in webproxy.detail
    resultat = auditer(inventaire, contextes, referentiel)
    assert "HST_EPFR_DMZ_WEB-01" not in {item.nom for item in resultat.retraits}
