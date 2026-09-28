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
        ("groupe-adresses", "Clients web", "GRP-MULTI-LAN-CLIENTS-WEB"),
        ("hote", "web_dmz_backup", "HST-EPFR-DMZ-WEB-BACKUP"),
        ("regle", "Acces web", "ALLOW-EPFR-LAN-DMZ-TCP-443"),
        ("regle", "Clients vers web", "ALLOW-MULTI-LAN-DMZ-TCP-443"),
        ("reseau", "Vlan210", "NET-GRAS-LAN-VLAN210"),
    ]
    assert resultat.renommages[1].references == ("Acces web",)
    assert [(item.sorte, item.conserve, item.supprimes, item.references_reecrites) for item in resultat.fusions] == [
        ("calendrier", "SCH-CTX-LAN-BUREAU", ("Bureau",), ("ALLOW-EPFR-LAN-DMZ-DOUBLON",)),
        ("fqdn", "FQDN-CTX-WAN-UPDATES", ("updates.example.com",), ("route 1",)),
        ("groupe-adresses", "GRP-EPFR-DMZ-WEB", ("Groupe Web",), ("ALLOW-EPFR-LAN-DMZ-DOUBLON",)),
        ("hote", "HST-EPFR-DMZ-WEB-01", ("Web_DMZ",), ("ALLOW-EPFR-LAN-DMZ-DOUBLON",)),
        ("pool", "POOL-EPFR-WAN-SORTANT", ("SNAT_POOL",), ("ALLOW-EPFR-LAN-DMZ-DOUBLON",)),
        ("reseau", "NET-EPFR-LAN-UTILISATEURS", ("LAN Utilisateurs",), ("ALLOW-EPFR-LAN-DMZ-DOUBLON",)),
        ("service", "SVC-TCP-443", ("HTTPS custom",), ("ALLOW-EPFR-LAN-DMZ-DOUBLON",)),
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
    assert "HST-EPFR-LAN-LEGACY" not in {item.nom for item in resultat.retraits}
    assert "Web_DMZ" not in {item.ancien for item in resultat.renommages}
    assert "srv-oublie" not in {item.ancien for item in resultat.renommages}


def test_doublon_quelle_que_soit_l_ordre_des_membres(contextes, referentiel):
    texte = """
config firewall addrgrp
    edit "GRP-EPFR-DMZ-WEB"
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
    assert fusion.conserve == "GRP-EPFR-DMZ-WEB"
    assert fusion.supprimes == ("Groupe_inverse",)
    assert [item.nom for item in resultat.retraits] == ["GRP-EPFR-DMZ-WEB"]
    assert resultat.renommages == ()


def test_masques_equivalents_et_types_ignores(contextes, referentiel):
    texte = """
config firewall address
    edit "HST-EPFR-DMZ-WEB-01"
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
    edit "SCH-CTX-WAN-MAINTENANCE"
        set start 00:00 2026/01/01
        set end 06:00 2026/01/01
    next
end
"""
    inventaire = lire_fortigate(texte, "memoire")
    resultat = auditer(inventaire, contextes, referentiel)
    assert any("France" in ignore for ignore in inventaire.ignores)
    assert "France" not in {item.nom for item in resultat.retraits}
    assert resultat.fusions[0].conserve == "HST-EPFR-DMZ-WEB-01"
    assert resultat.fusions[0].supprimes == ("Web_DMZ",)
    assert "SCH-CTX-WAN-MAINTENANCE" not in {item.nom for item in resultat.non_conformes}
    assert "SCH-CTX-WAN-MAINTENANCE" in {item.nom for item in resultat.retraits}


def test_objets_systeme_et_protocoles_reels(contextes, referentiel):
    """Cas rencontrés sur un export FortiGate 7.4 réel (all sans subnet, ICMP6, ALL)."""
    texte = """
config firewall address
    edit "all"
    next
    edit "FABRIC_DEVICE"
        set comment "IPv4 addresses of Fabric Devices."
    next
    edit "HST-EPFR-DMZ-WEB-01"
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
        set name "ALLOW-EPFR-WAN-DMZ-HTTPS"
        set srcintf "wan"
        set dstintf "dmz"
        set action accept
        set srcaddr "all"
        set dstaddr "HST-EPFR-DMZ-WEB-01"
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
    assert "HST-EPFR-DMZ-WEB-01" in noms
    assert "PING6" in noms
    assert "webproxy" in noms
    assert "ALL" in noms
    ping6 = next(objet for objet in inventaire.objets if objet.nom == "PING6")
    assert ping6.detail == "icmp6/128"
    webproxy = next(objet for objet in inventaire.objets if objet.nom == "webproxy")
    assert "tcp/0-65535" in webproxy.detail
    resultat = auditer(inventaire, contextes, referentiel)
    assert "HST-EPFR-DMZ-WEB-01" not in {item.nom for item in resultat.retraits}
