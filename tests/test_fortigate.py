from fwclean.audit import auditer
from fwclean.charger import charger
from fwclean.fortigate import lire_fortigate


def test_exemple_fortigate(racine, contextes, referentiel):
    inventaire = charger([racine / "examples" / "fortigate" / "nomenclature.conf"])
    resultat = auditer(inventaire, contextes, referentiel)

    assert inventaire.constructeur == "fortigate"
    assert len(inventaire.regles) == 7
    assert {item.nom for item in resultat.non_conformes} == {
        "Bureau",
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
        "partenaire",
        "Appli metier 8443",
    }
    assert [(item.sorte, item.ancien, item.nouveau) for item in resultat.renommages] == [
        ("groupe-adresses", "Clients web", "GRP_MULTI_LAN_CLIENTS-WEB"),
        ("hote", "web_dmz_backup", "HST_SIEGE_DMZ_WEB-BACKUP"),
        ("reseau", "Vlan210", "NET_GRAS_LAN_VLAN210"),
        ("service", "Appli metier 8443", "SVC_TCP_8443_APPLI-METIER"),
    ]
    assert resultat.renommages[1].references == ("Acces web",)
    assert [(item.sorte, item.conserve, item.supprimes, item.references_reecrites) for item in resultat.fusions] == [
        ("calendrier", "SCH_BUREAU", ("Bureau",), ("ALLOW_SIEGE_LAN_DMZ_DOUBLON",)),
        ("fqdn", "FQDN_SIEGE_WAN_UPDATES", ("updates.example.com",), ("route 1",)),
        ("groupe-adresses", "GRP_SIEGE_DMZ_WEB", ("Groupe Web",), ("ALLOW_SIEGE_LAN_DMZ_DOUBLON",)),
        ("hote", "HST_SIEGE_DMZ_WEB-01", ("Web_DMZ",), ("ALLOW_SIEGE_LAN_DMZ_DOUBLON",)),
        ("pool", "POOL_SIEGE_WAN_SORTANT", ("SNAT_POOL",), ("ALLOW_SIEGE_LAN_DMZ_DOUBLON",)),
        ("reseau", "NET_SIEGE_LAN_VLAN10-UTILISATEURS", ("LAN Utilisateurs",), ("ALLOW_SIEGE_LAN_DMZ_DOUBLON",)),
        ("service", "SVC_TCP_443_HTTPS", ("HTTPS custom",), ("ALLOW_SIEGE_LAN_DMZ_DOUBLON",)),
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
    assert "HST_SIEGE_LAN_LEGACY" not in {item.nom for item in resultat.retraits}
    assert "Web_DMZ" not in {item.ancien for item in resultat.renommages}
    assert "srv-oublie" not in {item.ancien for item in resultat.renommages}


def test_doublon_quelle_que_soit_l_ordre_des_membres(contextes, referentiel):
    texte = """
config firewall addrgrp
    edit "GRP_SIEGE_DMZ_WEB"
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
    assert fusion.conserve == "GRP_SIEGE_DMZ_WEB"
    assert fusion.supprimes == ("Groupe_inverse",)
    assert [item.nom for item in resultat.retraits] == ["GRP_SIEGE_DMZ_WEB"]
    assert resultat.renommages == ()


def test_masques_equivalents_et_types_ignores(contextes, referentiel):
    texte = """
config firewall address
    edit "HST_SIEGE_DMZ_WEB-01"
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
    edit "SCH_MAINTENANCE"
        set start 00:00 2026/01/01
        set end 06:00 2026/01/01
    next
end
"""
    inventaire = lire_fortigate(texte, "memoire")
    resultat = auditer(inventaire, contextes, referentiel)
    assert any("France" in ignore for ignore in inventaire.ignores)
    assert "France" not in {item.nom for item in resultat.retraits}
    assert resultat.fusions[0].conserve == "HST_SIEGE_DMZ_WEB-01"
    assert resultat.fusions[0].supprimes == ("Web_DMZ",)
    assert "SCH_MAINTENANCE" not in {item.nom for item in resultat.non_conformes}
    assert "SCH_MAINTENANCE" in {item.nom for item in resultat.retraits}


def test_objets_systeme_et_protocoles_reels(contextes, referentiel):
    """Cas rencontrés sur un export FortiGate 7.4 réel (all sans subnet, ICMP6, ALL)."""
    texte = """
config firewall address
    edit "all"
    next
    edit "FABRIC_DEVICE"
        set comment "IPv4 addresses of Fabric Devices."
    next
    edit "HST_SIEGE_DMZ_WEB-01"
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
        set name "ALLOW_SIEGE_WAN_DMZ_HTTPS"
        set srcintf "wan"
        set dstintf "dmz"
        set action accept
        set srcaddr "all"
        set dstaddr "HST_SIEGE_DMZ_WEB-01"
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
    assert "HST_SIEGE_DMZ_WEB-01" in noms
    assert "PING6" in noms
    assert "webproxy" in noms
    assert "ALL" in noms
    ping6 = next(objet for objet in inventaire.objets if objet.nom == "PING6")
    assert ping6.detail == "icmp6/128"
    webproxy = next(objet for objet in inventaire.objets if objet.nom == "webproxy")
    assert "tcp/0-65535" in webproxy.detail
    resultat = auditer(inventaire, contextes, referentiel)
    assert "HST_SIEGE_DMZ_WEB-01" not in {item.nom for item in resultat.retraits}


def test_vlan_des_reseaux(contextes, referentiel):
    texte = """
config system interface
    edit "VLAN-11"
        set ip 10.1.2.254 255.255.255.0
        set interface "LACP-LAN"
        set vlanid 11
        config ipv6
            set ip6-address ::/0
        end
    next
    edit "IDRAC"
        set vlanid 131
        set interface "LACP-LAN"
    next
    edit "port1"
        set ip 10.1.1.254 255.255.255.0
    next
end
config firewall address
    edit "SRV-ESX [vlan11]"
        set subnet 10.1.2.0 255.255.255.0
    next
    edit "sous-reseau-esx"
        set subnet 10.1.2.128 255.255.255.128
    next
    edit "IDRAC address"
        set type interface-subnet
        set subnet 10.118.131.0 255.255.255.0
        set interface "IDRAC"
    next
    edit "dmz-sans-vlan"
        set subnet 10.1.1.0 255.255.255.0
    next
end
config firewall addrgrp
    edit "tous"
        set member "SRV-ESX [vlan11]" "sous-reseau-esx" "IDRAC address" "dmz-sans-vlan"
    next
end
"""
    inventaire = lire_fortigate(texte, "memoire")
    vlans = {objet.nom: objet.vlan for objet in inventaire.objets if objet.sorte == "reseau"}
    assert vlans == {
        "SRV-ESX [vlan11]": 11,
        "sous-reseau-esx": 11,
        "IDRAC address": 131,
        "dmz-sans-vlan": None,
    }
    resultat = auditer(inventaire, contextes, referentiel)
    noms = {item.ancien: item.nouveau for item in resultat.renommages}
    assert noms["SRV-ESX [vlan11]"] == "NET_SIEGE_LAN_VLAN11-SRV-ESX"
    assert noms["dmz-sans-vlan"] == "NET_SIEGE_DMZ_SANS-VLAN"
    assert "IDRAC address" not in noms
