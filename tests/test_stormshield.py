from fwclean.audit import auditer
from fwclean.charger import charger
from fwclean.naming import est_conforme_objet
from fwclean.sites import Localisateur, Localisation
from fwclean.stormshield import assembler, lire_objets


def test_exemple_stormshield(racine, contextes, referentiel):
    inventaire = charger([racine / "examples" / "stormshield"])
    resultat = auditer(inventaire, contextes, referentiel)

    assert inventaire.constructeur == "stormshield"
    assert len(inventaire.regles) == 7
    assert {item.nom for item in resultat.non_conformes} == {
        "Acces web",
        "Bureau",
        "Clients vers web",
        "Clients_web",
        "Vlan210",
        "fenetre-oubliee",
        "Groupe_Web",
        "groupe-oublie",
        "HTTPS_custom",
        "LAN_Utilisateurs",
        "Web_DMZ",
        "web_dmz_backup",
        "srv-oublie",
    }
    assert [(item.sorte, item.ancien, item.nouveau) for item in resultat.renommages] == [
        ("groupe-adresses", "Clients_web", "GRP-MULTI-LAN-CLIENTS-WEB"),
        ("hote", "web_dmz_backup", "HST-EPFR-DMZ-WEB-BACKUP"),
        ("regle", "Acces web", "ALLOW-EPFR-LAN-DMZ-TCP-443"),
        ("regle", "Clients vers web", "ALLOW-MULTI-LAN-DMZ-TCP-443"),
        ("reseau", "Vlan210", "NET-GRAS-LAN-VLAN210"),
    ]
    assert [(item.sorte, item.conserve, item.supprimes, item.references_reecrites) for item in resultat.fusions] == [
        ("calendrier", "SCH-CTX-LAN-BUREAU", ("Bureau",), ("ALLOW-EPFR-LAN-DMZ-DOUBLON",)),
        ("groupe-adresses", "GRP-EPFR-DMZ-WEB", ("Groupe_Web",), ("ALLOW-EPFR-LAN-DMZ-DOUBLON",)),
        ("hote", "HST-EPFR-DMZ-WEB-01", ("Web_DMZ",), ("ALLOW-EPFR-LAN-DMZ-DOUBLON",)),
        ("reseau", "NET-EPFR-LAN-UTILISATEURS", ("LAN_Utilisateurs",), ("ALLOW-EPFR-LAN-DMZ-DOUBLON",)),
        ("service", "SVC-TCP-443", ("HTTPS_custom",), ("ALLOW-EPFR-LAN-DMZ-DOUBLON",)),
    ]
    assert resultat.fusions[2].contenu == "10.1.1.10/32"
    assert [(item.sorte, item.nom) for item in resultat.retraits] == [
        ("calendrier", "fenetre-oubliee"),
        ("groupe-adresses", "groupe-oublie"),
        ("hote", "srv-oublie"),
    ]
    assert "HST-EPFR-LAN-LEGACY" not in {item.nom for item in resultat.retraits}
    assert "RNG-EPFR-WAN-NAT" not in {item.nom for item in resultat.retraits}
    assert "FQDN-CTX-WAN-UPDATES" not in {item.nom for item in resultat.retraits}
    assert "nat-sortant" not in {regle.nom for regle in inventaire.regles}


def test_plage_de_ports_et_protocole(contextes):
    texte = """
service,SVC-TCP-HAUTE,tcp,,2000,2032,""
protocol,ospf,89,"OSPF"
"""
    objets, ignores = lire_objets(texte)
    assert ignores == ()
    par_nom = {objet.nom: objet for objet in objets}
    assert par_nom["SVC-TCP-HAUTE"].detail == "tcp/2000-2032"
    assert par_nom["ospf"].detail == "ip/89"
    assert est_conforme_objet("SVC-TCP-HAUTE", "service", contextes)


def test_hote_double_pile(contextes, referentiel):
    texte = """
host,srv_double,10.1.1.30,2001:db8::30,,,""
host,srv_v6,,2001:db8::31,,,""
"""
    objets, _ignores = lire_objets(texte)
    inventaire = assembler(("memoire",), objets, (), (), ())
    loc = Localisateur(inventaire, contextes, referentiel)
    assert loc.objet(objets[0]) == Localisation("epfr", "dmz")
    assert loc.objet(objets[1]) == Localisation("ctx", "ctx")
