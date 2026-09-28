from fwclean.audit import auditer
from fwclean.charger import charger
from fwclean.naming import lire_contextes
from fwclean.stormshield import lire_objets


def test_exemple_stormshield(racine):
    contextes = lire_contextes(racine / "contextes.txt")
    inventaire = charger([racine / "examples" / "stormshield"])
    resultat = auditer(inventaire, contextes)

    assert inventaire.constructeur == "stormshield"
    assert len(inventaire.regles) == 6
    assert {item.nom for item in resultat.non_conformes} == {
        "Acces web",
        "Bureau",
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
        ("hote", "web_dmz_backup", "HST-DMZ-WEB-BACKUP"),
        ("regle", "Acces web", "ALLOW-LAN-DMZ-TCP-443"),
    ]
    assert [(item.sorte, item.conserve, item.supprimes, item.references_reecrites) for item in resultat.fusions] == [
        ("calendrier", "SCH-LAN-BUREAU", ("Bureau",), ("ALLOW-LAN-DMZ-DOUBLON",)),
        ("groupe-adresses", "GRP-DMZ-WEB", ("Groupe_Web",), ("ALLOW-LAN-DMZ-DOUBLON",)),
        ("hote", "HST-DMZ-WEB-01", ("Web_DMZ",), ("ALLOW-LAN-DMZ-DOUBLON",)),
        ("reseau", "NET-LAN-UTILISATEURS", ("LAN_Utilisateurs",), ("ALLOW-LAN-DMZ-DOUBLON",)),
        ("service", "SVC-TCP-443", ("HTTPS_custom",), ("ALLOW-LAN-DMZ-DOUBLON",)),
    ]
    assert resultat.fusions[2].contenu == "10.1.1.10/32"
    assert [(item.sorte, item.nom) for item in resultat.retraits] == [
        ("calendrier", "fenetre-oubliee"),
        ("groupe-adresses", "groupe-oublie"),
        ("hote", "srv-oublie"),
    ]
    assert "HST-LAN-LEGACY" not in {item.nom for item in resultat.retraits}
    assert "RNG-WAN-NAT" not in {item.nom for item in resultat.retraits}
    assert "FQDN-WAN-UPDATES" not in {item.nom for item in resultat.retraits}
    assert "nat-sortant" not in {regle.nom for regle in inventaire.regles}


def test_plage_de_ports_et_protocole(racine):
    texte = """
service,SVC-TCP-HAUTE,tcp,,2000,2032,""
protocol,ospf,89,"OSPF"
"""
    objets, ignores = lire_objets(texte)
    assert ignores == ()
    par_nom = {objet.nom: objet for objet in objets}
    assert par_nom["SVC-TCP-HAUTE"].detail == "tcp/2000-2032"
    assert par_nom["ospf"].detail == "ip/89"
    from fwclean.naming import est_conforme_objet, lire_contextes as lire

    contextes = lire(racine / "contextes.txt")
    assert est_conforme_objet("SVC-TCP-HAUTE", "service", contextes)
