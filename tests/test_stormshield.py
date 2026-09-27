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
        ("hote", "web_dmz_backup", "hst-dmz-web-backup"),
        ("regle", "Acces web", "allow-lan-dmz-tcp-443"),
    ]
    assert [(item.sorte, item.conserve, item.supprimes, item.references_reecrites) for item in resultat.fusions] == [
        ("calendrier", "sch-lan-bureau", ("Bureau",), ("allow-lan-dmz-doublon",)),
        ("groupe-adresses", "grp-dmz-web", ("Groupe_Web",), ("allow-lan-dmz-doublon",)),
        ("hote", "hst-dmz-web-01", ("Web_DMZ",), ("allow-lan-dmz-doublon",)),
        ("reseau", "net-lan-utilisateurs", ("LAN_Utilisateurs",), ("allow-lan-dmz-doublon",)),
        ("service", "svc-tcp-443", ("HTTPS_custom",), ("allow-lan-dmz-doublon",)),
    ]
    assert resultat.fusions[2].contenu == "10.1.1.10/32"
    assert [(item.sorte, item.nom) for item in resultat.retraits] == [
        ("calendrier", "fenetre-oubliee"),
        ("groupe-adresses", "groupe-oublie"),
        ("hote", "srv-oublie"),
    ]
    assert "hst-lan-legacy" not in {item.nom for item in resultat.retraits}
    assert "rng-wan-nat" not in {item.nom for item in resultat.retraits}
    assert "fqdn-wan-updates" not in {item.nom for item in resultat.retraits}
    assert "nat-sortant" not in {regle.nom for regle in inventaire.regles}


def test_plage_de_ports_et_protocole(racine):
    texte = """
service,svc-tcp-haute,tcp,,2000,2032,""
protocol,ospf,89,"OSPF"
"""
    objets, ignores = lire_objets(texte)
    assert ignores == ()
    par_nom = {objet.nom: objet for objet in objets}
    assert par_nom["svc-tcp-haute"].detail == "tcp/2000-2032"
    assert par_nom["ospf"].detail == "ip/89"
    from fwclean.naming import est_conforme_objet, lire_contextes as lire

    contextes = lire(racine / "contextes.txt")
    assert est_conforme_objet("svc-tcp-haute", "service", contextes)
