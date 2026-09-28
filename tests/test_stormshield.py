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
        "Bureau",
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
        ("groupe-adresses", "Clients_web", "GRP_MULTI_LAN_CLIENTS-WEB"),
        ("hote", "web_dmz_backup", "HST_SIEGE_DMZ_WEB-BACKUP"),
        ("reseau", "Vlan210", "NET_GRAS_LAN_VLAN210"),
    ]
    assert [(item.sorte, item.conserve, item.supprimes, item.references_reecrites) for item in resultat.fusions] == [
        ("calendrier", "SCH_CTX_LAN_BUREAU", ("Bureau",), ("ALLOW_SIEGE_LAN_DMZ_DOUBLON",)),
        ("groupe-adresses", "GRP_SIEGE_DMZ_WEB", ("Groupe_Web",), ("ALLOW_SIEGE_LAN_DMZ_DOUBLON",)),
        ("hote", "HST_SIEGE_DMZ_WEB-01", ("Web_DMZ",), ("ALLOW_SIEGE_LAN_DMZ_DOUBLON",)),
        ("reseau", "NET_SIEGE_LAN_UTILISATEURS", ("LAN_Utilisateurs",), ("ALLOW_SIEGE_LAN_DMZ_DOUBLON",)),
        ("service", "SVC_TCP_443", ("HTTPS_custom",), ("ALLOW_SIEGE_LAN_DMZ_DOUBLON",)),
    ]
    assert resultat.fusions[2].contenu == "10.1.1.10/32"
    assert [(item.sorte, item.nom) for item in resultat.retraits] == [
        ("calendrier", "fenetre-oubliee"),
        ("groupe-adresses", "groupe-oublie"),
        ("hote", "srv-oublie"),
    ]
    assert "HST_SIEGE_LAN_LEGACY" not in {item.nom for item in resultat.retraits}
    assert "RNG_SIEGE_WAN_NAT" not in {item.nom for item in resultat.retraits}
    assert "FQDN_CTX_WAN_UPDATES" not in {item.nom for item in resultat.retraits}
    assert "nat-sortant" not in {regle.nom for regle in inventaire.regles}


def test_plage_de_ports_et_protocole(contextes):
    texte = """
service,SVC_TCP_HAUTE,tcp,,2000,2032,""
protocol,ospf,89,"OSPF"
"""
    objets, ignores = lire_objets(texte)
    assert ignores == ()
    par_nom = {objet.nom: objet for objet in objets}
    assert par_nom["SVC_TCP_HAUTE"].detail == "tcp/2000-2032"
    assert par_nom["ospf"].detail == "ip/89"
    assert est_conforme_objet("SVC_TCP_HAUTE", "service", contextes)


def test_hote_double_pile(contextes, referentiel):
    texte = """
host,srv_double,10.1.1.30,2001:db8::30,,,""
host,srv_v6,,2001:db8::31,,,""
"""
    objets, _ignores = lire_objets(texte)
    inventaire = assembler(("memoire",), objets, (), (), ())
    loc = Localisateur(inventaire, contextes, referentiel)
    assert loc.objet(objets[0]) == Localisation("siege", "dmz")
    assert loc.objet(objets[1]) == Localisation("ctx", "ctx")
