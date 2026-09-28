from fwclean.contenu import empreinte_service
from fwclean.naming import (
    est_conforme_objet,
    lire_contextes,
    longueur_max,
    proposer_objet,
    proposer_service,
    rendre_unique,
    tronquer,
)

SITES = ("gras", "siege")


def test_contextes_par_defaut(racine):
    assert lire_contextes(racine / "contextes.txt") == (
        "lan",
        "dmz",
        "wan",
        "vpn",
        "mgmt",
        "bastion",
        "users",
        "preprodfr",
        "preprodth",
        "invite",
        "mobile",
        "oob",
        "loop",
    )


def test_ctx_et_multi_ignores_dans_contextes(tmp_path):
    fichier = tmp_path / "contextes.txt"
    fichier.write_text("lan\nctx\nMULTI\n", encoding="utf-8")
    assert lire_contextes(fichier) == ("lan",)


def test_objets_conformes_et_plafond(contextes):
    assert est_conforme_objet("HST_SIEGE_LAN_ZABBIXSRV", "hote", contextes, SITES)
    assert est_conforme_objet("NET_GRAS_LAN_VLAN210", "reseau", contextes, SITES)
    assert est_conforme_objet("GRP_MULTI_LAN_CLIENTS", "groupe-adresses", contextes, SITES)
    assert est_conforme_objet("FQDN_CTX_WAN_UPDATES", "fqdn", contextes, SITES)
    assert est_conforme_objet("HST_SIEGE_MULTI_X", "hote", contextes, SITES)
    assert est_conforme_objet("SVC_TCP_443", "service", contextes, SITES)
    assert est_conforme_objet("SVC_UDP_53", "service", contextes)
    assert not est_conforme_objet("HST-DMZ-WEB-01", "hote", contextes, SITES)
    assert not est_conforme_objet("HST-SIEGE-LAN-ZABBIXSRV", "hote", contextes, SITES)
    assert not est_conforme_objet("HST_SIEGE-LAN_ZABBIXSRV", "hote", contextes, SITES)
    assert not est_conforme_objet("HST_SIEGE_LAN_ZABBIX_SRV", "hote", contextes, SITES)
    assert not est_conforme_objet("HST_SIEGE_LAN__X", "hote", contextes, SITES)
    assert est_conforme_objet("HST_SIEGE_LAN_ZABBIX-SRV-01", "hote", contextes, SITES)
    assert est_conforme_objet("SVC_TCP_2000-2032", "service", contextes)
    assert not est_conforme_objet("SVC-TCP-443", "service", contextes)
    assert not est_conforme_objet("HST_LYON_LAN_WEB", "hote", contextes, SITES)
    assert not est_conforme_objet("HST_SIEGE_USINE_WEB", "hote", contextes, SITES)
    assert not est_conforme_objet("HST-SIEGE-LAN", "hote", contextes, SITES)
    assert not est_conforme_objet("hst-siege-lan-web", "hote", contextes, SITES)
    assert not est_conforme_objet("NET_SIEGE_LAN_WEB", "hote", contextes, SITES)
    assert not est_conforme_objet("SVC-SIEGE-LAN-HTTPS", "service", contextes, SITES)
    assert est_conforme_objet("HST_SIEGE_LAN_X", "hote", contextes, ("SIEGE",))
    nom = "HST_SIEGE_DMZ_" + ("A" * 65)
    assert len(nom) == 79
    assert est_conforme_objet(nom, "hote", contextes, SITES)
    assert not est_conforme_objet(nom + "B", "hote", contextes, SITES)


def test_site_inconnu_sans_referentiel(contextes):
    assert not est_conforme_objet("HST_SIEGE_LAN_ZABBIXSRV", "hote", contextes)
    assert est_conforme_objet("HST_CTX_LAN_ZABBIXSRV", "hote", contextes)


def test_proposition_de_noms(contextes):
    assert proposer_objet("Web_DMZ", "HST", "siege", "dmz", contextes, SITES) == "HST_SIEGE_DMZ_WEB"
    assert proposer_objet("Hôte_DMZ", "HST", "ctx", "dmz", contextes, SITES) == "HST_CTX_DMZ_HOTE"
    assert proposer_objet("srv-oublie", "HST", "ctx", "ctx", contextes, SITES) == "HST_CTX_CTX_SRV-OUBLIE"
    assert proposer_objet("SIEGE_zabbix", "HST", "siege", "lan", contextes, SITES) == "HST_SIEGE_LAN_ZABBIX"
    assert proposer_objet("HST-DMZ-WEB-01", "HST", "siege", "dmz", contextes, SITES) == "HST_SIEGE_DMZ_WEB-01"
    assert proposer_objet("HST_SIEGE_DMZ_WEB-01", "HST", "ctx", "dmz", contextes) == "HST_CTX_DMZ_WEB-01"
    empreinte = empreinte_service([("tcp", ((443, 443, -1, -1),))])
    assert proposer_service(empreinte) == "SVC_TCP_443"


def test_limites_fortigate(contextes):
    assert longueur_max("fortigate", "calendrier") == 31
    assert longueur_max("fortigate", "hote") == 79
    assert longueur_max("stormshield", "calendrier") == 79
    nom = "SCH_CTX_LAN_" + "X" * 20
    assert est_conforme_objet(nom, "calendrier", contextes)
    assert not est_conforme_objet(nom, "calendrier", contextes, (), 31)


def test_troncature_garde_la_structure_et_le_suffixe():
    assert tronquer("SCH_CTX_LAN_HORAIRES-USINE-NUITS", 31) == "SCH_CTX_LAN_HORAIRES-USINE"
    base = "SCH_CTX_LAN_HORAIRES-USINE-ABC"
    assert len(base) == 30
    unique = rendre_unique(base, {base}, 31)
    assert unique == "SCH_CTX_LAN_HORAIRES-USINE-01"
    assert len(unique) <= 35
    assert rendre_unique("SCH_CTX_LAN_" + "X" * 30, set(), 31) == "SCH_CTX_LAN_" + "X" * 19
