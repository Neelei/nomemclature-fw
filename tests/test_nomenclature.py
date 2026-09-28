from fwclean.contenu import empreinte_service
from fwclean.naming import (
    est_conforme_objet,
    est_conforme_regle,
    jeton_service,
    lire_contextes,
    longueur_max,
    proposer_objet,
    proposer_regle,
    proposer_service,
    rendre_unique,
    tronquer,
)

SITES = ("epfr", "gras")


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
    assert est_conforme_objet("HST_EPFR_LAN_ZABBIXSRV", "hote", contextes, SITES)
    assert est_conforme_objet("NET_GRAS_LAN_VLAN210", "reseau", contextes, SITES)
    assert est_conforme_objet("GRP_MULTI_LAN_CLIENTS", "groupe-adresses", contextes, SITES)
    assert est_conforme_objet("FQDN_CTX_WAN_UPDATES", "fqdn", contextes, SITES)
    assert est_conforme_objet("HST_EPFR_MULTI_X", "hote", contextes, SITES)
    assert est_conforme_objet("SVC_TCP_443", "service", contextes, SITES)
    assert est_conforme_objet("SVC_UDP_53", "service", contextes)
    assert not est_conforme_objet("HST-DMZ-WEB-01", "hote", contextes, SITES)
    assert not est_conforme_objet("HST-EPFR-LAN-ZABBIXSRV", "hote", contextes, SITES)
    assert not est_conforme_objet("HST_EPFR-LAN_ZABBIXSRV", "hote", contextes, SITES)
    assert not est_conforme_objet("HST_EPFR_LAN_ZABBIX_SRV", "hote", contextes, SITES)
    assert not est_conforme_objet("HST_EPFR_LAN__X", "hote", contextes, SITES)
    assert est_conforme_objet("HST_EPFR_LAN_ZABBIX-SRV-01", "hote", contextes, SITES)
    assert est_conforme_objet("SVC_TCP_2000-2032", "service", contextes)
    assert not est_conforme_objet("SVC-TCP-443", "service", contextes)
    assert not est_conforme_objet("HST_LYON_LAN_WEB", "hote", contextes, SITES)
    assert not est_conforme_objet("HST_EPFR_USINE_WEB", "hote", contextes, SITES)
    assert not est_conforme_objet("HST-EPFR-LAN", "hote", contextes, SITES)
    assert not est_conforme_objet("hst-epfr-lan-web", "hote", contextes, SITES)
    assert not est_conforme_objet("NET_EPFR_LAN_WEB", "hote", contextes, SITES)
    assert not est_conforme_objet("SVC-EPFR-LAN-HTTPS", "service", contextes, SITES)
    assert est_conforme_objet("HST_EPFR_LAN_X", "hote", contextes, ("EPFR",))
    nom = "HST_EPFR_DMZ_" + ("A" * 66)
    assert len(nom) == 79
    assert est_conforme_objet(nom, "hote", contextes, SITES)
    assert not est_conforme_objet(nom + "B", "hote", contextes, SITES)


def test_site_inconnu_sans_referentiel(contextes):
    assert not est_conforme_objet("HST_EPFR_LAN_ZABBIXSRV", "hote", contextes)
    assert est_conforme_objet("HST_CTX_LAN_ZABBIXSRV", "hote", contextes)


def test_regles_suffixe_et_port(contextes):
    assert est_conforme_regle("ALLOW_EPFR_LAN_DMZ_HTTPS", "allow", contextes, SITES)
    assert est_conforme_regle("ALLOW_EPFR_LAN_DMZ_HTTPS-01", "allow", contextes, SITES)
    assert est_conforme_regle("ALLOW_EPFR_LAN_DMZ_TCP-80", "allow", contextes, SITES)
    assert est_conforme_regle("DENY_MULTI_WAN_LAN_ANY", "deny", contextes, SITES)
    assert not est_conforme_regle("ALLOW_EPFR_LAN_DMZ_01", "allow", contextes, SITES)
    assert not est_conforme_regle("ALLOW-LAN-DMZ-HTTPS", "allow", contextes, SITES)
    assert not est_conforme_regle("ALLOW-EPFR-LAN-DMZ-HTTPS", "allow", contextes, SITES)
    assert not est_conforme_regle("ALLOW_EPFR_LAN_DMZ_TCP_443", "allow", contextes, SITES)
    assert not est_conforme_regle("ALLOW_LYON_LAN_DMZ_HTTPS", "allow", contextes, SITES)
    assert not est_conforme_regle("DENY_EPFR_LAN_DMZ_HTTPS", "allow", contextes, SITES)
    assert not est_conforme_regle("allow-epfr-lan-dmz-https", "allow", contextes, SITES)
    assert not est_conforme_regle("Acces web", "allow", contextes, SITES)


def test_proposition_de_noms(contextes):
    assert proposer_objet("Web_DMZ", "HST", "epfr", "dmz", contextes, SITES) == "HST_EPFR_DMZ_WEB"
    assert proposer_objet("Hôte_DMZ", "HST", "ctx", "dmz", contextes, SITES) == "HST_CTX_DMZ_HOTE"
    assert proposer_objet("srv-oublie", "HST", "ctx", "ctx", contextes, SITES) == "HST_CTX_CTX_SRV-OUBLIE"
    assert proposer_objet("EPFR_zabbix", "HST", "epfr", "lan", contextes, SITES) == "HST_EPFR_LAN_ZABBIX"
    assert proposer_objet("HST-DMZ-WEB-01", "HST", "epfr", "dmz", contextes, SITES) == "HST_EPFR_DMZ_WEB-01"
    assert proposer_objet("HST_EPFR_DMZ_WEB-01", "HST", "ctx", "dmz", contextes) == "HST_CTX_DMZ_WEB-01"
    empreinte = empreinte_service([("tcp", ((443, 443, -1, -1),))])
    assert proposer_service(empreinte) == "SVC_TCP_443"
    assert proposer_regle("allow", "epfr", "lan", "dmz", ("SVC_TCP_443",)) == "ALLOW_EPFR_LAN_DMZ_TCP-443"
    assert jeton_service(("SGRP_CTX_DMZ_WEB",)) == "web"
    assert jeton_service(("SGRP-DMZ-WEB",)) == "dmz-web"
    assert jeton_service(("SVC_TCP_443", "SVC_UDP_53")) == "multi"


def test_limite_fortigate_des_regles_et_calendriers(contextes):
    assert longueur_max("fortigate", "regle") == 35
    assert longueur_max("fortigate", "calendrier") == 31
    assert longueur_max("fortigate", "hote") == 79
    assert longueur_max("stormshield", "regle") == 79
    long = "ALLOW_EPFR_PREPRODFR_PREPRODTH_HFSQL"
    assert len(long) == 36
    assert est_conforme_regle(long, "allow", contextes, SITES)
    assert not est_conforme_regle(long, "allow", contextes, SITES, 35)
    nom = proposer_regle("allow", "epfr", "preprodfr", "preprodth", ("PCSOFT-HFSQL",), 35)
    assert nom == "ALLOW_EPFR_PREPRODFR_PREPRODTH_PCSO"
    assert len(nom) <= 35 and est_conforme_regle(nom, "allow", contextes, SITES, 35)
    court = proposer_regle("allow", "epfr", "lan", "dmz", ("SVC_TCP_443", "X"), 35)
    assert court == "ALLOW_EPFR_LAN_DMZ_MULTI"


def test_troncature_garde_la_structure_et_le_suffixe():
    assert tronquer("ALLOW_EPFR_LAN_DMZ_PCSOFT-HFSQL-LONG", 35) == "ALLOW_EPFR_LAN_DMZ_PCSOFT-HFSQL"
    base = "ALLOW_EPFR_LAN_DMZ_PCSOFT-HFSQL-XYZ"
    assert len(base) == 35
    unique = rendre_unique(base, {base}, 35)
    assert unique == "ALLOW_EPFR_LAN_DMZ_PCSOFT-HFSQL-01"
    assert len(unique) <= 35
    assert rendre_unique("SCH_CTX_LAN_" + "X" * 30, set(), 31) == "SCH_CTX_LAN_" + "X" * 19
