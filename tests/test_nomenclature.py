from fwclean.contenu import empreinte_service
from fwclean.naming import (
    est_conforme_objet,
    libelle_service,
    lire_contextes,
    longueur_max,
    proposer_objet,
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
    assert est_conforme_objet("FQDN_SIEGE_WAN_UPDATES", "fqdn", contextes, SITES)
    assert est_conforme_objet("HST_SIEGE_MULTI_X", "hote", contextes, SITES)
    assert est_conforme_objet("HST_SIEGE_LAN_ZABBIX-SRV-01", "hote", contextes, SITES)
    assert est_conforme_objet("HST_SIEGE_LAN_X", "hote", contextes, ("SIEGE",))
    assert not est_conforme_objet("HST_CTX_LAN_ZABBIXSRV", "hote", contextes, SITES)
    assert not est_conforme_objet("HST_SIEGE_CTX_ZABBIXSRV", "hote", contextes, SITES)
    assert not est_conforme_objet("HST-DMZ-WEB-01", "hote", contextes, SITES)
    assert not est_conforme_objet("HST-SIEGE-LAN-ZABBIXSRV", "hote", contextes, SITES)
    assert not est_conforme_objet("HST_SIEGE-LAN_ZABBIXSRV", "hote", contextes, SITES)
    assert not est_conforme_objet("HST_SIEGE_LAN_ZABBIX_SRV", "hote", contextes, SITES)
    assert not est_conforme_objet("HST_SIEGE_LAN__X", "hote", contextes, SITES)
    assert not est_conforme_objet("HST_LYON_LAN_WEB", "hote", contextes, SITES)
    assert not est_conforme_objet("HST_SIEGE_USINE_WEB", "hote", contextes, SITES)
    assert not est_conforme_objet("hst_siege_lan_web", "hote", contextes, SITES)
    assert not est_conforme_objet("NET_SIEGE_LAN_WEB", "hote", contextes, SITES)
    nom = "HST_SIEGE_DMZ_" + ("A" * 65)
    assert len(nom) == 79
    assert est_conforme_objet(nom, "hote", contextes, SITES)
    assert not est_conforme_objet(nom + "B", "hote", contextes, SITES)


def test_services_calendriers_sans_site_ni_zone(contextes):
    assert est_conforme_objet("SVC_HTTPS", "service", contextes)
    assert est_conforme_objet("SVC_CITRIX-LICENCING-7279", "service", contextes)
    assert est_conforme_objet("SGRP_ACTIVE-DIRECTORY", "groupe-services", contextes)
    assert est_conforme_objet("SCH_BUREAU", "calendrier", contextes)
    assert not est_conforme_objet("SVC_TCP_443", "service", contextes)
    assert not est_conforme_objet("SGRP_SIEGE_DMZ_WEB", "groupe-services", contextes, SITES)
    assert not est_conforme_objet("SCH_CTX_LAN_BUREAU", "calendrier", contextes)
    assert not est_conforme_objet("SVC-HTTPS", "service", contextes)


def test_reseau_avec_vlan(contextes):
    assert est_conforme_objet("NET_SIEGE_LAN_VLAN11-SRV", "reseau", contextes, SITES, vlan=11)
    assert not est_conforme_objet("NET_SIEGE_LAN_SRV", "reseau", contextes, SITES, vlan=11)
    assert not est_conforme_objet("NET_SIEGE_LAN_VLAN12-SRV", "reseau", contextes, SITES, vlan=11)
    assert est_conforme_objet("NET_SIEGE_LAN_SRV", "reseau", contextes, SITES)
    propose = proposer_objet("SRV-ESX-MSA [vlan11]", "NET", "siege", "lan", contextes, vlan=11)
    assert propose == "NET_SIEGE_LAN_VLAN11-SRV-ESX-MSA"
    assert proposer_objet("MEETING [valn50]", "NET", "siege", "lan", contextes, vlan=50) == (
        "NET_SIEGE_LAN_VLAN50-MEETING"
    )
    assert proposer_objet("EDF [vlan20]", "NET", "siege", "lan", contextes, vlan=52) == (
        "NET_SIEGE_LAN_VLAN52-EDF"
    )
    assert proposer_objet("VLAN-10", "NET", "siege", "lan", contextes, vlan=10) == "NET_SIEGE_LAN_VLAN10"


def test_proposition_de_noms(contextes):
    assert proposer_objet("Web_DMZ", "HST", "siege", "dmz", contextes) == "HST_SIEGE_DMZ_WEB"
    assert proposer_objet("SIEGE_zabbix", "HST", "siege", "lan", contextes) == "HST_SIEGE_LAN_ZABBIX"
    assert proposer_objet("HST-DMZ-WEB-01", "HST", "siege", "dmz", contextes) == "HST_SIEGE_DMZ_WEB-01"
    assert proposer_objet("HST_GRAS_DMZ_WEB-01", "HST", "siege", "dmz", contextes) == (
        "HST_SIEGE_DMZ_WEB-01"
    )
    # Seuls le site et la zone retenus sortent du détail : MGMT reste quand la zone est LAN.
    assert proposer_objet("MGMT [vlan13]", "NET", "siege", "lan", contextes, vlan=13) == (
        "NET_SIEGE_LAN_VLAN13-MGMT"
    )
    assert proposer_objet("Hôte_DMZ", "HST", "siege", "lan", contextes) == "HST_SIEGE_LAN_HOTE-DMZ"


def test_services_gardent_leur_libelle(contextes):
    assert proposer_objet("HTTP-8080", "SVC", None, None, contextes) == "SVC_HTTP-8080"
    assert proposer_objet("MS Global Catalog", "SVC", None, None, contextes) == "SVC_MS-GLOBAL-CATALOG"
    assert proposer_objet("DMZ-web", "SVC", None, None, contextes) == "SVC_DMZ-WEB"
    assert proposer_objet("SVC_TCP_443", "SVC", None, None, contextes) == "SVC_TCP-443"
    assert proposer_objet("SGRP_CTX_DMZ_WEB", "SGRP", None, None, contextes) == "SGRP_WEB"
    assert proposer_objet("Bureau", "SCH", None, None, contextes) == "SCH_BUREAU"
    empreinte = empreinte_service([("tcp", ((443, 443, -1, -1),))])
    assert libelle_service(empreinte) == "tcp-443"
    assert proposer_objet("svc", "SVC", None, None, contextes, libelle_defaut="tcp-443") == "SVC_TCP-443"


def test_limites_fortigate(contextes):
    assert longueur_max("fortigate", "calendrier") == 31
    assert longueur_max("fortigate", "hote") == 79
    assert longueur_max("stormshield", "calendrier") == 79
    nom = "SCH_" + "X" * 28
    assert est_conforme_objet(nom, "calendrier", contextes)
    assert not est_conforme_objet(nom, "calendrier", contextes, (), 31)


def test_troncature_garde_la_structure_et_le_suffixe():
    assert tronquer("HST_SIEGE_LAN_HORAIRES-USINE-NUITS", 31) == "HST_SIEGE_LAN_HORAIRES-USINE"
    base = "HST_SIEGE_LAN_HORAIRES-USINE-AB"
    assert len(base) == 31
    unique = rendre_unique(base, {base}, 31)
    assert unique == "HST_SIEGE_LAN_HORAIRES-USINE-01"
    assert len(unique) <= 31
    assert rendre_unique("SCH_" + "X" * 30, set(), 31) == "SCH_" + "X" * 27
