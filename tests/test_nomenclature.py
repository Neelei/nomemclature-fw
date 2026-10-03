from fwclean.contenu import empreinte_service
from fwclean.naming import (
    Localisation,
    est_conforme_objet,
    lire_contextes,
    longueur_max,
    normaliser_interface,
    proposer_objet,
    proposer_service,
    rendre_unique,
    signature_service,
    tronquer,
)

SITES = ("gras", "siege")
INTERFACES = ("dmz", "serveurs", "labo-ana", "wan", "lan-users")


def test_contextes_par_defaut(racine):
    assert lire_contextes(racine / "contextes.txt") == (
        "lan",
        "dmz",
        "wan",
        "mgmt",
        "bastion",
        "users",
        "preprodfr",
        "preprodth",
        "invite",
        "mobile",
    )


def test_ctx_et_multi_ignores_dans_contextes(tmp_path):
    fichier = tmp_path / "contextes.txt"
    fichier.write_text("lan\nctx\nMULTI\n", encoding="utf-8")
    assert lire_contextes(fichier) == ("lan",)


def test_objets_conformes_et_plafond(contextes):
    def conforme(nom, sorte="hote", sites=SITES, attendu=None):
        return est_conforme_objet(nom, sorte, contextes, sites, interfaces=INTERFACES, attendu=attendu)

    assert conforme("SIEGE_HST_SERVEURS_ZABBIXSRV")
    assert conforme("SIEGE_HST_LABO-ANA_PC01")
    assert conforme("MULTI_GRP_MULTI_CLIENTS", "groupe-adresses")
    assert conforme("SIEGE_FQDN_WAN_UPDATES", "fqdn")
    assert conforme("SIEGE_HST_MULTI_X")
    assert conforme("SIEGE_HST_DMZ_ZABBIX-SRV-01")
    assert conforme("SIEGE_HST_DMZ_X", sites=("SIEGE",))
    assert not conforme("CTX_HST_DMZ_ZABBIXSRV")
    assert not conforme("SIEGE_HST_CTX_ZABBIXSRV")
    assert not conforme("SIEGE_HST_LAN_ZABBIXSRV")
    assert not conforme("HST-DMZ-WEB-01")
    assert not conforme("HST-SIEGE-DMZ-ZABBIXSRV")
    assert not conforme("SIEGE_HST_DMZ_ZABBIX_SRV")
    assert not conforme("SIEGE_HST_DMZ__X")
    assert not conforme("LYON_HST_DMZ_WEB")
    assert not conforme("hst_siege_dmz_web")
    assert not conforme("SIEGE_NET_DMZ_WEB")
    assert not conforme("HST_SIEGE_DMZ_WEB")
    assert not conforme("SIEGE_HST_DMZ_A.B")
    nom = "SIEGE_HST_DMZ_" + ("A" * 65)
    assert len(nom) == 79
    assert conforme(nom)
    assert not conforme(nom + "B")


def test_conformite_contre_l_interface_attendue(contextes):
    def conforme(nom, attendu, sorte="hote"):
        sites = (*SITES, "hq")
        return est_conforme_objet(nom, sorte, contextes, sites, interfaces=INTERFACES, attendu=attendu)

    dmz = Localisation("siege", "dmz")
    assert conforme("SIEGE_HST_DMZ_WEB", dmz)
    assert not conforme("SIEGE_HST_SERVEURS_WEB", dmz)
    assert not conforme("GRAS_HST_DMZ_WEB", dmz)
    # Ancienne convention par zone : plus conforme, même si la zone existe toujours.
    assert not conforme("HQ_HST_LAN_PC01", Localisation("hq", "cabines"))
    assert conforme("HQ_HST_CABINES_PC01", Localisation("hq", "cabines"))
    assert conforme("HQ_GRP_MULTI_SERVEURS", Localisation("hq", "multi"), "groupe-adresses")


def _service(*elements):
    return empreinte_service([(proto, tuple((d, f, -1, -1) for d, f in ports)) for proto, ports in elements])


HTTPS = _service(("tcp", [(443, 443)]))


def test_services_calendriers_sans_site_ni_zone(contextes):
    assert est_conforme_objet("SVC_TCP_443_HTTPS", "service", contextes, signature=("TCP", "443"))
    assert est_conforme_objet("SVC_TCP_443", "service", contextes, signature=("TCP", "443"))
    assert est_conforme_objet("SG_ACTIVE-DIRECTORY", "groupe-services", contextes)
    assert not est_conforme_objet("SGRP_ACTIVE-DIRECTORY", "groupe-services", contextes)
    assert est_conforme_objet("SCH_BUREAU", "calendrier", contextes)
    assert not est_conforme_objet("SVC_HTTPS", "service", contextes, signature=("TCP", "443"))
    assert not est_conforme_objet("SVC_UDP_443_HTTPS", "service", contextes, signature=("TCP", "443"))
    assert not est_conforme_objet("SVC_TCP_8443_HTTPS", "service", contextes, signature=("TCP", "443"))
    assert not est_conforme_objet("SVC_TCP_443_HT.TPS", "service", contextes, signature=("TCP", "443"))
    assert not est_conforme_objet("SG_SIEGE_DMZ_WEB", "groupe-services", contextes, SITES)
    assert not est_conforme_objet("SCH_CTX_LAN_BUREAU", "calendrier", contextes)
    assert not est_conforme_objet("SIEGE_HST_LAN_A.B", "hote", contextes, SITES)


def test_signature_des_services():
    assert signature_service(HTTPS) == ("TCP", "443")
    assert signature_service(_service(("udp", [(67, 68)]))) == ("UDP", "67-68")
    assert signature_service(_service(("tcp", [(53, 53)]), ("udp", [(53, 53)]))) == ("ANY", "53")
    kerberos = _service(("tcp", [(88, 88), (464, 464)]), ("udp", [(88, 88), (464, 464)]))
    assert signature_service(kerberos) == ("ANY", "88.464")
    assert signature_service(_service(("icmp", [(8, 8)]))) == ("ICMP", "8")
    assert signature_service(_service(("icmp", [(-1, -1)]))) == ("ICMP", "ANY")
    assert signature_service(_service(("ip", [(47, 47)]))) == ("IP", "47")
    assert signature_service(_service(("ip", [(0, 0)]))) == ("IP", "ANY")


def test_services_gardent_leur_libelle_avec_protocole_et_port():
    assert proposer_service("HTTP-8080", _service(("tcp", [(8080, 8080)]))) == "SVC_TCP_8080_HTTP"
    assert proposer_service("HTTPS", HTTPS) == "SVC_TCP_443_HTTPS"
    assert proposer_service("SVC_TCP_443", HTTPS) == "SVC_TCP_443"
    assert proposer_service("LDAP_UDP", _service(("udp", [(389, 389)]))) == "SVC_UDP_389_LDAP"
    assert proposer_service("MS Global Catalog", _service(("tcp", [(3268, 3269)]))) == (
        "SVC_TCP_3268-3269_MS-GLOBAL-CATALOG"
    )
    dns = _service(("tcp", [(53, 53)]), ("udp", [(53, 53)]))
    assert proposer_service("DNS", dns) == "SVC_ANY_53_DNS"
    assert proposer_service("PING", _service(("icmp", [(8, 8)]))) == "SVC_ICMP_8_PING"


def test_reseaux_zone_vlan_interface(contextes):
    exact = Localisation("hq", "cabines", "lan", 25, exact=True)
    assert proposer_objet("Res-VLAN25", "NET", exact, contextes) == "HQ_NET_LAN_V25_CABINES"
    # Sans zone FortiGate (et toujours côté Stormshield) : pas de segment zone.
    sans_zone = Localisation("hq", "cabines", None, 25, exact=True)
    assert proposer_objet("Res-VLAN25", "NET", sans_zone, contextes) == "HQ_NET_V25_CABINES"
    # Port physique sans VLAN : pas de segment V.
    port = Localisation("hq", "cabines", "lan", None, exact=True)
    assert proposer_objet("cabines", "NET", port, contextes) == "HQ_NET_LAN_CABINES"
    # Sous-réseau : l'ancien nom reste en détail après l'interface, sans mention de VLAN.
    sous_reseau = exact._replace(exact=False)
    assert proposer_objet("Imprimantes [vlan25]", "NET", sous_reseau, contextes) == (
        "HQ_NET_LAN_V25_CABINES-IMPRIMANTES"
    )
    assert proposer_objet("VLAN-25", "NET", sous_reseau, contextes) == "HQ_NET_LAN_V25_CABINES"

    def conforme(nom, attendu):
        return est_conforme_objet(nom, "reseau", contextes, ("hq",), interfaces=("cabines",), attendu=attendu)

    assert conforme("HQ_NET_LAN_V25_CABINES", exact)
    assert not conforme("HQ_NET_LAN_V25_CABINES-IMPRIMANTES", exact)
    assert conforme("HQ_NET_LAN_V25_CABINES-IMPRIMANTES", sous_reseau)
    assert conforme("HQ_NET_LAN_V25_CABINES", sous_reseau)
    assert not conforme("HQ_NET_LAN_V26_CABINES", exact)
    assert not conforme("HQ_NET_V25_CABINES", exact)
    assert conforme("HQ_NET_V25_CABINES", sans_zone)
    assert conforme("HQ_NET_LAN_CABINES", port)
    assert not conforme("HQ_NET_LAN_VLAN25-CABINES", exact)
    # Sans localisation connue : forme seule.
    assert conforme("HQ_NET_LAN_V25_CABINES-X", None)
    assert conforme("HQ_NET_CABINES", None)
    assert not conforme("HQ_NET_USINE_V25_CABINES", None)
    assert not conforme("HQ_NET_LAN_V25_AUTRE", None)


def test_interface_avec_tiret_bas_ou_espaces(contextes):
    labo = Localisation("hq", normaliser_interface("LABO_ANA"))
    assert labo.interface == "labo-ana"
    assert normaliser_interface("WIFI INVITE VLAN-42") == "wifi-invite-vlan-42"
    assert normaliser_interface("Wi‑Fi GUEST") == "wi-fi-guest"
    assert proposer_objet("PC01", "HST", labo, contextes) == "HQ_HST_LABO-ANA_PC01"
    nouveau = proposer_objet("analyseur_labo_ana", "HST", labo, contextes)
    assert nouveau == "HQ_HST_LABO-ANA_ANALYSEUR"
    assert est_conforme_objet(nouveau, "hote", contextes, ("hq",), interfaces=("labo-ana",), attendu=labo)


def test_proposition_de_noms(contextes):
    dmz = Localisation("siege", "dmz")
    lan = Localisation("siege", "lan-users")
    assert proposer_objet("Web_DMZ", "HST", dmz, contextes) == "SIEGE_HST_DMZ_WEB"
    assert proposer_objet("SIEGE_zabbix", "HST", lan, contextes) == "SIEGE_HST_LAN-USERS_ZABBIX"
    assert proposer_objet("HST-DMZ-WEB-01", "HST", dmz, contextes) == "SIEGE_HST_DMZ_WEB-01"
    assert proposer_objet("GRAS_HST_DMZ_WEB-01", "HST", dmz, contextes) == "SIEGE_HST_DMZ_WEB-01"
    assert proposer_objet("HST_GRAS_DMZ_WEB-01", "HST", dmz, contextes) == "SIEGE_HST_DMZ_WEB-01"
    assert proposer_objet("SIEGE_HST_web", "HST", dmz, contextes) == "SIEGE_HST_DMZ_WEB"
    assert proposer_objet("Hôte_DMZ", "HST", lan, contextes) == "SIEGE_HST_LAN-USERS_HOTE-DMZ"
    assert proposer_objet("SIEGE_HST_LAN_ZABBIX_SRV", "HST", lan, contextes) == "SIEGE_HST_LAN-USERS_ZABBIX-SRV"
    groupe = Localisation("hq", "multi")
    assert proposer_objet("Serveurs", "GRP", groupe, contextes) == "HQ_GRP_MULTI_SERVEURS"
    assert proposer_objet("Bureau", "SCH", None, contextes) == "SCH_BUREAU"


def test_anciens_formats_reconnus(contextes):
    """Noms du lot 01 déjà appliqués sur le lab : ni la zone ni le VLAN ne passent dans le détail."""
    reseau = Localisation("hq", "vlan-11", "lan", 11)
    assert proposer_objet("HQ_NET_LAN_VLAN11-RES", "NET", reseau, contextes) == "HQ_NET_LAN_V11_VLAN-11-RES"
    assert proposer_objet("NET_HQ_LAN_VLAN11-RES", "NET", reseau, contextes) == "HQ_NET_LAN_V11_VLAN-11-RES"
    cabines = Localisation("hq", "cabines")
    assert proposer_objet("HQ_GRP_LAN_IMPRIMANTES", "GRP", cabines, contextes) == "HQ_GRP_CABINES_IMPRIMANTES"
    assert proposer_objet("HQ_HST_LOOP_FGT", "HST", cabines, contextes) == "HQ_HST_CABINES_FGT"
    assert proposer_objet("HQ_HST_MULTI_X", "HST", cabines, contextes) == "HQ_HST_CABINES_X"
    # Nouvelle forme relue : l'interface en tête du dernier segment n'est pas répétée.
    sous_reseau = Localisation("hq", "cabines", "lan", 16)
    nom = "HQ_NET_LAN_V16_CABINES-IMPRIMANTES"
    assert proposer_objet(nom, "NET", sous_reseau, contextes, interfaces=("cabines",)) == nom
    autre = Localisation("hq", "cabines-bis", "lan", 17)
    assert proposer_objet(nom, "NET", autre, contextes, interfaces=("cabines",)) == (
        "HQ_NET_LAN_V17_CABINES-BIS-IMPRIMANTES"
    )


def test_groupes_de_services_et_calendriers(contextes):
    assert proposer_objet("Active Directory", "SG", None, contextes) == "SG_ACTIVE-DIRECTORY"
    assert proposer_objet("SGRP_CTX_DMZ_WEB", "SG", None, contextes) == "SG_WEB"
    assert proposer_objet("SG_CTX_DMZ_WEB", "SG", None, contextes) == "SG_WEB"


def test_ancien_prefixe_sgrp_renomme_en_sg(contextes):
    assert not est_conforme_objet("SGRP_X", "groupe-services", contextes)
    assert proposer_objet("SGRP_X", "SG", None, contextes) == "SG_X"
    assert proposer_objet("SGRP_ACTIVE-DIRECTORY", "SG", None, contextes) == "SG_ACTIVE-DIRECTORY"
    assert proposer_objet("Bureau", "SCH", None, contextes) == "SCH_BUREAU"


def test_limites_fortigate(contextes):
    assert longueur_max("fortigate", "calendrier") == 31
    assert longueur_max("fortigate", "hote") == 79
    assert longueur_max("stormshield", "calendrier") == 79
    nom = "SCH_" + "X" * 28
    assert est_conforme_objet(nom, "calendrier", contextes)
    assert not est_conforme_objet(nom, "calendrier", contextes, (), 31)


def test_troncature_garde_la_structure_et_le_suffixe():
    assert tronquer("SIEGE_HST_LAN_HORAIRES-USINE-NUITS", 31) == "SIEGE_HST_LAN_HORAIRES-USINE"
    base = "SIEGE_HST_LAN_HORAIRES-USINE-AB"
    assert len(base) == 31
    unique = rendre_unique(base, {base}, 31)
    assert unique == "SIEGE_HST_LAN_HORAIRES-USINE-01"
    assert len(unique) <= 31
    assert rendre_unique("SCH_" + "X" * 30, set(), 31) == "SCH_" + "X" * 27


def test_troncature_coupe_le_detail_jamais_l_interface(contextes):
    interface = "centrale-detection-gaz"
    loc = Localisation("hq", interface, "lan", 25)
    nom = proposer_objet("tres long detail " * 5, "NET", loc, contextes, 60)
    assert nom.startswith("HQ_NET_LAN_V25_CENTRALE-DETECTION-GAZ-TRES")
    assert len(nom) <= 60
    assert tronquer("HQ_NET_LAN_V25_CENTRALE-DETECTION-GAZ", 30, protege=len(interface)) == (
        "HQ_NET_LAN_V25_CENTRALE"
    )
    base = "HQ_NET_LAN_V25_CENTRALE-DETECTION-GAZ-ABC"
    unique = rendre_unique(base, {base}, len(base), len(interface))
    assert unique == "HQ_NET_LAN_V25_CENTRALE-DETECTION-GAZ-01"
