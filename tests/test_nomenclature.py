from fwclean.contenu import empreinte_service
from fwclean.naming import (
    Localisation,
    est_conforme_objet,
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


def test_objets_conformes_et_plafond():
    def conforme(nom, sorte="hote", sites=SITES, attendu=None):
        return est_conforme_objet(nom, sorte, sites, interfaces=INTERFACES, attendu=attendu)

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


def test_conformite_contre_l_interface_attendue():
    def conforme(nom, attendu, sorte="hote"):
        sites = (*SITES, "hq")
        return est_conforme_objet(nom, sorte, sites, interfaces=INTERFACES, attendu=attendu)

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


def test_services_calendriers_sans_site_ni_zone():
    assert est_conforme_objet("SVC_TCP_443_HTTPS", "service", signature=("TCP", "443"))
    assert est_conforme_objet("SVC_TCP_443", "service", signature=("TCP", "443"))
    assert est_conforme_objet("SG_ACTIVE-DIRECTORY", "groupe-services")
    assert not est_conforme_objet("SGRP_ACTIVE-DIRECTORY", "groupe-services")
    assert est_conforme_objet("SCH_BUREAU", "calendrier")
    assert not est_conforme_objet("SVC_HTTPS", "service", signature=("TCP", "443"))
    assert not est_conforme_objet("SVC_UDP_443_HTTPS", "service", signature=("TCP", "443"))
    assert not est_conforme_objet("SVC_TCP_8443_HTTPS", "service", signature=("TCP", "443"))
    assert not est_conforme_objet("SVC_TCP_443_HT.TPS", "service", signature=("TCP", "443"))
    assert not est_conforme_objet("SG_SIEGE_DMZ_WEB", "groupe-services", SITES)
    assert not est_conforme_objet("SCH_CTX_LAN_BUREAU", "calendrier")
    assert not est_conforme_objet("SIEGE_HST_LAN_A.B", "hote", SITES)


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


def test_reseaux_vlan_interface():
    exact = Localisation("hq", "cabines", 25, exact=True)
    assert proposer_objet("Res-VLAN25", "NET", exact) == "HQ_NET_V25_CABINES"
    # Zone réservée à l'inventaire : jamais dans le nom, même renseignée.
    sans_zone = Localisation("hq", "cabines", 25, exact=True)
    assert proposer_objet("Res-VLAN25", "NET", sans_zone) == "HQ_NET_V25_CABINES"
    # Port physique sans VLAN : pas de segment V.
    port = Localisation("hq", "cabines", None, exact=True)
    assert proposer_objet("cabines", "NET", port) == "HQ_NET_CABINES"
    # Sous-réseau : l'ancien nom reste en détail après l'interface, sans mention de VLAN.
    sous_reseau = exact._replace(exact=False)
    assert proposer_objet("Imprimantes [vlan25]", "NET", sous_reseau) == (
        "HQ_NET_V25_CABINES-IMPRIMANTES"
    )
    assert proposer_objet("VLAN-25", "NET", sous_reseau) == "HQ_NET_V25_CABINES"

    def conforme(nom, attendu):
        return est_conforme_objet(nom, "reseau", ("hq",), interfaces=("cabines",), attendu=attendu)

    assert conforme("HQ_NET_V25_CABINES", exact)
    assert not conforme("HQ_NET_V25_CABINES-IMPRIMANTES", exact)
    assert conforme("HQ_NET_V25_CABINES-IMPRIMANTES", sous_reseau)
    assert conforme("HQ_NET_V25_CABINES", sous_reseau)
    assert not conforme("HQ_NET_V26_CABINES", exact)
    # Ancienne forme avec zone : plus conforme.
    assert not conforme("HQ_NET_LAN_V25_CABINES", exact)
    assert conforme("HQ_NET_CABINES", port)
    assert not conforme("HQ_NET_LAN_CABINES", port)
    assert not conforme("HQ_NET_LAN_VLAN25-CABINES", exact)
    # Sans localisation connue : forme seule (milieu = VLAN optionnel seulement).
    assert conforme("HQ_NET_V25_CABINES-X", None)
    assert conforme("HQ_NET_CABINES", None)
    assert not conforme("HQ_NET_LAN_V25_CABINES-X", None)
    assert not conforme("HQ_NET_USINE_V25_CABINES", None)
    assert not conforme("HQ_NET_V25_AUTRE", None)


def test_interface_avec_tiret_bas_ou_espaces():
    labo = Localisation("hq", normaliser_interface("LABO_ANA"))
    assert labo.interface == "labo-ana"
    assert normaliser_interface("WIFI INVITE VLAN-42") == "wifi-invite-vlan-42"
    assert normaliser_interface("Wi‑Fi GUEST") == "wi-fi-guest"
    assert proposer_objet("PC01", "HST", labo) == "HQ_HST_LABO-ANA_PC01"
    nouveau = proposer_objet("analyseur_labo_ana", "HST", labo)
    assert nouveau == "HQ_HST_LABO-ANA_ANALYSEUR"
    assert est_conforme_objet(nouveau, "hote", ("hq",), interfaces=("labo-ana",), attendu=labo)


def test_proposition_de_noms():
    dmz = Localisation("siege", "dmz")
    lan = Localisation("siege", "lan-users")
    assert proposer_objet("Web_DMZ", "HST", dmz) == "SIEGE_HST_DMZ_WEB"
    assert proposer_objet("SIEGE_zabbix", "HST", lan) == "SIEGE_HST_LAN-USERS_ZABBIX"
    assert proposer_objet("HST-DMZ-WEB-01", "HST", dmz) == "SIEGE_HST_DMZ_WEB-01"
    assert proposer_objet("GRAS_HST_DMZ_WEB-01", "HST", dmz) == "SIEGE_HST_DMZ_WEB-01"
    assert proposer_objet("HST_GRAS_DMZ_WEB-01", "HST", dmz) == "SIEGE_HST_DMZ_WEB-01"
    assert proposer_objet("SIEGE_HST_web", "HST", dmz) == "SIEGE_HST_DMZ_WEB"
    assert proposer_objet("Hôte_DMZ", "HST", lan) == "SIEGE_HST_LAN-USERS_HOTE-DMZ"
    assert proposer_objet("SIEGE_HST_LAN_ZABBIX_SRV", "HST", lan) == "SIEGE_HST_LAN-USERS_ZABBIX-SRV"
    groupe = Localisation("hq", "multi")
    assert proposer_objet("Serveurs", "GRP", groupe) == "HQ_GRP_MULTI_SERVEURS"
    assert proposer_objet("Bureau", "SCH", None) == "SCH_BUREAU"


def test_anciens_formats_reconnus():
    """Noms du lot 01 déjà appliqués sur le lab : ni la zone ni le VLAN ne passent dans le détail."""
    reseau = Localisation("hq", "vlan-11", 11)
    assert proposer_objet("HQ_NET_LAN_VLAN11-RES", "NET", reseau) == "HQ_NET_V11_VLAN-11-RES"
    assert proposer_objet("NET_HQ_LAN_VLAN11-RES", "NET", reseau) == "HQ_NET_V11_VLAN-11-RES"
    cabines = Localisation("hq", "cabines")
    assert proposer_objet("HQ_GRP_LAN_IMPRIMANTES", "GRP", cabines) == "HQ_GRP_CABINES_IMPRIMANTES"
    assert proposer_objet("HQ_HST_LOOP_FGT", "HST", cabines) == "HQ_HST_CABINES_FGT"
    assert proposer_objet("HQ_HST_MULTI_X", "HST", cabines) == "HQ_HST_CABINES_X"
    # Forme avec zone relue : l'interface en tête du dernier segment n'est pas répétée, zone retirée.
    sous_reseau = Localisation("hq", "cabines", 16)
    assert proposer_objet("HQ_NET_LAN_V16_CABINES-IMPRIMANTES", "NET", sous_reseau, interfaces=("cabines",)) == (
        "HQ_NET_V16_CABINES-IMPRIMANTES"
    )
    nom = "HQ_NET_V16_CABINES-IMPRIMANTES"
    assert proposer_objet(nom, "NET", sous_reseau, interfaces=("cabines",)) == nom
    autre = Localisation("hq", "cabines-bis", 17)
    assert proposer_objet(nom, "NET", autre, interfaces=("cabines",)) == (
        "HQ_NET_V17_CABINES-BIS-IMPRIMANTES"
    )


def test_groupes_de_services_et_calendriers():
    assert proposer_objet("Active Directory", "SG", None) == "SG_ACTIVE-DIRECTORY"
    assert proposer_objet("SGRP_CTX_DMZ_WEB", "SG", None) == "SG_WEB"
    assert proposer_objet("SG_CTX_DMZ_WEB", "SG", None) == "SG_WEB"


def test_ancien_prefixe_sgrp_renomme_en_sg():
    assert not est_conforme_objet("SGRP_X", "groupe-services")
    assert proposer_objet("SGRP_X", "SG", None) == "SG_X"
    assert proposer_objet("SGRP_ACTIVE-DIRECTORY", "SG", None) == "SG_ACTIVE-DIRECTORY"
    assert proposer_objet("Bureau", "SCH", None) == "SCH_BUREAU"


def test_limites_fortigate():
    assert longueur_max("fortigate", "calendrier") == 31
    assert longueur_max("fortigate", "hote") == 79
    assert longueur_max("stormshield", "calendrier") == 79
    nom = "SCH_" + "X" * 28
    assert est_conforme_objet(nom, "calendrier")
    assert not est_conforme_objet(nom, "calendrier", (), 31)


def test_troncature_garde_la_structure_et_le_suffixe():
    assert tronquer("SIEGE_HST_LAN_HORAIRES-USINE-NUITS", 31) == "SIEGE_HST_LAN_HORAIRES-USINE"
    base = "SIEGE_HST_LAN_HORAIRES-USINE-AB"
    assert len(base) == 31
    unique = rendre_unique(base, {base}, 31)
    assert unique == "SIEGE_HST_LAN_HORAIRES-USINE-01"
    assert len(unique) <= 31
    assert rendre_unique("SCH_" + "X" * 30, set(), 31) == "SCH_" + "X" * 27


def test_troncature_coupe_le_detail_jamais_l_interface():
    interface = "centrale-detection-gaz"
    loc = Localisation("hq", interface, 25)
    nom = proposer_objet("tres long detail " * 5, "NET", loc, 60)
    assert nom.startswith("HQ_NET_V25_CENTRALE-DETECTION-GAZ-TRES")
    assert len(nom) <= 60
    assert tronquer("HQ_NET_V25_CENTRALE-DETECTION-GAZ", 30, protege=len(interface)) == (
        "HQ_NET_V25_CENTRALE-DETECTION"
    )
    base = "HQ_NET_V25_CENTRALE-DETECTION-GAZ-ABC"
    unique = rendre_unique(base, {base}, len(base), len(interface))
    assert unique == "HQ_NET_V25_CENTRALE-DETECTION-GAZ-01"
