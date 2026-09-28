from fwclean.contenu import empreinte_service
from fwclean.naming import (
    est_conforme_objet,
    est_conforme_regle,
    jeton_service,
    lire_contextes,
    proposer_objet,
    proposer_regle,
    proposer_service,
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
    assert est_conforme_objet("HST-EPFR-LAN-ZABBIXSRV", "hote", contextes, SITES)
    assert est_conforme_objet("NET-GRAS-LAN-VLAN210", "reseau", contextes, SITES)
    assert est_conforme_objet("GRP-MULTI-LAN-CLIENTS", "groupe-adresses", contextes, SITES)
    assert est_conforme_objet("FQDN-CTX-WAN-UPDATES", "fqdn", contextes, SITES)
    assert est_conforme_objet("HST-EPFR-MULTI-X", "hote", contextes, SITES)
    assert est_conforme_objet("SVC-TCP-443", "service", contextes, SITES)
    assert est_conforme_objet("SVC-UDP-53", "service", contextes)
    assert not est_conforme_objet("HST-DMZ-WEB-01", "hote", contextes, SITES)
    assert not est_conforme_objet("HST-LYON-LAN-WEB", "hote", contextes, SITES)
    assert not est_conforme_objet("HST-EPFR-USINE-WEB", "hote", contextes, SITES)
    assert not est_conforme_objet("HST-EPFR-LAN", "hote", contextes, SITES)
    assert not est_conforme_objet("hst-epfr-lan-web", "hote", contextes, SITES)
    assert not est_conforme_objet("NET-EPFR-LAN-WEB", "hote", contextes, SITES)
    assert not est_conforme_objet("SVC-EPFR-LAN-HTTPS", "service", contextes, SITES)
    assert est_conforme_objet("HST-EPFR-LAN-X", "hote", contextes, ("EPFR",))
    nom = "HST-EPFR-DMZ-" + ("A" * 66)
    assert len(nom) == 79
    assert est_conforme_objet(nom, "hote", contextes, SITES)
    assert not est_conforme_objet(nom + "B", "hote", contextes, SITES)


def test_site_inconnu_sans_referentiel(contextes):
    assert not est_conforme_objet("HST-EPFR-LAN-ZABBIXSRV", "hote", contextes)
    assert est_conforme_objet("HST-CTX-LAN-ZABBIXSRV", "hote", contextes)


def test_regles_suffixe_et_port(contextes):
    assert est_conforme_regle("ALLOW-EPFR-LAN-DMZ-HTTPS", "allow", contextes, SITES)
    assert est_conforme_regle("ALLOW-EPFR-LAN-DMZ-HTTPS-01", "allow", contextes, SITES)
    assert est_conforme_regle("ALLOW-EPFR-LAN-DMZ-TCP-80", "allow", contextes, SITES)
    assert est_conforme_regle("DENY-MULTI-WAN-LAN-ANY", "deny", contextes, SITES)
    assert not est_conforme_regle("ALLOW-EPFR-LAN-DMZ-01", "allow", contextes, SITES)
    assert not est_conforme_regle("ALLOW-LAN-DMZ-HTTPS", "allow", contextes, SITES)
    assert not est_conforme_regle("ALLOW-LYON-LAN-DMZ-HTTPS", "allow", contextes, SITES)
    assert not est_conforme_regle("DENY-EPFR-LAN-DMZ-HTTPS", "allow", contextes, SITES)
    assert not est_conforme_regle("allow-epfr-lan-dmz-https", "allow", contextes, SITES)
    assert not est_conforme_regle("Acces web", "allow", contextes, SITES)


def test_proposition_de_noms(contextes):
    assert proposer_objet("Web_DMZ", "HST", "epfr", "dmz", contextes, SITES) == "HST-EPFR-DMZ-WEB"
    assert proposer_objet("Hôte_DMZ", "HST", "ctx", "dmz", contextes, SITES) == "HST-CTX-DMZ-HOTE"
    assert proposer_objet("srv-oublie", "HST", "ctx", "ctx", contextes, SITES) == "HST-CTX-CTX-SRV-OUBLIE"
    assert proposer_objet("EPFR_zabbix", "HST", "epfr", "lan", contextes, SITES) == "HST-EPFR-LAN-ZABBIX"
    assert proposer_objet("HST-DMZ-WEB-01", "HST", "epfr", "dmz", contextes, SITES) == "HST-EPFR-DMZ-WEB-01"
    assert proposer_objet("HST-EPFR-DMZ-WEB-01", "HST", "ctx", "dmz", contextes) == "HST-CTX-DMZ-WEB-01"
    empreinte = empreinte_service([("tcp", ((443, 443, -1, -1),))])
    assert proposer_service(empreinte) == "SVC-TCP-443"
    assert proposer_regle("allow", "epfr", "lan", "dmz", ("SVC-TCP-443",)) == "ALLOW-EPFR-LAN-DMZ-TCP-443"
    assert jeton_service(("SGRP-CTX-DMZ-WEB",)) == "web"
    assert jeton_service(("SGRP-DMZ-WEB",)) == "dmz-web"
    assert jeton_service(("SVC-TCP-443", "SVC-UDP-53")) == "multi"
