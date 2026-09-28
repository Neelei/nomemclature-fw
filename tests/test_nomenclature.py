from fwclean.contenu import empreinte_service
from fwclean.naming import (
    est_conforme_objet,
    est_conforme_regle,
    lire_contextes,
    proposer_depuis_nom,
    proposer_regle,
    proposer_service,
)


def test_contextes_par_defaut(racine):
    contextes = lire_contextes(racine / "contextes.txt")
    assert contextes == ("dmz", "lan", "wan", "vpn", "ctx")


def test_objets_conformes_et_plafond(racine):
    contextes = lire_contextes(racine / "contextes.txt")
    assert est_conforme_objet("HST-DMZ-WEB-01", "hote", contextes)
    assert est_conforme_objet("NET-LAN-UTILISATEURS", "reseau", contextes)
    assert est_conforme_objet("SVC-TCP-443", "service", contextes)
    assert est_conforme_objet("SVC-UDP-53", "service", contextes)
    assert est_conforme_objet("GRP-DMZ-WEB", "groupe-adresses", contextes)
    assert not est_conforme_objet("Web_DMZ", "hote", contextes)
    assert not est_conforme_objet("hst-dmz-web-01", "hote", contextes)
    assert not est_conforme_objet("HST-DMZ", "hote", contextes)
    assert not est_conforme_objet("NET-DMZ-WEB", "hote", contextes)
    assert not est_conforme_objet("SVC-DMZ-HTTPS", "service", contextes)
    nom = "HST-DMZ-" + ("A" * 71)
    assert len(nom) == 79
    assert est_conforme_objet(nom, "hote", contextes)
    assert not est_conforme_objet(nom + "B", "hote", contextes)


def test_regles_suffixe_et_port(racine):
    contextes = lire_contextes(racine / "contextes.txt")
    assert est_conforme_regle("ALLOW-LAN-DMZ-HTTPS", "allow", contextes)
    assert est_conforme_regle("ALLOW-LAN-DMZ-HTTPS-01", "allow", contextes)
    assert est_conforme_regle("ALLOW-LAN-DMZ-TCP-80", "allow", contextes)
    assert est_conforme_regle("ALLOW-LAN-DMZ-TCP-443", "allow", contextes)
    assert not est_conforme_regle("ALLOW-LAN-DMZ-01", "allow", contextes)
    assert not est_conforme_regle("DENY-LAN-DMZ-HTTPS", "allow", contextes)
    assert not est_conforme_regle("allow-lan-dmz-https", "allow", contextes)
    assert not est_conforme_regle("Acces web", "allow", contextes)


def test_proposition_de_noms(racine):
    contextes = lire_contextes(racine / "contextes.txt")
    assert proposer_depuis_nom("Web_DMZ", "HST", contextes) == "HST-DMZ-WEB"
    assert proposer_depuis_nom("Hôte_DMZ", "HST", contextes) == "HST-DMZ-HOTE"
    assert proposer_depuis_nom("srv-oublie", "HST", contextes) == "HST-CTX-SRV-OUBLIE"
    empreinte = empreinte_service([("tcp", ((443, 443, -1, -1),))])
    assert proposer_service(empreinte) == "SVC-TCP-443"
    assert (
        proposer_regle(
            "allow",
            ("lan",),
            ("dmz",),
            ("NET-LAN-UTILISATEURS",),
            ("web_dmz_backup",),
            ("SVC-TCP-443",),
            contextes,
        )
        == "ALLOW-LAN-DMZ-TCP-443"
    )


def test_code_site_sans_changer_l_outil(tmp_path):
    fichier = tmp_path / "contextes.txt"
    fichier.write_text("par\nlyo\n", encoding="utf-8")
    contextes = lire_contextes(fichier)
    assert est_conforme_objet("HST-PAR-WEB-01", "hote", contextes)
    assert est_conforme_regle("ALLOW-PAR-LYO-HTTPS", "allow", contextes)
    assert not est_conforme_objet("HST-DMZ-WEB-01", "hote", contextes)
