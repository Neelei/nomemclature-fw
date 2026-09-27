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
    assert est_conforme_objet("hst-dmz-web-01", "hote", contextes)
    assert est_conforme_objet("net-lan-utilisateurs", "reseau", contextes)
    assert est_conforme_objet("svc-tcp-443", "service", contextes)
    assert est_conforme_objet("svc-udp-53", "service", contextes)
    assert est_conforme_objet("grp-dmz-web", "groupe-adresses", contextes)
    assert not est_conforme_objet("Web_DMZ", "hote", contextes)
    assert not est_conforme_objet("hst-dmz", "hote", contextes)
    assert not est_conforme_objet("net-dmz-web", "hote", contextes)
    assert not est_conforme_objet("svc-dmz-https", "service", contextes)
    nom = "hst-dmz-" + ("a" * 71)
    assert len(nom) == 79
    assert est_conforme_objet(nom, "hote", contextes)
    assert not est_conforme_objet(nom + "b", "hote", contextes)


def test_regles_suffixe_et_port(racine):
    contextes = lire_contextes(racine / "contextes.txt")
    assert est_conforme_regle("allow-lan-dmz-https", "allow", contextes)
    assert est_conforme_regle("allow-lan-dmz-https-01", "allow", contextes)
    assert est_conforme_regle("allow-lan-dmz-tcp-80", "allow", contextes)
    assert est_conforme_regle("allow-lan-dmz-tcp-443", "allow", contextes)
    assert not est_conforme_regle("allow-lan-dmz-01", "allow", contextes)
    assert not est_conforme_regle("deny-lan-dmz-https", "allow", contextes)
    assert not est_conforme_regle("Acces web", "allow", contextes)


def test_proposition_de_noms(racine):
    contextes = lire_contextes(racine / "contextes.txt")
    assert proposer_depuis_nom("Web_DMZ", "hst", contextes) == "hst-dmz-web"
    assert proposer_depuis_nom("Hôte_DMZ", "hst", contextes) == "hst-dmz-hote"
    assert proposer_depuis_nom("srv-oublie", "hst", contextes) == "hst-ctx-srv-oublie"
    empreinte = empreinte_service([("tcp", ((443, 443, -1, -1),))])
    assert proposer_service(empreinte) == "svc-tcp-443"
    assert (
        proposer_regle(
            "allow",
            ("lan",),
            ("dmz",),
            ("net-lan-utilisateurs",),
            ("web_dmz_backup",),
            ("svc-tcp-443",),
            contextes,
        )
        == "allow-lan-dmz-tcp-443"
    )


def test_code_site_sans_changer_l_outil(tmp_path):
    fichier = tmp_path / "contextes.txt"
    fichier.write_text("par\nlyo\n", encoding="utf-8")
    contextes = lire_contextes(fichier)
    assert est_conforme_objet("hst-par-web-01", "hote", contextes)
    assert est_conforme_regle("allow-par-lyo-https", "allow", contextes)
    assert not est_conforme_objet("hst-dmz-web-01", "hote", contextes)
