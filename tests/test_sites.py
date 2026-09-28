import pytest

from fwclean.audit import auditer
from fwclean.fortigate import lire_fortigate
from fwclean.model import ErreurLecture, Inventaire, Objet, Regle
from fwclean.sites import Localisateur, Localisation, analyser_reseaux, commun


def _hote(nom: str, ip: str) -> Objet:
    return Objet(sorte="hote", nom=nom, empreinte=("v4", ip, 32), detail=f"{ip}/32")


def _reseau(nom: str, adresse: str, prefixe: int) -> Objet:
    return Objet(
        sorte="reseau", nom=nom, empreinte=("v4", adresse, prefixe), detail=f"{adresse}/{prefixe}"
    )


def _groupe(nom: str, *membres: str) -> Objet:
    return Objet(
        sorte="groupe-adresses",
        nom=nom,
        empreinte=(membres, ()),
        detail=", ".join(membres),
        mentions_adresses=membres,
    )


def _localisateur(objets, contextes, referentiel, regles=()):
    inventaire = Inventaire(
        constructeur="fortigate", sources=("memoire",), objets=tuple(objets), regles=tuple(regles)
    )
    return Localisateur(inventaire, contextes, referentiel), inventaire


def test_lecture_du_referentiel(contextes, referentiel):
    assert referentiel.sites == ("epfr", "gras")
    assert len(referentiel.entrees) == 6
    texte = "# commentaire\nRESEAU;Site;Zone\n10.0.0.0/8;EPFR;LAN   # casse tolérée\n"
    lu = analyser_reseaux(texte, contextes)
    assert lu.entrees[0].site == "epfr" and lu.entrees[0].zone == "lan"


@pytest.mark.parametrize(
    "texte",
    [
        "reseau,site,zone\n10.0.0.0/8,epfr,lan\n",
        "reseau;site;zone\n10.0.0.0/33;epfr;lan\n",
        "reseau;site;zone\n10.0.0.0/8;epfr;usine\n",
        "reseau;site;zone\n10.0.0.0/8;ctx;lan\n",
        "reseau;site;zone\n10.0.0.0/8;ep-fr;lan\n",
        "reseau;site;zone\n10.0.0.0/8;epfr\n",
        "reseau;site;zone\n10.0.0.0/8;epfr;lan\n10.0.0.0/8;gras;lan\n",
    ],
)
def test_referentiel_invalide(contextes, texte):
    with pytest.raises(ErreurLecture):
        analyser_reseaux(texte, contextes)


def test_commun():
    assert commun(["epfr", "epfr"]) == "epfr"
    assert commun(["epfr", "ctx"]) == "epfr"
    assert commun(["epfr", "gras"]) == "multi"
    assert commun(["ctx"]) == "ctx"
    assert commun([]) == "ctx"


def test_site_trouve_et_reseau_le_plus_precis(contextes, referentiel):
    loc, _ = _localisateur([], contextes, referentiel)
    objets = {
        "zabbix": _hote("zabbix_srv", "10.1.2.10"),
        "web": _hote("web", "10.1.1.10"),
        "vlan": _reseau("Vlan210", "10.210.0.0", 24),
        "large": _reseau("tout_epfr", "10.1.0.0", 16),
    }
    assert loc.objet(objets["zabbix"]) == Localisation("epfr", "lan")
    assert loc.objet(objets["web"]) == Localisation("epfr", "dmz")
    assert loc.objet(objets["vlan"]) == Localisation("gras", "lan")
    assert loc.objet(objets["large"]) == Localisation("epfr", "lan")


def test_hors_referentiel_ctx_et_zone_par_le_nom(contextes, referentiel):
    loc, _ = _localisateur([], contextes, referentiel)
    assert loc.objet(_hote("srv_dmz_tiers", "192.0.2.50")) == Localisation("ctx", "dmz")
    assert loc.objet(_hote("EPFR_srv", "192.0.2.51")) == Localisation("ctx", "ctx")
    assert loc.objet(_reseau("NET-EPFR-LAN-LARGE", "10.0.0.0", 8)) == Localisation("ctx", "lan")


def test_plage_pool_vip_et_fqdn(contextes, referentiel):
    plage = Objet(sorte="plage", nom="p", empreinte=("v4", "10.8.0.1", "10.8.0.200"), detail="")
    a_cheval = Objet(sorte="plage", nom="q_lan", empreinte=("v4", "10.0.0.250", "10.1.1.5"), detail="")
    pool_a_cheval = Objet(sorte="pool", nom="q", empreinte=("10.0.0.250", "10.1.1.5"), detail="")
    pool = Objet(sorte="pool", nom="nat", empreinte=("203.0.113.20", "203.0.113.30"), detail="")
    web = _hote("HST-EPFR-DMZ-WEB-01", "10.1.1.10")
    vip = Objet(
        sorte="vip",
        nom="vip_web",
        empreinte=("vip", "203.0.113.10", "HST-EPFR-DMZ-WEB-01", "", "", ""),
        detail="",
        mentions_adresses=("HST-EPFR-DMZ-WEB-01",),
    )
    vip_interne = Objet(
        sorte="vip", nom="vip_lan", empreinte=("vip", "198.51.100.1", "10.1.2.5", "", "", ""), detail=""
    )
    fqdn = Objet(sorte="fqdn", nom="gras_wan_maj", empreinte=("fqdn", "maj.example.com"), detail="")
    loc, _ = _localisateur([web, vip], contextes, referentiel)
    assert loc.objet(plage) == Localisation("epfr", "vpn")
    assert loc.objet(a_cheval) == Localisation("ctx", "lan")
    assert loc.objet(pool_a_cheval) == Localisation("epfr", "multi")
    assert loc.objet(pool) == Localisation("epfr", "wan")
    assert loc.objet(vip) == Localisation("epfr", "multi")
    assert loc.objet(vip_interne) == Localisation("epfr", "lan")
    assert loc.objet(fqdn) == Localisation("gras", "wan")


def test_groupe_multi_et_groupe_commun(contextes, referentiel):
    objets = [
        _hote("a", "10.1.2.10"),
        _hote("b", "10.1.2.11"),
        _reseau("Vlan210", "10.210.0.0", 24),
        _hote("dehors", "192.0.2.9"),
        _groupe("meme_site", "a", "b", "dehors"),
        _groupe("deux_sites", "a", "Vlan210"),
        _groupe("imbrique", "meme_site", "deux_sites"),
        _groupe("inconnus_dmz", "dehors"),
    ]
    loc, _ = _localisateur(objets, contextes, referentiel)
    par_nom = {objet.nom: objet for objet in objets}
    assert loc.objet(par_nom["meme_site"]) == Localisation("epfr", "lan")
    assert loc.objet(par_nom["deux_sites"]) == Localisation("multi", "lan")
    assert loc.objet(par_nom["imbrique"]) == Localisation("multi", "lan")
    assert loc.objet(par_nom["inconnus_dmz"]) == Localisation("ctx", "dmz")


def test_groupe_cyclique_ne_boucle_pas(contextes, referentiel):
    objets = [_groupe("x", "y"), _groupe("y", "x")]
    loc, _ = _localisateur(objets, contextes, referentiel)
    assert loc.objet(objets[0]) == Localisation("ctx", "ctx")


def test_regle_site_depuis_les_sources_et_zones(contextes, referentiel):
    objets = [
        _hote("zabbix", "10.1.2.10"),
        _hote("web", "10.1.1.10"),
        _reseau("Vlan210", "10.210.0.0", 24),
    ]
    regles = [
        Regle("r1", "allow", True, ("zabbix",), ("web",), ("SVC-TCP-443",), ("port1",), ("port2",)),
        Regle("r2", "allow", True, ("zabbix", "Vlan210"), ("web",), ("SVC-TCP-443",), ("lan",), ("dmz",)),
        Regle("r3", "deny", True, ("all",), ("web",), ("ALL",), ("wan",), ("dmz",)),
        Regle("r4", "allow", True, ("all",), ("all",), ("ALL",), ("port9",), ("port8",)),
    ]
    loc, _ = _localisateur(objets, contextes, referentiel, regles)
    assert loc.regle(regles[0]) == ("epfr", "lan", "dmz")
    assert loc.regle(regles[1]) == ("multi", "lan", "dmz")
    assert loc.regle(regles[2]) == ("epfr", "wan", "dmz")
    assert loc.regle(regles[3]) == ("ctx", "ctx", "ctx")


def test_audit_propose_site_et_zone(contextes, referentiel):
    texte = """
config firewall address
    edit "zabbix_srv"
        set subnet 10.1.2.10 255.255.255.255
    next
    edit "HST-EPFR-DMZ-WEB-01"
        set subnet 10.1.1.10 255.255.255.255
    next
    edit "partenaire"
        set subnet 192.0.2.10 255.255.255.255
    next
end
config firewall policy
    edit 1
        set name "supervision"
        set srcintf "port1"
        set dstintf "dmz"
        set srcaddr "zabbix_srv"
        set dstaddr "HST-EPFR-DMZ-WEB-01" "partenaire"
        set action accept
        set service "SVC-TCP-10050"
    next
end
"""
    resultat = auditer(lire_fortigate(texte, "memoire"), contextes, referentiel)
    assert [(item.ancien, item.nouveau) for item in resultat.renommages] == [
        ("partenaire", "HST-CTX-CTX-PARTENAIRE"),
        ("zabbix_srv", "HST-EPFR-LAN-ZABBIX-SRV"),
        ("supervision", "ALLOW-EPFR-LAN-DMZ-TCP-10050"),
    ]
    assert "sites : EPFR, GRAS" in resultat.referentiel


def test_audit_sans_referentiel(contextes):
    texte = """
config firewall address
    edit "HST-EPFR-DMZ-WEB-01"
        set subnet 10.1.1.10 255.255.255.255
    next
end
config firewall addrgrp
    edit "grp"
        set member "HST-EPFR-DMZ-WEB-01"
    next
end
"""
    resultat = auditer(lire_fortigate(texte, "memoire"), contextes)
    assert [(item.ancien, item.nouveau) for item in resultat.renommages] == [
        ("HST-EPFR-DMZ-WEB-01", "HST-CTX-DMZ-WEB-01"),
    ]
    assert resultat.referentiel == "aucun (sites en CTX)"
