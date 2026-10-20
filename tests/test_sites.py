
import pytest

from fwclean.audit import auditer
from fwclean.fortigate import lire_fortigate
from fwclean.model import ErreurLecture, Inventaire, Objet
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


def _localisateur(objets, referentiel):
    inventaire = Inventaire(constructeur="fortigate", sources=("memoire",), objets=tuple(objets))
    return Localisateur(inventaire, referentiel), inventaire


def test_lecture_du_referentiel(referentiel):
    assert referentiel.sites == ("gras", "siege")
    assert len(referentiel.entrees) == 7
    assert referentiel.interfaces == ("dmz", "gras-210", "lan-users", "serveurs", "srv", "vpn-ssl", "wan")
    vpn = next(entree for entree in referentiel.entrees if entree.interface == "VPN_SSL")
    assert vpn.cle_interface == "vpn-ssl"
    texte = "# commentaire\nRESEAU;Site;Zone;Vlan;Interface\n10.0.0.0/8;SIEGE;LAN;;Cabines   # casse tolérée\n"
    lu = analyser_reseaux(texte)
    assert lu.entrees[0].site == "siege"
    assert lu.entrees[0].interface == "Cabines"


def test_ancien_format_tolere_sans_interface():
    """Anciens fichiers avec colonne zone : lus, zone ignorée (même inconnue), sans interface."""
    texte = (
        "reseau;site;zone;vlan\n"
        "10.0.0.0/24;hq;oob;\n"
        "10.1.0.0/24;hq;lan;11\n"
        "reseau;site;zone;vlan   # en-tête répété (bloc collé)\n"
        "10.211.0.0/24;th;srv;11\n"
    )
    lu = analyser_reseaux(texte)
    assert [(entree.vlan, entree.interface) for entree in lu.entrees] == [(None, None), (11, None), (11, None)]
    assert lu.interfaces == ()
    assert "3 sans interface" in lu.decrire()
    mixte = "reseau;site;zone;vlan;interface\n10.0.0.0/24;hq;lan;10;VLAN-10\n10.211.0.0/24;th;corp-wifi;20\n"
    assert [entree.interface for entree in analyser_reseaux(mixte).entrees] == ["VLAN-10", None]


@pytest.mark.parametrize(
    "texte",
    [
        "reseau,site,zone\n10.0.0.0/8,siege,lan\n",
        "reseau;site;zone\n10.0.0.0/33;siege;lan\n",
        "reseau;site;zone;vlan;interface\n10.0.0.0/8;siege;;;multi\n",
        "reseau;site;zone;vlan;interface\n10.0.0.0/8;siege;;;--\n",
        "reseau;site;zone;vlan;interface\n10.0.0.0/8;siege;;;X;Y\n",
        "reseau;site;zone\n10.0.0.0/8;ctx;lan\n",
        "reseau;site;zone\n10.0.0.0/8;ep-fr;lan\n",
        "reseau;site;vlan;interface\n10.0.0.0/8\n",
        "reseau;site;vlan;interface\n10.0.0.0/8;siege;0;X\n",
        "reseau;site;zone\n10.0.0.0/8;siege;lan\n10.0.0.0/8;gras;lan\n",
        "reseau;site;zone;vlan;interface\n10.0.0.0/8;siege;;;A\n10.0.0.0/8;siege;;;B\n",
    ],
)
def test_referentiel_invalide(texte):
    with pytest.raises(ErreurLecture):
        analyser_reseaux(texte)


def test_zone_ignoree():
    ancien = analyser_reseaux("reseau;site;zone;vlan;interface\n10.0.0.0/24;hq;mgmt-ntk;10;MGMT\n")
    nouveau = analyser_reseaux("reseau;site;vlan;interface\n10.0.0.0/24;hq;10;MGMT\n")
    assert ancien.entrees == nouveau.entrees


def test_commun():
    assert commun(["siege", "siege"]) == "siege"
    assert commun(["siege", "ctx"]) == "siege"
    assert commun(["siege", "gras"]) == "multi"
    assert commun(["ctx"]) == "ctx"
    assert commun([]) == "ctx"


def test_site_et_interface_du_reseau_le_plus_precis(referentiel):
    loc, _ = _localisateur([], referentiel)
    assert loc.objet(_hote("zabbix_srv", "10.1.2.10")) == Localisation("siege", "serveurs")
    assert loc.objet(_hote("web", "10.1.1.10")) == Localisation("siege", "dmz")
    assert loc.objet(_reseau("Vlan210", "10.210.0.0", 24)) == Localisation("gras", "gras-210", 210, True)
    assert loc.objet(_reseau("tout_siege", "10.1.0.0", 16)) == Localisation("siege", "serveurs", None, True)
    assert loc.objet(_reseau("esx", "10.1.2.0", 25)) == Localisation("siege", "serveurs", None, False)
    assert loc.objet(_reseau("lan", "10.0.0.0", 24)) == Localisation("siege", "lan-users", 10, True)


def test_reseau_stormshield_sans_zone(referentiel):
    inventaire = Inventaire(constructeur="stormshield", sources=(), objets=())
    loc = Localisateur(inventaire, referentiel)
    assert loc.objet(_reseau("lan", "10.0.0.0", 24)) == Localisation("siege", "lan-users", 10, True)


def test_hors_referentiel_ou_sans_interface(referentiel):
    loc, _ = _localisateur([], referentiel)
    assert loc.objet(_hote("srv_dmz_tiers", "192.0.2.50")) == Localisation("ctx", "ctx")
    assert loc.objet(_reseau("SIEGE_NET_LAN_LARGE", "10.0.0.0", 8)) == Localisation("ctx", "ctx")
    ancien = analyser_reseaux("reseau;site;zone;vlan\n10.0.0.0/24;hq;lan;10\n")
    loc, _ = _localisateur([], ancien)
    assert loc.objet(_hote("pc", "10.0.0.5")) == Localisation("hq", "ctx")
    assert loc.objet(_reseau("lan", "10.0.0.0", 24)) == Localisation("hq", "ctx", 10, True)


def test_plage_pool_vip_et_fqdn(referentiel):
    plage = Objet(sorte="plage", nom="p", empreinte=("v4", "10.8.0.1", "10.8.0.200"), detail="")
    a_cheval = Objet(sorte="plage", nom="q_lan", empreinte=("v4", "10.0.0.250", "10.1.1.5"), detail="")
    pool_a_cheval = Objet(sorte="pool", nom="q", empreinte=("10.0.0.250", "10.1.1.5"), detail="")
    pool = Objet(sorte="pool", nom="nat", empreinte=("203.0.113.20", "203.0.113.30"), detail="")
    web = _hote("SIEGE_HST_DMZ_WEB-01", "10.1.1.10")
    vip = Objet(
        sorte="vip",
        nom="vip_web",
        empreinte=("vip", "203.0.113.10", "SIEGE_HST_DMZ_WEB-01", "", "", ""),
        detail="",
        mentions_adresses=("SIEGE_HST_DMZ_WEB-01",),
    )
    vip_interne = Objet(
        sorte="vip", nom="vip_lan", empreinte=("vip", "198.51.100.1", "10.1.2.5", "", "", ""), detail=""
    )
    vip_inconnue = Objet(
        sorte="vip", nom="vip_lan_x", empreinte=("vip", "203.0.113.11", "192.0.2.5", "", "", ""), detail=""
    )
    fqdn = Objet(sorte="fqdn", nom="gras_srv_maj", empreinte=("fqdn", "maj.example.com"), detail="")
    loc, _ = _localisateur([web, vip], referentiel)
    assert loc.objet(plage) == Localisation("siege", "vpn-ssl")
    assert loc.objet(a_cheval) == Localisation("ctx", "ctx")
    assert loc.objet(pool_a_cheval) == Localisation("siege", "multi")
    assert loc.objet(pool) == Localisation("siege", "wan")
    # VIP : interface de l'adresse interne seule, jamais de l'IP externe ni du nom.
    assert loc.objet(vip) == Localisation("siege", "dmz")
    assert loc.objet(vip_interne) == Localisation("siege", "serveurs")
    assert loc.objet(vip_inconnue) == Localisation("ctx", "ctx")
    assert loc.objet(fqdn) == Localisation("gras", "srv")


def test_groupe_multi_et_groupe_commun(referentiel):
    objets = [
        _hote("a", "10.1.2.10"),
        _hote("b", "10.1.2.11"),
        _hote("c", "10.1.1.12"),
        _reseau("Vlan210", "10.210.0.0", 24),
        _hote("dehors", "192.0.2.9"),
        _groupe("meme_interface", "a", "b", "dehors"),
        _groupe("deux_interfaces", "a", "c"),
        _groupe("deux_sites", "a", "Vlan210"),
        _groupe("imbrique", "meme_interface", "deux_sites"),
        _groupe("inconnus_dmz", "dehors"),
    ]
    loc, _ = _localisateur(objets, referentiel)
    par_nom = {objet.nom: objet for objet in objets}
    assert loc.objet(par_nom["meme_interface"]) == Localisation("siege", "serveurs")
    assert loc.objet(par_nom["deux_interfaces"]) == Localisation("siege", "multi")
    assert loc.objet(par_nom["deux_sites"]) == Localisation("multi", "multi")
    assert loc.objet(par_nom["imbrique"]) == Localisation("multi", "multi")
    assert loc.objet(par_nom["inconnus_dmz"]) == Localisation("ctx", "dmz")


def test_groupe_cyclique_ne_boucle_pas(referentiel):
    objets = [_groupe("x", "y"), _groupe("y", "x")]
    loc, _ = _localisateur(objets, referentiel)
    assert loc.objet(objets[0]) == Localisation("ctx", "ctx")


def test_audit_propose_site_et_interface(referentiel):
    texte = """
config firewall address
    edit "zabbix_srv"
        set subnet 10.1.2.10 255.255.255.255
    next
    edit "SIEGE_HST_DMZ_WEB-01"
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
        set dstaddr "SIEGE_HST_DMZ_WEB-01" "partenaire"
        set action accept
        set service "SVC_TCP_10050"
    next
end
"""
    resultat = auditer(lire_fortigate(texte, "memoire"), referentiel)
    assert [(item.ancien, item.nouveau) for item in resultat.renommages] == [
        ("zabbix_srv", "SIEGE_HST_SERVEURS_ZABBIX-SRV"),
    ]
    a_revoir = {item.nom: item for item in resultat.non_conformes if item.traitement == "revoir"}
    assert a_revoir["partenaire"].nom_propose is None
    assert a_revoir["partenaire"].commentaire == (
        "site et interface introuvables : adresse absente de reseaux.csv"
    )
    assert all(item.sorte != "regle" for item in resultat.non_conformes)
    assert "sites : GRAS, SIEGE" in resultat.referentiel


def test_audit_ancien_format_a_revoir():
    texte = """
config firewall address
    edit "pc01"
        set subnet 10.0.0.5 255.255.255.255
    next
    edit "Res-LAN"
        set subnet 10.0.0.0 255.255.255.0
    next
end
config firewall addrgrp
    edit "postes"
        set member "pc01"
    next
end
config firewall policy
    edit 1
        set srcaddr "postes"
        set dstaddr "Res-LAN"
        set action accept
        set service "ALL"
    next
end
"""
    ancien = analyser_reseaux("reseau;site;zone;vlan\n10.0.0.0/24;hq;lan;10\n")
    resultat = auditer(lire_fortigate(texte, "memoire"), ancien)
    assert resultat.renommages == ()
    revoir = {item.nom: item.commentaire for item in resultat.non_conformes if item.traitement == "revoir"}
    attendu = (
        "interface introuvable : réseau de reseaux.csv sans colonne interface "
        "(vide ou ancien format à 4 colonnes)"
    )
    assert revoir["pc01"] == attendu
    assert revoir["Res-LAN"] == attendu
    assert revoir["postes"] == "interface introuvable : aucun membre sur une interface connue"


def test_audit_sans_referentiel():
    texte = """
config firewall address
    edit "SIEGE_HST_DMZ_WEB-01"
        set subnet 10.1.1.10 255.255.255.255
    next
end
config firewall addrgrp
    edit "grp"
        set member "SIEGE_HST_DMZ_WEB-01"
    next
end
"""
    resultat = auditer(lire_fortigate(texte, "memoire"))
    assert resultat.renommages == ()
    item = next(item for item in resultat.non_conformes if item.nom == "SIEGE_HST_DMZ_WEB-01")
    assert item.traitement == "revoir"
    assert item.commentaire == "site et interface introuvables : adresse absente de reseaux.csv"
    assert resultat.referentiel == "aucun : objets à adresse IP signalés à revoir"
