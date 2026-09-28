import json
import shutil

import pytest

from fwclean.audit import auditer
from fwclean.charger import charger
from fwclean.cli import executer
from fwclean.model import ErreurLecture, Inventaire, Objet
from fwclean.naming import analyser_contextes, cle_correspondance
from fwclean.reseaux import ecrire_reseaux, reseaux_sns
from fwclean.sites import analyser_reseaux, appliquer_vlans
from fwclean.stormshield_natif import (
    genre_natif,
    lire_filtre_natif,
    lire_objets_natifs,
    lire_routes_natives,
    vlans_natifs,
)

OBJETS = """
[Network]
lan=10.0.0.0/255.255.255.0   # masque pointé
lan_bis=10.0.0.0/24
doc_v6=2001:db8::/32
casse=pas-une-adresse

[Service]
web=443/tcp
dns=53/any
appli=2000 - 2032/tcp
maj=16004/TCP

[Protocol]
gre=47

[Internet]
operator=ne

[Fqdn]
maj.example.com=203.0.113.5

[Host]
srv=10.0.0.10,resolve=static   # commentaire
double=10.0.0.20,2001:db8::20
dyn.example.org=203.0.113.50,resolve=dynamic
poste=10.0.0.30,resolve=static,mac=00:11:22:33:44:55
mac_seule=00:11:22:33:44:66
plage_mac=00:11:22:33:44:00-00:11:22:33:44:ff
plage=10.0.0.100-10.0.0.200
"""


def test_objets_natifs():
    objets, ignores = lire_objets_natifs(OBJETS)
    par_nom = {objet.nom: objet for objet in objets}
    assert par_nom["lan"].empreinte == par_nom["lan_bis"].empreinte == (("v4", "10.0.0.0", 24),)
    assert par_nom["doc_v6"].empreinte == (("v6", "2001:db8::", 32),)
    assert {protocole for protocole, _plages in par_nom["dns"].empreinte} == {"tcp", "udp"}
    assert par_nom["appli"].empreinte == (("tcp", ((2000, 2032, -1, -1),)),)
    assert par_nom["maj"].empreinte == (("tcp", ((16004, 16004, -1, -1),)),)
    assert par_nom["gre"].sorte == "protocole"
    assert par_nom["srv"].sorte == "hote" and par_nom["srv"].empreinte == (("v4", "10.0.0.10", 32),)
    assert len(par_nom["double"].empreinte) == 2
    assert par_nom["poste"].empreinte == (("v4", "10.0.0.30", 32),)
    assert par_nom["plage"].sorte == "plage" and par_nom["plage"].empreinte == ("v4", "10.0.0.100", "10.0.0.200")
    for nom in ("dyn.example.org", "maj.example.com"):
        assert par_nom[nom].sorte == "fqdn" and par_nom[nom].fige
    assert {"mac_seule", "plage_mac", "casse", "operator"}.isdisjoint(par_nom)
    assert [ignore.split(" ")[0] for ignore in ignores] == ["casse", "mac_seule", "plage_mac"]


FILTRE = """
[NAT]
separator color="c0c0c0" comment="NAT # sortant" collapse="0"
nat from lan to internet on out -> from Firewall_out arp port ephemeral_fw to original rulename "n1"
off nat from any to pub port web -> from any to srv port web_interne rulename "n2"

[Filter]
off pass from srv to any port web rulename "a"   # désactivée
pass inspection log route gw from lan|!double on in to internet port web|dns rulename "b"
block from user=jdupont@plage via ipsec to srv ipproto gre rulename "c"
reset from any to any
"""


def test_filtre_natif():
    regles, liens = lire_filtre_natif(FILTRE)
    par_nom = {regle.nom: regle for regle in regles}
    assert list(par_nom) == ["a", "b", "c", "filter-4"]
    assert par_nom["a"].active is False and par_nom["a"].destinations == ()
    assert par_nom["b"].sources == ("lan", "double")
    assert par_nom["b"].interfaces_source == ("in",)
    assert par_nom["b"].services == ("web", "dns")
    assert par_nom["c"].action == "deny" and par_nom["c"].sources == ("plage",)
    assert par_nom["c"].protocoles == ("gre",)
    assert par_nom["filter-4"].action == "deny"
    par_origine = {lien.origine: lien for lien in liens}
    assert par_origine["nat n1"].adresses == ("lan", "Firewall_out")
    assert par_origine["nat n1"].services == ("ephemeral_fw",)
    assert par_origine["nat n2"].adresses == ("pub", "srv")
    assert par_origine["nat n2"].services == ("web", "web_interne")
    assert par_origine["routage de b"].adresses == ("gw",)


def test_routes_natives():
    liens = lire_routes_natives(
        """
[Config]
DefaultRoute=Routeur_Principal

[StaticRoutes]
distant,in->gw_lan
off lan,in->gw_lan   # désactivée
192.168.99.0/24,in->10.0.0.1

[ReverseRoutes]
inverse,in->gw_inverse
"""
    )
    assert [(lien.origine, lien.adresses) for lien in liens] == [
        ("route par défaut", ("Routeur_Principal",)),
        ("route 1", ("distant", "gw_lan")),
        ("route 2", ("lan", "gw_lan")),
        ("route 3", ()),
    ]


NETWORK = """
[ethernet0]
State=1
Name=out
Address=203.0.113.2
Mask=255.255.255.0
Address1=198.51.100.2
Mask1=24

[vlan0]
State=1
Physical=ethernet1
Tag=10
Name=LAN
Address=10.0.0.254
Mask=24

[vlan1]
State=0
Physical=ethernet1
Tag=11
Name=Admin
Address=dhcp

[loopback0]
Name=loopback
Address=127.0.0.1
Mask=255.0.0.0

[Config]
MaxBridges=4
"""


def test_vlans_et_genres():
    assert [(str(reseau), tag) for reseau, tag in vlans_natifs(NETWORK)] == [("10.0.0.0/24", 10)]
    assert genre_natif("Network", "") == "network"
    assert genre_natif("OBJECT", "") == "object"
    assert genre_natif("router", "") == "router"
    assert genre_natif("03", "# slot\n[Filter]\npass from any to any\n") == "filter"
    assert genre_natif("x", NETWORK) == "network"
    assert genre_natif("x", OBJETS) == "object"
    assert genre_natif("objets.csv", "host,a,10.0.0.1") is None


def test_exemple_natif_retraits_suspendus(racine, contextes, referentiel):
    inventaire = charger([racine / "examples" / "stormshield-natif"])
    resultat = auditer(inventaire, contextes, referentiel)
    assert inventaire.constructeur == "stormshield"
    assert len(inventaire.regles) == 7
    assert "router" in inventaire.retraits_suspendus
    assert resultat.retraits == ()
    assert inventaire.non_definis == ("Routeur_Principal", "global_SRV_PROXY", "mail")
    renommages = {(item.sorte, item.ancien): item.nouveau for item in resultat.renommages}
    assert renommages[("reseau", "Res-VLAN10")] == "NET_SIEGE_LAN_VLAN10-RES"
    assert renommages[("reseau", "Res-DMZ")] == "NET_SIEGE_DMZ_VLAN66-RES"
    assert renommages[("hote", "srv_web")] == "HST_SIEGE_DMZ_SRV-WEB"
    assert renommages[("protocole", "rdp")] == "SVC_IP_27_RDP"
    assert renommages[("service", "rdp")] == "SVC_TCP_3389_RDP"
    assert renommages[("service", "dns_any")] == "SVC_ANY_53_DNS"
    assert ("hote", "srv-oublie") not in renommages
    revoir = {item.nom: item.commentaire for item in resultat.non_conformes if item.traitement == "revoir"}
    assert "resolve=dynamic" in revoir["mirror.example.org"]
    assert "FQDN" in revoir["updates.example.com"]
    fusions = {(item.sorte, item.conserve): item.supprimes for item in resultat.fusions}
    assert fusions[("hote", "srv_web")] == ("Web_DMZ",)
    assert fusions[("service", "SVC_TCP_443_HTTPS")] == ("https_ep",)


def test_router_vide_debloque_les_retraits(racine, tmp_path, contextes, referentiel):
    dossier = tmp_path / "sns"
    shutil.copytree(racine / "examples" / "stormshield-natif", dossier)
    (dossier / "router").write_text("", encoding="utf-8")
    resultat = auditer(charger([dossier]), contextes, referentiel)
    assert resultat.inventaire.retraits_suspendus is None
    assert [(item.sorte, item.nom) for item in resultat.retraits] == [
        ("groupe-adresses", "grp_oublie"),
        ("protocole", "rdp"),
        ("reseau", "IANA_v6_doc"),
    ]
    (dossier / "router").write_text("[Routeur_Principal]\ngw=passerelle_wan\n", encoding="utf-8")
    inventaire = charger([dossier])
    assert "router" in inventaire.retraits_suspendus
    assert any("non lus" in message and "router" in message for message in inventaire.avertissements)


def test_slots_filter_et_dossier_global(racine, tmp_path):
    dossier = tmp_path / "sns"
    dossier.mkdir()
    shutil.copy(racine / "examples" / "stormshield-natif" / "object", dossier / "object")
    (dossier / "Filter").mkdir()
    (dossier / "Filter" / "01").write_text('[Filter]\npass from srv_web to any rulename "r1"\n', encoding="utf-8")
    (dossier / "Filter" / "02").write_text('[Filter]\npass from Web_DMZ to any rulename "r1"\n', encoding="utf-8")
    (dossier / "Filter" / "03").write_text("", encoding="utf-8")
    (dossier / "global").mkdir()
    inventaire = charger([dossier])
    assert sorted(regle.nom for regle in inventaire.regles) == ["01:r1", "02:r1"]
    assert any("global/" in source for source in inventaire.sources)
    assert "objectgroup, servicegroup, router" in inventaire.retraits_suspendus


def test_melanges_refuses(racine):
    natif = racine / "examples" / "stormshield-natif" / "object"
    with pytest.raises(ErreurLecture, match="mélangés"):
        charger([natif, racine / "examples" / "stormshield" / "objets.csv"])
    with pytest.raises(ErreurLecture, match="seul constructeur"):
        charger([natif, racine / "examples" / "fortigate" / "nomenclature.conf"])


def test_vlan_par_le_referentiel(racine, contextes):
    referentiel = analyser_reseaux(
        "reseau;site;zone;vlan\n"
        "10.0.0.0/24;siege;lan;99\n"
        "10.1.0.0/16;siege;lan;100\n"
        "10.1.1.0/24;siege;dmz;\n"
        "10.210.0.0/24;gras;lan;210\n"
        "203.0.113.0/24;siege;wan\n",
        contextes,
    )
    assert {str(entree.reseau): entree.vlan for entree in referentiel.entrees}["203.0.113.0/24"] is None
    resultat = auditer(charger([racine / "examples" / "stormshield-natif"]), contextes, referentiel)
    renommages = {item.ancien: item.nouveau for item in resultat.renommages}
    assert renommages["Reseau_Gras"] == "NET_GRAS_LAN_VLAN210-RESEAU"
    # Le VLAN de l'interface SNS prime sur le référentiel.
    assert renommages["Res-VLAN10"] == "NET_SIEGE_LAN_VLAN10-RES"
    assert renommages["Res-DMZ"] == "NET_SIEGE_DMZ_VLAN66-RES"


def test_vlan_absent_de_l_entree_la_plus_precise(contextes):
    referentiel = analyser_reseaux(
        "reseau;site;zone;vlan\n10.1.0.0/16;siege;lan;100\n10.1.1.0/24;siege;dmz;\n10.1.2.0/24;siege;lan\n",
        contextes,
    )
    inventaire = Inventaire(
        constructeur="stormshield",
        sources=(),
        objets=(
            Objet(sorte="reseau", nom="a", empreinte=(("v4", "10.1.1.0", 25),), detail=""),
            Objet(sorte="reseau", nom="b", empreinte=(("v4", "10.1.9.0", 24),), detail=""),
            Objet(sorte="reseau", nom="c", empreinte=("v4", "10.1.9.0", 24), detail=""),
        ),
    )
    assert [objet.vlan for objet in appliquer_vlans(inventaire, referentiel).objets] == [None, 100, 100]


@pytest.mark.parametrize(
    "texte",
    [
        "reseau;site;zone;vlan\n10.0.0.0/24;siege;lan;abc\n",
        "reseau;site;zone;vlan\n10.0.0.0/24;siege;lan;5000\n",
        "reseau;site;zone;vlan\n10.0.0.0/24;siege;lan;10\n10.0.0.0/24;siege;lan;11\n",
        "reseau;site;zone\n10.0.0.0/24;siege;lan;10\n",
        "reseau;site;zone;vlan;x\n",
    ],
)
def test_colonne_vlan_invalide(contextes, texte):
    with pytest.raises(ErreurLecture):
        analyser_reseaux(texte, contextes)


def test_reseaux_sns():
    zones = analyser_contextes("lan\nwan\nadmin\n")
    correspondances = {cle_correspondance("out"): "wan"}
    lignes = reseaux_sns(NETWORK, zones, correspondances)
    assert [(ligne.reseau, ligne.interface, ligne.zone, ligne.vlan) for ligne in lignes] == [
        ("203.0.113.0/24", "out", "wan", None),
        ("198.51.100.0/24", "out", "wan", None),
        ("10.0.0.0/24", "LAN", "lan", 10),
    ]
    texte = ecrire_reseaux(lignes, "siege", "Network", zones, "stormshield")
    assert "10.0.0.0/24;siege;lan;10  # LAN (vlan0)" in texte
    assert "203.0.113.0/24;siege;wan;  # out (ethernet0)" in texte
    assert "127.0.0.0" not in texte


def test_commande_reseaux_sns(racine, tmp_path, capsys, monkeypatch):
    shutil.copy(racine / "contextes.txt", tmp_path / "contextes.txt")
    monkeypatch.chdir(tmp_path)
    assert executer(["reseaux", str(racine / "examples" / "stormshield-natif"), "--site", "siege"]) == 0
    sortie = capsys.readouterr().out
    assert "à compléter : 203.0.113.0/24 (out)" in sortie
    assert "Interfaces désactivées, laissées en commentaire : 1." in sortie
    texte = (tmp_path / "reseaux.csv").read_text(encoding="utf-8")
    assert "10.0.0.0/24;siege;lan;10  # LAN (vlan0)" in texte
    assert "# 10.1.1.0/24;siege;dmz;66  — DMZ (vlan1) : interface désactivée" in texte
    assert executer(["reseaux", str(tmp_path), "--site", "siege", "--ecraser"]) == 2
    assert "aucun fichier Network" in capsys.readouterr().err


def test_audit_cli_natif(racine, tmp_path, capsys):
    sortie = tmp_path / "out"
    code = executer(
        [
            "audit",
            str(racine / "examples" / "stormshield-natif"),
            "--sortie",
            str(sortie),
            "--contextes",
            str(racine / "contextes.txt"),
            "--reseaux",
            str(racine / "reseaux.exemple.csv"),
        ]
    )
    assert code == 0
    assert "orphelins : suspendus" in capsys.readouterr().out
    plan = json.loads((sortie / "plan.json").read_text(encoding="utf-8"))
    assert plan["retraits"] == []
    assert "router" in plan["avertissements"]["retraits_suspendus"]
    assert plan["avertissements"]["noms_non_definis"] == ["Routeur_Principal", "global_SRV_PROXY", "mail"]
    rapport = (sortie / "rapport.md").read_text(encoding="utf-8")
    assert "## Avertissements" in rapport and "`global_SRV_PROXY`" in rapport
    assert "| Orphelins | suspendus |" in rapport
    assert "Retraits suspendus : fichier router non lu" in rapport
