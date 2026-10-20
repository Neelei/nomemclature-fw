import json
import shutil
from dataclasses import replace

import pytest

from fwclean.audit import auditer
from fwclean.charger import charger
from fwclean.cli import executer
from fwclean.model import ErreurLecture
from fwclean.report import plan_dict
from fwclean.reseaux import completer_reseaux, ecrire_reseaux, reseaux_sns
from fwclean.sites import analyser_reseaux
from fwclean.stormshield_natif import (
    AVERTISSEMENT_NON_GERES,
    AVERTISSEMENT_ROUTEURS,
    VERIFIER_USAGE,
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
Address2=198.51.100.3
Mask2=255.255.255.0

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


def test_exemple_natif(racine, referentiel):
    inventaire = charger([racine / "examples" / "stormshield-natif"])
    resultat = auditer(inventaire, referentiel)
    assert inventaire.constructeur == "stormshield"
    assert len(inventaire.regles) == 11
    assert inventaire.retraits_suspendus is None
    assert [(item.sorte, item.nom) for item in resultat.retraits] == [
        ("groupe-adresses", "grp_oublie"),
        ("protocole", "esp_ancien"),
    ]
    assert AVERTISSEMENT_ROUTEURS in inventaire.avertissements
    assert AVERTISSEMENT_NON_GERES not in inventaire.avertissements
    assert VERIFIER_USAGE in inventaire.avertissements
    assert inventaire.non_definis == ("Routeur_Principal", "global_SRV_PROXY", "mail")
    renommages = {(item.sorte, item.ancien): item.nouveau for item in resultat.renommages}
    # SNS : pas de segment zone ; VLAN et interface viennent de reseaux.csv.
    assert renommages[("reseau", "Res-DMZ")] == "SIEGE_NET_DMZ"
    assert renommages[("reseau", "Reseau_Gras")] == "GRAS_NET_V210_GRAS-210"
    assert renommages[("hote", "passerelle_wan")] == "SIEGE_HST_WAN_PASSERELLE"
    assert renommages[("plage", "Plage_VPN")] == "SIEGE_RNG_VPN-SSL_PLAGE-VPN"
    assert renommages[("hote", "srv_web")] == "SIEGE_HST_DMZ_SRV-WEB"
    assert renommages[("protocole", "gre_tunnel")] == "SVC_IP_47_GRE-TUNNEL"
    natifs = {(objet.sorte, objet.nom) for objet in resultat.natifs}
    assert natifs == {
        ("reseau", "IANA_v6_doc"),
        ("service", "syslog"),
        ("service", "rdp"),
        ("protocole", "rdp"),
        ("groupe-services", "web"),
    }
    assert not natifs & set(renommages)
    assert not natifs & {(item.sorte, item.nom) for item in resultat.non_conformes}
    assert renommages[("service", "dns_any")] == "SVC_ANY_53_DNS"
    assert ("hote", "srv-oublie") not in renommages
    revoir = {item.nom: item.commentaire for item in resultat.non_conformes if item.traitement == "revoir"}
    assert "resolve=dynamic" in revoir["mirror.example.org"]
    assert "FQDN" in revoir["updates.example.com"]
    fusions = {(item.sorte, item.conserve): item.supprimes for item in resultat.fusions}
    assert fusions[("hote", "srv_web")] == ("Web_DMZ",)
    assert fusions[("reseau", "SIEGE_NET_V10_LAN-USERS")] == ("Res-VLAN10",)
    assert fusions[("service", "SVC_TCP_443_HTTPS")] == ("https_ep",)
    assert fusions[("service", "rdp")] == ("rdp_admin",)


def test_groupes_absents_suspendent_les_retraits(racine, tmp_path, referentiel):
    dossier = tmp_path / "sns"
    shutil.copytree(racine / "examples" / "stormshield-natif", dossier)
    (dossier / "router").write_text("[Routeur_Principal]\ngw=passerelle_wan\n", encoding="utf-8")
    (dossier / "global").mkdir()
    inventaire = charger([dossier])
    assert inventaire.retraits_suspendus is None
    assert any("non lus (non gérés)" in message and "router" in message for message in inventaire.avertissements)
    (dossier / "servicegroup").unlink()
    resultat = auditer(charger([dossier]), referentiel)
    assert resultat.inventaire.retraits_suspendus.startswith("fichier servicegroup non lu")
    assert resultat.retraits == ()
    assert VERIFIER_USAGE not in resultat.inventaire.avertissements


def test_slots_filter_et_dossier_global(racine, tmp_path):
    dossier = tmp_path / "sns"
    dossier.mkdir()
    shutil.copy(racine / "examples" / "stormshield-natif" / "object", dossier / "object")
    (dossier / "Filter").mkdir()
    (dossier / "Filter" / "01").write_text('[Filter]\npass from srv_web to any rulename "r1"\n', encoding="utf-8")
    (dossier / "Filter" / "02").write_text('[Filter]\npass from Web_DMZ to any rulename "r1"\n', encoding="utf-8")
    (dossier / "Filter" / "03").write_text("", encoding="utf-8")
    (dossier / "global").mkdir()
    (dossier / "global" / "router").write_text("[r]\n", encoding="utf-8")
    inventaire = charger([dossier])
    assert sorted(regle.nom for regle in inventaire.regles) == ["01:r1", "02:r1"]
    assert any(source.endswith("global/router") for source in inventaire.sources)
    assert "objectgroup, servicegroup non lus" in inventaire.retraits_suspendus


def test_melanges_refuses(racine):
    natif = racine / "examples" / "stormshield-natif" / "object"
    with pytest.raises(ErreurLecture, match="mélangés"):
        charger([natif, racine / "examples" / "stormshield" / "objets.csv"])
    with pytest.raises(ErreurLecture, match="seul constructeur"):
        charger([natif, racine / "examples" / "fortigate" / "nomenclature.conf"])


def test_vlan_et_interface_par_le_referentiel(racine):
    referentiel = analyser_reseaux(
        "reseau;site;vlan;interface\n"
        "10.0.0.0/24;siege;99;LAN\n"
        "10.1.0.0/16;siege;100;SERVEURS\n"
        "10.1.1.0/24;siege;;DMZ\n"
        "10.210.0.0/24;gras;210;SRV_GRAS\n"
        "203.0.113.0/24;siege;;out\n"
    )
    assert {str(entree.reseau): entree.vlan for entree in referentiel.entrees}["203.0.113.0/24"] is None
    resultat = auditer(charger([racine / "examples" / "stormshield-natif"]), referentiel)
    renommages = {item.ancien: item.nouveau for item in resultat.renommages}
    assert renommages["Reseau_Gras"] == "GRAS_NET_V210_SRV-GRAS"
    # Le VLAN est celui de la ligne de reseaux.csv, pas le Tag de l'interface SNS (66 ici).
    assert renommages["Res-DMZ"] == "SIEGE_NET_DMZ"
    assert "SIEGE_NET_V99_LAN" in {fusion.nouveau_nom for fusion in resultat.fusions}


@pytest.mark.parametrize(
    "texte",
    [
        "reseau;site;zone;vlan\n10.0.0.0/24;siege;lan;abc\n",
        "reseau;site;zone;vlan\n10.0.0.0/24;siege;lan;5000\n",
        "reseau;site;zone;vlan\n10.0.0.0/24;siege;lan;10\n10.0.0.0/24;siege;lan;11\n",
        "reseau;site;zone\n10.0.0.0/24;siege;lan;10\n",
        "reseau;site;vlan;interface\n10.0.0.0/24;siege;10;LAN;X\n",
        "reseau;site;zone;vlan;x\n",
        "reseau;site;zone;vlan;interface;x\n",
    ],
)
def test_colonne_vlan_invalide(texte):
    with pytest.raises(ErreurLecture):
        analyser_reseaux(texte)


def test_reseaux_sns():
    lignes = reseaux_sns(NETWORK)
    assert [(ligne.reseau, ligne.interface, ligne.vlan) for ligne in lignes] == [
        ("203.0.113.0/24", "out", None),
        ("198.51.100.0/24", "out", None),
        ("10.0.0.0/24", "LAN", 10),
    ]
    texte = ecrire_reseaux(lignes, "siege", "Network", "stormshield")
    assert "reseau;site;vlan;interface" in texte
    assert "10.0.0.0/24;siege;10;LAN  # LAN (vlan0)" in texte
    assert "203.0.113.0/24;siege;;out  # out (ethernet0)" in texte
    assert "127.0.0.0" not in texte


def test_commande_reseaux_sns(racine, tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert executer(["reseaux", str(racine / "examples" / "stormshield-natif"), "--site", "siege"]) == 0
    sortie = capsys.readouterr().out
    assert "Réseaux connectés : 3." in sortie
    assert "Interfaces désactivées, laissées en commentaire : 1." in sortie
    texte = (tmp_path / "reseaux.csv").read_text(encoding="utf-8")
    assert "10.0.0.0/24;siege;10;LAN  # LAN (vlan0)" in texte
    assert "203.0.113.0/24;siege;;out  # out (ethernet0)" in texte
    assert "# 10.1.1.0/24;siege;66;DMZ  — DMZ (vlan1) : interface désactivée" in texte
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
            "--reseaux",
            str(racine / "reseaux.exemple.csv"),
        ]
    )
    assert code == 0
    console = capsys.readouterr().out
    assert "orphelins : 2." in console
    assert "Objets natifs SNS ignorés : 5." in console
    plan = json.loads((sortie / "plan.json").read_text(encoding="utf-8"))
    assert [item["nom"] for item in plan["retraits"]] == ["grp_oublie", "esp_ancien"]
    assert plan["avertissements"]["retraits_suspendus"] is None
    assert plan["avertissements"]["noms_non_definis"] == ["Routeur_Principal", "global_SRV_PROXY", "mail"]
    rapport = (sortie / "rapport.md").read_text(encoding="utf-8")
    assert "## Avertissements" in rapport and "`global_SRV_PROXY`" in rapport
    assert "Objets routeur non lus" in rapport
    assert "## Objets globaux SMC" in rapport
    assert "| Orphelins | 2 |" in rapport
    assert "| Objets natifs SNS ignorés | 5 |" in rapport
    assert "## Objets natifs SNS ignorés" in rapport
    assert {"sorte": "reseau", "nom": "IANA_v6_doc"} in plan["natifs_ignores"]
    assert "**À vérifier avant chaque suppression** : « Vérifier l'utilisation »" in rapport


def test_reseaux_ajouter_migre_l_ancien_format(racine, tmp_path, capsys, monkeypatch):
    existant = (
        "# Référentiel relu à la main.\n"
        "reseau;site;zone;vlan\n"
        "10.210.0.0/24;gras;lan;  # site distant ajouté à la main\n"
        "203.0.113.0/24;siege;dmz;\n"
    )
    (tmp_path / "reseaux.csv").write_text(existant, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    source = str(racine / "examples" / "stormshield-natif")
    assert executer(["reseaux", source, "--site", "siege", "--ajouter"]) == 0
    sortie = capsys.readouterr().out
    texte = (tmp_path / "reseaux.csv").read_text(encoding="utf-8")
    assert texte.startswith(
        "# Référentiel relu à la main.\n"
        "reseau;site;vlan;interface\n"
        "10.210.0.0/24;gras;  # site distant ajouté à la main\n"
        "203.0.113.0/24;siege;;out  # out (ethernet0)\n"
    )
    assert texte.endswith("10.0.0.0/24;siege;10;LAN  # LAN (vlan0)\n")
    assert (
        "Ajoutés : 1, interface complétée : 1, alias appliqué : 0, déjà présents : 0, "
        "différents (non modifiés) : 0, "
        "écartés : 1."
    ) in sortie
    assert executer(["reseaux", source, "--site", "siege", "--ajouter"]) == 0
    assert "Ajoutés : 0, interface complétée : 0, alias appliqué : 0, déjà présents : 2" in capsys.readouterr().out
    assert (tmp_path / "reseaux.csv").read_text(encoding="utf-8") == texte
    with pytest.raises(SystemExit):
        executer(["reseaux", source, "--site", "siege", "--ajouter", "--ecraser"])
    assert executer(["reseaux", source, "--site", "siege"]) == 2
    assert "--ajouter" in capsys.readouterr().err


def test_reseaux_ajouter_ne_touche_pas_aux_lignes_renseignees():
    lignes = reseaux_sns(NETWORK)
    existant = (
        "reseau;site;vlan;interface\n"
        "203.0.113.0/24;siege;;WAN-PRINCIPAL   # renommé à la main\n"
        "10.0.0.0/24;gras;10\n"
    )
    completion = completer_reseaux(existant, lignes, "siege", "Network", "stormshield")
    assert completion.migrees == ()
    assert completion.differentes == (
        "203.0.113.0/24 : fichier siege;;WAN-PRINCIPAL, interface out (ethernet0) siege;;out",
        "10.0.0.0/24 : fichier gras;10;, interface LAN (vlan0) siege;10;LAN",
    )
    assert completion.texte.startswith(existant)
    assert "198.51.100.0/24;siege;;out" in completion.texte


def test_reseaux_ajouter_entete_sans_vlan():
    lignes = reseaux_sns(NETWORK)
    existant = "reseau;site;zone\n10.210.0.0/24;gras;lan\n"
    completion = completer_reseaux(existant, lignes, "siege", "Network", "stormshield")
    assert completion.texte.startswith("reseau;site;vlan;interface\n10.210.0.0/24;gras\n")
    assert "10.0.0.0/24;siege;10;LAN  # LAN (vlan0)" in completion.texte
    analyser_reseaux(completion.texte)


def test_reseaux_ajouter_vlan_absent_de_l_interface():
    lignes = reseaux_sns(NETWORK)
    existant = "reseau;site;vlan;interface\n10.0.0.0/24;siege;10;LAN\n"
    sans_tag = [replace(lignes[-1], vlan=None)]
    assert completer_reseaux(existant, sans_tag, "siege", "Network").presentes
    autre_tag = [replace(lignes[-1], vlan=11)]
    assert completer_reseaux(existant, autre_tag, "siege", "Network").differentes


def test_objets_globaux_lus(racine):
    inventaire = charger([racine / "examples" / "stormshield-natif"])
    globaux = {objet.nom: objet for objet in inventaire.objets if objet.globale}
    assert set(globaux) == {
        "global_SRV_WEB",
        "global_SRV_APPLI",
        "global_NAS_INCONNU",
        "global_PASSERELLE_SECOURS",
        "global_SRV_RETIRE",
        "global_LAN_USERS",
        "global_http_appli",
        "global_GRP_SERVEURS",
        "global_GRP_IMBRIQUE",
        "global_GRP_A_REVOIR",
        "global_WEB_APPLI",
    }
    assert globaux["global_GRP_IMBRIQUE"].mentions_adresses == ("global_GRP_SERVEURS", "global_LAN_USERS")
    assert not any(objet.globale for objet in inventaire.objets if not objet.nom.startswith("global_"))
    regles = {regle.nom: regle for regle in inventaire.regles}
    # « Global_X » et « global_X » ramenés au même nom canonique.
    assert regles["g1"].sources == ("global_GRP_IMBRIQUE",)
    assert regles["g1"].services_brutes == ("global_WEB_APPLI",)
    assert any("global_PASSERELLE_SECOURS" in lien.adresses for lien in inventaire.liens)
    # Global non fourni dans Global/object : reste non défini.
    assert "global_SRV_PROXY" in inventaire.non_definis


def test_plan_objets_globaux(racine, referentiel):
    resultat = auditer(charger([racine / "examples" / "stormshield-natif"]), referentiel)
    actions = {item.ancien: (item.action, item.nouveau) for item in resultat.globaux}
    assert actions["global_SRV_WEB"] == ("reutiliser", "SIEGE_HST_DMZ_SRV-WEB")
    assert actions["global_LAN_USERS"] == ("reutiliser", "SIEGE_NET_V10_LAN-USERS")
    assert actions["global_SRV_APPLI"] == ("creer", "SIEGE_HST_SERVEURS_SRV-APPLI")
    assert actions["global_http_appli"] == ("creer", "SVC_TCP_8080_HTTP-APPLI")
    assert actions["global_GRP_SERVEURS"] == ("creer", "SIEGE_GRP_MULTI_SERVEURS")
    assert actions["global_WEB_APPLI"] == ("creer", "SG_WEB-APPLI")
    assert actions["global_NAS_INCONNU"] == ("revoir", None)
    assert actions["global_GRP_A_REVOIR"] == ("revoir", None)
    assert actions["global_SRV_RETIRE"] == ("supprimer", None)
    imbrique = next(item for item in resultat.globaux if item.ancien == "global_GRP_IMBRIQUE")
    assert imbrique.membres == ("SIEGE_GRP_MULTI_SERVEURS", "SIEGE_NET_V10_LAN-USERS")
    ordre = [item.ancien for item in resultat.globaux]
    assert ordre.index("global_GRP_SERVEURS") < ordre.index("global_GRP_IMBRIQUE")
    # Les globaux ne sont ni renommés, ni fusionnés, ni retirés, ni signalés non conformes.
    touches = (
        {item.ancien for item in resultat.renommages}
        | {nom for fusion in resultat.fusions for nom in (fusion.conserve, *fusion.supprimes)}
        | {item.nom for item in resultat.retraits}
        | {item.nom for item in resultat.non_conformes}
    )
    assert not {nom for nom in touches if nom.startswith("global_")}
    plan = plan_dict(resultat)
    assert {"sorte": "hote", "ancien": "global_SRV_RETIRE", "action": "supprimer"}.items() <= next(
        item for item in plan["globaux"] if item["ancien"] == "global_SRV_RETIRE"
    ).items()


def test_globaux_non_cites_a_revoir_si_retraits_suspendus(racine, tmp_path, referentiel):
    dossier = tmp_path / "sns"
    shutil.copytree(racine / "examples" / "stormshield-natif", dossier)
    (dossier / "objectgroup").unlink()
    resultat = auditer(charger([dossier]), referentiel)
    retire = next(item for item in resultat.globaux if item.ancien == "global_SRV_RETIRE")
    assert retire.action == "revoir"
    assert "retraits suspendus" in retire.commentaire


def test_lecture_des_interfaces(racine):
    from fwclean.model import Interface
    from fwclean.stormshield_natif import lire_interfaces

    interfaces = {i.nom: i for i in lire_interfaces((racine / "examples" / "stormshield-natif" / "Network").read_text())}
    assert interfaces["out"] == Interface(nom="out", adresse="203.0.113.2", prefixe=24)
    assert interfaces["LAN"] == Interface(nom="LAN", adresse="10.0.0.254", prefixe=24)
    assert interfaces["in"].dhcp and interfaces["in"].adresse is None


def test_natifs_d_interface_remplaces(racine, referentiel):
    resultat = auditer(charger([racine / "examples" / "stormshield-natif"]), referentiel)
    natifs = {item.natif: item for item in resultat.natifs_interfaces}
    assert "Network_internals" not in natifs
    # Network_LAN : réseau de l'interface LAN, identique à l'objet local conservé de la fusion.
    assert (natifs["Network_LAN"].action, natifs["Network_LAN"].nouveau) == ("reutiliser", "SIEGE_NET_V10_LAN-USERS")
    assert (natifs["Firewall_LAN"].action, natifs["Firewall_LAN"].nouveau) == ("creer", "SIEGE_HST_FW_LAN-USERS")
    assert natifs["Firewall_LAN"].contenu == "10.0.0.254"
    assert (natifs["Firewall_out"].nouveau, natifs["Firewall_out"].nat) == ("SIEGE_HST_FW_WAN", ("nat nat1",))
    for nom in ("Firewall_in", "Network_in"):
        assert natifs[nom].action == "revoir" and "DHCP" in natifs[nom].commentaire
    assert natifs["Network_LAN"].references == ("r8",)
    from fwclean.report import _markdown, plan_dict

    assert plan_dict(resultat)["natifs_interfaces"][0]["natif"] == "Firewall_in"
    assert "## Natifs remplacés" in _markdown(resultat)
    assert "| Natifs remplacés (Network_, Firewall_) | 3 |" in _markdown(resultat)


def test_natif_reseau_hors_reseaux_csv():
    from fwclean.model import Interface, Inventaire, Regle
    from fwclean.sites import analyser_reseaux

    referentiel = analyser_reseaux("reseau;site;vlan;interface\n10.0.0.0/16;siege;;LAN-LARGE\n")
    inventaire = Inventaire(
        constructeur="stormshield",
        sources=("test",),
        objets=(),
        regles=(Regle(nom="r", action="allow", active=True, sources=("Network_LAN", "Firewall_LAN")),),
        interfaces=(Interface(nom="LAN", adresse="10.0.0.254", prefixe=24),),
    )
    natifs = {item.natif: item for item in auditer(inventaire, referentiel).natifs_interfaces}
    assert natifs["Network_LAN"].action == "revoir"
    assert "plus large" in natifs["Network_LAN"].commentaire
    # L'adresse du firewall se localise dans le réseau large : l'hôte est créé.
    assert natifs["Firewall_LAN"].nouveau == "SIEGE_HST_FW_LAN-LARGE"
