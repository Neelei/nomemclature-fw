from fwclean.audit import auditer
from fwclean.model import Inventaire, Objet, Regle
from fwclean.naming import lire_contextes


def _hote(nom: str, ip: str = "10.9.9.9") -> Objet:
    return Objet(sorte="hote", nom=nom, empreinte=("v4", ip, 32), detail=f"{ip}/32")


def _regle(nom: str, destination: str) -> Regle:
    return Regle(
        nom=nom,
        action="allow",
        active=True,
        sources=("net-lan-utilisateurs",),
        destinations=(destination,),
        services=("svc-tcp-443",),
        interfaces_source=("lan",),
        interfaces_destination=("dmz",),
    )


def _auditer(racine, objets, regles=()):
    inventaire = Inventaire(
        constructeur="fortigate",
        sources=("memoire",),
        objets=tuple(objets),
        regles=tuple(regles),
    )
    return auditer(inventaire, lire_contextes(racine / "contextes.txt"))


def test_le_conforme_gagne_meme_moins_reference(racine):
    resultat = _auditer(
        racine,
        [_hote("hst-dmz-web-01", "10.1.1.10"), _hote("Web_DMZ", "10.1.1.10")],
        [
            _regle("allow-lan-dmz-un", "hst-dmz-web-01"),
            _regle("allow-lan-dmz-deux", "Web_DMZ"),
            _regle("allow-lan-dmz-trois", "Web_DMZ"),
            _regle("allow-lan-dmz-quatre", "Web_DMZ"),
        ],
    )
    assert len(resultat.fusions) == 1
    assert resultat.fusions[0].conserve == "hst-dmz-web-01"
    assert resultat.fusions[0].supprimes == ("Web_DMZ",)
    assert resultat.renommages == ()
    assert resultat.retraits == ()


def test_le_plus_reference_puis_renommage(racine):
    resultat = _auditer(
        racine,
        [_hote("Serveur_DMZ"), _hote("srv")],
        [
            _regle("allow-lan-dmz-un", "Serveur_DMZ"),
            _regle("allow-lan-dmz-deux", "Serveur_DMZ"),
            _regle("allow-lan-dmz-trois", "Serveur_DMZ"),
            _regle("allow-lan-dmz-quatre", "srv"),
        ],
    )
    assert [(item.ancien, item.nouveau) for item in resultat.renommages] == [
        ("Serveur_DMZ", "hst-dmz-serveur"),
    ]
    assert resultat.fusions[0].conserve == "Serveur_DMZ"
    assert resultat.fusions[0].nouveau_nom == "hst-dmz-serveur"
    assert resultat.fusions[0].supprimes == ("srv",)
    assert resultat.retraits == ()


def test_nom_le_plus_court_puis_retrait_si_personne_ne_cite(racine):
    resultat = _auditer(racine, [_hote("bbbb"), _hote("aa")])
    assert resultat.fusions[0].conserve == "aa"
    assert resultat.fusions[0].supprimes == ("bbbb",)
    assert [item.nom for item in resultat.retraits] == ["aa"]
    assert resultat.renommages == ()
