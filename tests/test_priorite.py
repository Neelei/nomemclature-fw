from fwclean.audit import auditer
from fwclean.model import Inventaire, Objet, Regle
from fwclean.sites import lire_reseaux


def _hote(nom: str, ip: str = "10.9.9.9") -> Objet:
    return Objet(sorte="hote", nom=nom, empreinte=("v4", ip, 32), detail=f"{ip}/32")


def _regle(nom: str, destination: str) -> Regle:
    return Regle(
        nom=nom,
        action="allow",
        active=True,
        sources=("SIEGE_NET_LAN_UTILISATEURS",),
        destinations=(destination,),
        services=("SVC_TCP_443_HTTPS",),
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
    return auditer(inventaire, lire_reseaux(racine / "reseaux.exemple.csv"))


def test_le_conforme_gagne_meme_moins_reference(racine):
    resultat = _auditer(
        racine,
        [_hote("SIEGE_HST_DMZ_WEB-01", "10.1.1.10"), _hote("Web_DMZ", "10.1.1.10")],
        [
            _regle("ALLOW_SIEGE_LAN_DMZ_UN", "SIEGE_HST_DMZ_WEB-01"),
            _regle("ALLOW_SIEGE_LAN_DMZ_DEUX", "Web_DMZ"),
            _regle("ALLOW_SIEGE_LAN_DMZ_TROIS", "Web_DMZ"),
            _regle("ALLOW_SIEGE_LAN_DMZ_QUATRE", "Web_DMZ"),
        ],
    )
    assert len(resultat.fusions) == 1
    assert resultat.fusions[0].conserve == "SIEGE_HST_DMZ_WEB-01"
    assert resultat.fusions[0].supprimes == ("Web_DMZ",)
    assert resultat.renommages == ()
    assert resultat.retraits == ()


def test_le_plus_reference_puis_renommage(racine):
    resultat = _auditer(
        racine,
        [_hote("Serveur_DMZ", "10.1.1.50"), _hote("srv", "10.1.1.50")],
        [
            _regle("ALLOW_SIEGE_LAN_DMZ_UN", "Serveur_DMZ"),
            _regle("ALLOW_SIEGE_LAN_DMZ_DEUX", "Serveur_DMZ"),
            _regle("ALLOW_SIEGE_LAN_DMZ_TROIS", "Serveur_DMZ"),
            _regle("ALLOW_SIEGE_LAN_DMZ_QUATRE", "srv"),
        ],
    )
    assert [(item.ancien, item.nouveau) for item in resultat.renommages] == [
        ("Serveur_DMZ", "SIEGE_HST_DMZ_SERVEUR"),
    ]
    assert resultat.fusions[0].conserve == "Serveur_DMZ"
    assert resultat.fusions[0].nouveau_nom == "SIEGE_HST_DMZ_SERVEUR"
    assert resultat.fusions[0].supprimes == ("srv",)
    assert resultat.retraits == ()


def test_nom_le_plus_court_puis_retrait_si_personne_ne_cite(racine):
    resultat = _auditer(racine, [_hote("bbbb"), _hote("aa")])
    assert resultat.fusions[0].conserve == "aa"
    assert resultat.fusions[0].supprimes == ("bbbb",)
    assert [item.nom for item in resultat.retraits] == ["aa"]
    assert resultat.renommages == ()
