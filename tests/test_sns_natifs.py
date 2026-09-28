from fwclean.audit import auditer
from fwclean.model import Inventaire, Objet
from fwclean.sns_natifs import NATIFS, est_natif


def test_natifs_de_la_base_sns():
    assert est_natif("reseau", "rfc5735_private_1")
    assert est_natif("reseau", "IANA_v6_uniquelocal")
    assert est_natif("groupe-adresses", "rfc3330")
    assert est_natif("hote", "update1-sns.stormshieldcs.eu")
    assert est_natif("fqdn", "webupdate.netasq.com")
    assert est_natif("hote", "rfc4291_loopback")
    assert est_natif("hote", "localhost")
    assert est_natif("service", "https")
    assert est_natif("service", "microsoft-ds_tcp")
    assert est_natif("service", "quic_443")
    assert est_natif("groupe-services", "ActiveDirectory2008")
    assert est_natif("protocole", "vrrp")
    assert len(NATIFS["protocole"]) == 22


def test_objets_admin_non_natifs():
    for sorte, nom in [
        ("hote", "EPFRSRV01"),
        ("reseau", "Res-VLAN10"),
        ("service", "Veeam_https"),
        ("service", "https_EP"),
        ("service", "UDP_9001"),
        ("service", "udpvpn"),
        ("service", "sybase"),
        ("groupe-services", "grp_admin"),
        ("hote", "router"),
        ("hote", "https"),
        ("fqdn", "www.googleapis.com"),
        ("hote", "0.fr.pool.ntp.org"),
        ("hote", "evil.stormshield.eu.example.com"),
    ]:
        assert not est_natif(sorte, nom), nom
    assert est_natif("service", "router")


def _objet(sorte, nom, empreinte):
    return Objet(sorte=sorte, nom=nom, empreinte=empreinte, detail=str(empreinte))


def test_audit_laisse_les_natifs_et_les_conserve_en_fusion():
    objets = (
        _objet("service", "https", (("tcp", ((443, 443, 0, 65535),)),)),
        _objet("service", "https_admin", (("tcp", ((443, 443, 0, 65535),)),)),
        _objet("service", "ssh_udp", (("udp", ((22, 22, 0, 65535),)),)),
        _objet("service", "Veeam_https", (("tcp", ((9443, 9443, 0, 65535),)),)),
    )
    resultat = auditer(Inventaire("stormshield", (), objets), ["lan"])
    assert [(item.conserve, item.supprimes) for item in resultat.fusions] == [
        ("https", ("https_admin",))
    ]
    assert resultat.fusions[0].nouveau_nom == "https"
    assert [item.nom for item in resultat.retraits] == ["Veeam_https"]
    assert [objet.nom for objet in resultat.natifs] == ["https", "ssh_udp"]
    assert {item.nom for item in resultat.non_conformes} == {"https_admin", "Veeam_https"}


def test_fortigate_sans_natifs_sns():
    objets = (_objet("service", "https", (("tcp", ((443, 443, 0, 65535),)),)),)
    resultat = auditer(Inventaire("fortigate", (), objets), ["lan"])
    assert resultat.natifs == ()
    assert [item.nom for item in resultat.retraits] == ["https"]
