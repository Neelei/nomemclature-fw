"""Audit des objets : renommages, fusions strictes, orphelins. Les règles ne sont pas renommées."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Sequence

from fwclean.model import (
    Fusion,
    Inventaire,
    NonConforme,
    Objet,
    Renommage,
    Resultat,
    Retrait,
)
from fwclean.naming import (
    CTX,
    ESPACE,
    MULTI,
    PREFIXE,
    SANS_LOCALISATION,
    SORTES_SERVICE,
    Localisation,
    est_conforme_objet,
    longueur_max,
    proposer_objet,
    proposer_service,
    rendre_unique,
    signature_service,
)
from fwclean.sites import Localisateur, Referentiel
from fwclean.sns_natifs import est_natif

_RAISONS = {
    "hote": "adresse absente de reseaux.csv",
    "reseau": "réseau absent de reseaux.csv",
    "plage": "plage absente de reseaux.csv",
    "pool": "pool absent de reseaux.csv",
    "fqdn": "FQDN sans adresse IP, aucun site ni interface reconnu dans le nom",
    "groupe-adresses": "aucun membre localisé",
    "vip": "IP mappée (adresse interne) absente de reseaux.csv",
}

_SANS_INTERFACE = {
    "groupe-adresses": "aucun membre sur une interface connue",
    "fqdn": "FQDN sans adresse IP, aucune interface reconnue dans le nom",
}
SANS_INTERFACE = "réseau de reseaux.csv sans colonne interface (vide ou ancien format à 4 colonnes)"

MOTIF_ORPHELIN = "aucune reference"


def auditer(
    inventaire: Inventaire,
    contextes: Sequence[str],
    referentiel: Referentiel | None = None,
) -> Resultat:
    referentiel = referentiel or Referentiel()
    sites = referentiel.sites
    interfaces = referentiel.interfaces
    localisateur = Localisateur(inventaire, contextes, referentiel)
    refs = _index_references(inventaire)

    def limite(sorte: str) -> int:
        return longueur_max(inventaire.constructeur, sorte)

    def conforme(objet: Objet) -> bool:
        signature = signature_service(objet.empreinte) if objet.sorte in SORTES_SERVICE else None
        attendu = None if objet.sorte in SANS_LOCALISATION else localisateur.objet(objet)
        return est_conforme_objet(
            objet.nom,
            objet.sorte,
            contextes,
            sites,
            limite(objet.sorte),
            signature,
            interfaces,
            attendu,
        )

    def origines(objet: Objet) -> set[str]:
        return refs.get((objet.sorte, objet.nom), set())

    natifs = tuple(
        objet
        for objet in inventaire.objets
        if inventaire.constructeur == "stormshield" and est_natif(objet.sorte, objet.nom)
    )
    natif_ids = {(objet.sorte, objet.nom) for objet in natifs}

    def natif(objet: Objet) -> bool:
        return (objet.sorte, objet.nom) in natif_ids

    groupes: dict[tuple, list[Objet]] = defaultdict(list)
    for objet in inventaire.objets:
        groupes[(objet.sorte, objet.empreinte)].append(objet)

    supprimes: dict[tuple[str, str], Objet] = {}
    preparations: list[tuple[Objet, tuple[Objet, ...], set[str]]] = []
    for membres in groupes.values():
        if len(membres) < 2:
            continue
        conserve = min(
            membres,
            key=lambda objet: (
                0 if natif(objet) else 1,
                0 if conforme(objet) else 1,
                -len(origines(objet)),
                len(objet.nom),
                objet.nom,
            ),
        )
        partis = tuple(
            sorted(
                (objet for objet in membres if objet != conserve and not natif(objet)),
                key=lambda o: o.nom,
            )
        )
        if not partis:
            continue
        cites: set[str] = set()
        for parti in partis:
            supprimes[(parti.sorte, parti.nom)] = parti
            cites |= origines(parti)
        preparations.append((conserve, partis, cites))

    orphelins = () if inventaire.retraits_suspendus else tuple(
        sorted(
            (
                objet
                for objet in inventaire.objets
                if (objet.sorte, objet.nom) not in supprimes
                and not natif(objet)
                and not origines(objet)
            ),
            key=lambda objet: (objet.sorte, objet.nom),
        )
    )
    orphelin_ids = {(objet.sorte, objet.nom) for objet in orphelins}

    candidats = sorted(
        (
            objet
            for objet in inventaire.objets
            if (objet.sorte, objet.nom) not in supprimes
            and (objet.sorte, objet.nom) not in orphelin_ids
            and not natif(objet)
            and not conforme(objet)
        ),
        key=lambda objet: (objet.sorte, objet.nom),
    )

    prises = {objet.nom for objet in inventaire.objets}
    renommages: list[Renommage] = []
    nouveaux: dict[tuple[str, str], str] = {}
    commentaires: dict[tuple[str, str], str] = {}
    for objet in candidats:
        if objet.fige:
            commentaires[(objet.sorte, objet.nom)] = objet.fige
            continue
        localisation = None
        if objet.sorte not in SANS_LOCALISATION:
            localisation = localisateur.objet(objet)
            commentaire = _commentaire(objet.sorte, localisation)
            if commentaire:
                commentaires[(objet.sorte, objet.nom)] = commentaire
                continue
        prises.discard(objet.nom)
        protege = 0
        if objet.sorte in SORTES_SERVICE:
            base = proposer_service(objet.nom, objet.empreinte, limite(objet.sorte))
        else:
            base = proposer_objet(
                objet.nom,
                PREFIXE[objet.sorte],
                localisation,
                contextes,
                limite(objet.sorte),
                interfaces,
            )
            if objet.sorte == "reseau" and localisation is not None:
                protege = len(localisation.interface)
        nouveau = rendre_unique(base, prises, limite(objet.sorte), protege)
        prises.add(nouveau)
        if nouveau == objet.nom:
            continue
        renommages.append(
            Renommage(
                sorte=objet.sorte,
                ancien=objet.nom,
                nouveau=nouveau,
                references=tuple(sorted(origines(objet))),
            )
        )
        nouveaux[(objet.sorte, objet.nom)] = nouveau

    fusions = tuple(
        sorted(
            (
                Fusion(
                    sorte=conserve.sorte,
                    contenu=conserve.detail,
                    conserve=conserve.nom,
                    nouveau_nom=nouveaux.get((conserve.sorte, conserve.nom), conserve.nom),
                    supprimes=tuple(parti.nom for parti in partis),
                    references_reecrites=tuple(sorted(cites)),
                )
                for conserve, partis, cites in preparations
            ),
            key=lambda fusion: (fusion.sorte, fusion.conserve),
        )
    )
    retraits = tuple(
        Retrait(sorte=objet.sorte, nom=objet.nom, motif=MOTIF_ORPHELIN) for objet in orphelins
    )
    non_conformes = _non_conformes(
        inventaire,
        lambda objet: natif(objet) or conforme(objet),
        supprimes,
        orphelin_ids,
        {(renommage.sorte, renommage.ancien): renommage for renommage in renommages},
        commentaires,
    )
    return Resultat(
        inventaire=inventaire,
        non_conformes=non_conformes,
        renommages=tuple(renommages),
        fusions=fusions,
        retraits=retraits,
        referentiel=referentiel.decrire(),
        natifs=tuple(sorted(natifs, key=lambda objet: (objet.sorte, objet.nom))),
    )


def _non_conformes(
    inventaire: Inventaire,
    conforme: Callable[[Objet], bool],
    supprimes: dict[tuple[str, str], Objet],
    orphelin_ids: set[tuple[str, str]],
    renommages: dict[tuple[str, str], Renommage],
    commentaires: dict[tuple[str, str], str],
) -> tuple[NonConforme, ...]:
    trouves: list[NonConforme] = []
    for objet in inventaire.objets:
        if conforme(objet):
            continue
        cle = (objet.sorte, objet.nom)
        renommage = renommages.get(cle)
        if cle in orphelin_ids:
            traitement, propose = "retrait", None
        elif cle in supprimes:
            traitement, propose = "fusion", None
        elif renommage is not None:
            traitement, propose = "renommage", renommage.nouveau
        else:
            traitement, propose = "revoir", None
        trouves.append(
            NonConforme(
                sorte=objet.sorte,
                nom=objet.nom,
                traitement=traitement,
                nom_propose=propose,
                commentaire=commentaires.get(cle) if traitement == "revoir" else None,
            )
        )
    return tuple(sorted(trouves, key=lambda item: (item.sorte, item.nom)))


def _index_references(inventaire: Inventaire) -> dict[tuple[str, str], set[str]]:
    par_espace = {(ESPACE[objet.sorte], objet.nom): objet for objet in inventaire.objets}
    refs: dict[tuple[str, str], set[str]] = defaultdict(set)

    def pointer(origine: str, espace: str, noms: tuple[str, ...]) -> None:
        for nom in noms:
            if not nom:
                continue
            objet = par_espace.get((espace, nom))
            if objet is not None:
                refs[(objet.sorte, objet.nom)].add(origine)

    for regle in inventaire.regles:
        pointer(regle.nom, "adresse", regle.sources)
        pointer(regle.nom, "adresse", regle.destinations)
        pointer(regle.nom, "service", regle.services)
        pointer(regle.nom, "protocole", regle.protocoles)
        if regle.planification:
            pointer(regle.nom, "calendrier", (regle.planification,))
        if regle.pool:
            pointer(regle.nom, "pool", (regle.pool,))
    for objet in inventaire.objets:
        pointer(objet.nom, "adresse", objet.mentions_adresses)
        pointer(objet.nom, "service", objet.mentions_services)
        pointer(objet.nom, "calendrier", objet.mentions_calendriers)
        pointer(objet.nom, "pool", objet.mentions_pools)
    for lien in inventaire.liens:
        pointer(lien.origine, "adresse", lien.adresses)
        pointer(lien.origine, "service", lien.services)
        pointer(lien.origine, "protocole", lien.protocoles)
        pointer(lien.origine, "calendrier", lien.calendriers)
        pointer(lien.origine, "pool", lien.pools)
    return refs


def _commentaire(sorte: str, localisation: Localisation) -> str | None:
    """Raison du classement « à revoir », ou None si un nom peut être proposé (pas de repli CTX)."""
    site, interface = localisation.site, localisation.interface
    if sorte == "reseau" and site != CTX and interface == MULTI:
        return "interface introuvable : réseau à cheval sur plusieurs interfaces de reseaux.csv"
    if CTX not in (site, interface):
        return None
    if site == CTX:
        raison = _RAISONS.get(sorte, "aucune correspondance")
        manques = "site et interface introuvables" if interface == CTX else "site introuvable"
        return f"{manques} : {raison}"
    return f"interface introuvable : {_SANS_INTERFACE.get(sorte, SANS_INTERFACE)}"
