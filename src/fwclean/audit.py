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
    ESPACE,
    CTX,
    PREFIXE,
    SANS_LOCALISATION,
    est_conforme_objet,
    libelle_service,
    longueur_max,
    proposer_objet,
    rendre_unique,
)
from fwclean.sites import Localisateur, Referentiel

_RAISONS = {
    "hote": "adresse absente de reseaux.csv",
    "reseau": "réseau absent de reseaux.csv",
    "plage": "plage absente de reseaux.csv",
    "pool": "pool absent de reseaux.csv",
    "fqdn": "FQDN sans adresse IP, aucun site ni zone reconnu dans le nom",
    "groupe-adresses": "aucun membre localisé",
    "vip": "IP externe et IP mappée absentes de reseaux.csv",
}

MOTIF_ORPHELIN = "aucune reference"


def auditer(
    inventaire: Inventaire,
    contextes: Sequence[str],
    referentiel: Referentiel | None = None,
) -> Resultat:
    referentiel = referentiel or Referentiel()
    sites = referentiel.sites
    localisateur = Localisateur(inventaire, contextes, referentiel)
    refs = _index_references(inventaire)

    def limite(sorte: str) -> int:
        return longueur_max(inventaire.constructeur, sorte)

    def conforme(objet: Objet) -> bool:
        return est_conforme_objet(
            objet.nom, objet.sorte, contextes, sites, limite(objet.sorte), objet.vlan
        )

    def origines(objet: Objet) -> set[str]:
        return refs.get((objet.sorte, objet.nom), set())

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
                0 if conforme(objet) else 1,
                -len(origines(objet)),
                len(objet.nom),
                objet.nom,
            ),
        )
        partis = tuple(sorted((objet for objet in membres if objet != conserve), key=lambda o: o.nom))
        cites: set[str] = set()
        for parti in partis:
            supprimes[(parti.sorte, parti.nom)] = parti
            cites |= origines(parti)
        preparations.append((conserve, partis, cites))

    orphelins = tuple(
        sorted(
            (
                objet
                for objet in inventaire.objets
                if (objet.sorte, objet.nom) not in supprimes and not origines(objet)
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
            and not conforme(objet)
        ),
        key=lambda objet: (objet.sorte, objet.nom),
    )

    prises = {objet.nom for objet in inventaire.objets}
    renommages: list[Renommage] = []
    nouveaux: dict[tuple[str, str], str] = {}
    commentaires: dict[tuple[str, str], str] = {}
    for objet in candidats:
        if objet.sorte in SANS_LOCALISATION:
            site = zone = None
        else:
            site, zone = localisateur.objet(objet)
            if CTX in (site, zone):
                commentaires[(objet.sorte, objet.nom)] = _commentaire(objet.sorte, site, zone)
                continue
        prises.discard(objet.nom)
        base = proposer_objet(
            objet.nom,
            PREFIXE[objet.sorte],
            site,
            zone,
            contextes,
            limite(objet.sorte),
            vlan=objet.vlan,
            libelle_defaut=libelle_service(objet.empreinte) if objet.sorte == "service" else "nd",
        )
        nouveau = rendre_unique(base, prises, limite(objet.sorte))
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
        conforme,
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
        pointer(lien.origine, "calendrier", lien.calendriers)
        pointer(lien.origine, "pool", lien.pools)
    return refs


def _commentaire(sorte: str, site: str, zone: str) -> str:
    manques = [libelle for libelle, valeur in (("site", site), ("zone", zone)) if valeur == CTX]
    raison = _RAISONS.get(sorte, "aucune correspondance")
    return f"{' et '.join(manques)} introuvable{'s' if len(manques) > 1 else ''} : {raison}"
