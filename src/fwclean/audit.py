"""Audit : renommages, fusions strictes, orphelins. Rien n'est appliqué."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from fwclean.model import (
    Fusion,
    Inventaire,
    NonConforme,
    Objet,
    Regle,
    Renommage,
    Resultat,
    Retrait,
)
from fwclean.naming import (
    ESPACE,
    PREFIXE,
    est_conforme_objet,
    est_conforme_regle,
    proposer_objet,
    proposer_regle,
    proposer_service,
    rendre_unique,
)
from fwclean.sites import Localisateur, Referentiel

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

    def conforme(objet: Objet) -> bool:
        return est_conforme_objet(objet.nom, objet.sorte, contextes, sites)

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

    candidats: list[tuple[str, Objet | Regle]] = []
    for objet in inventaire.objets:
        cle = (objet.sorte, objet.nom)
        if cle in supprimes or cle in orphelin_ids or conforme(objet):
            continue
        candidats.append(("objet", objet))
    for regle in inventaire.regles:
        if not est_conforme_regle(regle.nom, regle.action, contextes, sites):
            candidats.append(("regle", regle))
    candidats.sort(key=lambda item: (_sorte_item(item), _nom_item(item)))

    prises = {objet.nom for objet in inventaire.objets} | {regle.nom for regle in inventaire.regles}
    renommages: list[Renommage] = []
    nouveaux: dict[tuple[str, str], str] = {}
    for genre, item in candidats:
        prises.discard(item.nom)
        if genre == "objet":
            assert isinstance(item, Objet)
            if item.sorte == "service":
                base = proposer_service(item.empreinte)
            else:
                site, zone = localisateur.objet(item)
                base = proposer_objet(item.nom, PREFIXE[item.sorte], site, zone, contextes, sites)
            references = tuple(sorted(origines(item)))
            sorte = item.sorte
        else:
            assert isinstance(item, Regle)
            site, zone_source, zone_destination = localisateur.regle(item)
            base = proposer_regle(item.action, site, zone_source, zone_destination, item.services)
            references = ()
            sorte = "regle"
        nouveau = rendre_unique(base, prises)
        prises.add(nouveau)
        if nouveau == item.nom:
            continue
        renommages.append(
            Renommage(sorte=sorte, ancien=item.nom, nouveau=nouveau, references=references)
        )
        nouveaux[(sorte, item.nom)] = nouveau

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
        contextes,
        sites,
        supprimes,
        orphelin_ids,
        {renommage.ancien: renommage for renommage in renommages},
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
    contextes: Sequence[str],
    sites: Sequence[str],
    supprimes: dict[tuple[str, str], Objet],
    orphelin_ids: set[tuple[str, str]],
    renommages: dict[str, Renommage],
) -> tuple[NonConforme, ...]:
    trouves: list[NonConforme] = []
    for objet in inventaire.objets:
        if est_conforme_objet(objet.nom, objet.sorte, contextes, sites):
            continue
        cle = (objet.sorte, objet.nom)
        renommage = renommages.get(objet.nom)
        if cle in orphelin_ids:
            traitement, propose = "retrait", None
        elif cle in supprimes:
            traitement, propose = "fusion", None
        elif renommage is not None and renommage.sorte == objet.sorte:
            traitement, propose = "renommage", renommage.nouveau
        else:
            traitement, propose = "revoir", None
        trouves.append(
            NonConforme(sorte=objet.sorte, nom=objet.nom, traitement=traitement, nom_propose=propose)
        )
    for regle in inventaire.regles:
        if est_conforme_regle(regle.nom, regle.action, contextes, sites):
            continue
        renommage = renommages.get(regle.nom)
        if renommage is not None and renommage.sorte == "regle":
            traitement, propose = "renommage", renommage.nouveau
        else:
            traitement, propose = "revoir", None
        trouves.append(
            NonConforme(sorte="regle", nom=regle.nom, traitement=traitement, nom_propose=propose)
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


def _sorte_item(item: tuple[str, Objet | Regle]) -> str:
    genre, valeur = item
    if genre == "regle":
        return "regle"
    assert isinstance(valeur, Objet)
    return valeur.sorte


def _nom_item(item: tuple[str, Objet | Regle]) -> str:
    return item[1].nom
