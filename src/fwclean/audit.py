"""Audit des objets : renommages, fusions strictes, orphelins. Les règles ne sont pas renommées."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Sequence

from fwclean.contenu import membres_tries
from fwclean.model import (
    Fusion,
    Inventaire,
    NonConforme,
    Objet,
    RemplacementGlobal,
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
    forme_valide,
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
    referentiel: Referentiel | None = None,
) -> Resultat:
    referentiel = referentiel or Referentiel()
    sites = referentiel.sites
    interfaces = referentiel.interfaces
    localisateur = Localisateur(inventaire, referentiel)
    refs = _index_references(inventaire)

    def limite(sorte: str) -> int:
        return longueur_max(inventaire.constructeur, sorte)

    def conforme(objet: Objet, nom: str | None = None) -> bool:
        signature = signature_service(objet.empreinte) if objet.sorte in SORTES_SERVICE else None
        attendu = None if objet.sorte in SANS_LOCALISATION else localisateur.objet(objet)
        return est_conforme_objet(
            objet.nom if nom is None else nom,
            objet.sorte,
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
        if not objet.globale:
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
                and not objet.globale
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
            and not objet.globale
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

    conserves = {
        (parti.sorte, parti.nom): conserve for conserve, partis, _cites in preparations for parti in partis
    }

    def nom_final(objet: Objet) -> str:
        objet = conserves.get((objet.sorte, objet.nom), objet)
        return nouveaux.get((objet.sorte, objet.nom), objet.nom)

    def nommer(objet: Objet, base: str, localisation: Localisation | None) -> str:
        if base not in prises and forme_valide(base, limite(objet.sorte)) and conforme(objet, base):
            nouveau = base
        elif objet.sorte in SORTES_SERVICE:
            nouveau = rendre_unique(proposer_service(base, objet.empreinte, limite(objet.sorte)), prises, limite(objet.sorte))
        else:
            propose = proposer_objet(
                base, PREFIXE[objet.sorte], localisation, limite(objet.sorte), interfaces
            )
            protege = len(localisation.interface) if objet.sorte == "reseau" and localisation else 0
            nouveau = rendre_unique(propose, prises, limite(objet.sorte), protege)
        prises.add(nouveau)
        return nouveau

    globaux = _remplacer_globaux(
        inventaire,
        [
            objet
            for objet in inventaire.objets
            if not objet.globale
            and (objet.sorte, objet.nom) not in supprimes
            and (objet.sorte, objet.nom) not in orphelin_ids
        ],
        nom_final,
        localisateur,
        nommer,
        origines,
    )
    non_conformes = _non_conformes(
        inventaire,
        lambda objet: objet.globale or natif(objet) or conforme(objet),
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
        globaux=globaux,
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


PREFIXE_GLOBAL = "global_"
MOTIF_GLOBAL_INUTILE = "objet global cité par aucune règle, route, NAT ni objet local"
SORTES_GROUPE = ("groupe-adresses", "groupe-services")


def _remplacer_globaux(
    inventaire: Inventaire,
    locaux: Sequence[Objet],
    nom_final: Callable[[Objet], str],
    localisateur: Localisateur,
    nommer: Callable[[Objet, str, Localisation | None], str],
    origines: Callable[[Objet], set[str]],
) -> tuple[RemplacementGlobal, ...]:
    """Objet local qui remplace chaque objet global SMC, ou suppression du global inutile.

    Un global identique (même contenu) à un objet local conservé réutilise cet objet, sous son
    nom final (après renommages et fusions) ; sinon un objet local est créé, nommé selon la
    nomenclature. Les groupes sont traités après leurs membres, membres traduits.
    """
    globaux = {objet.nom: objet for objet in inventaire.objets if objet.globale}
    if not globaux:
        return ()

    necessaires: set[str] = set()
    cites: list[str] = []
    for regle in inventaire.regles:
        cites.extend(regle.sources + regle.destinations + regle.services + regle.protocoles)
    for lien in inventaire.liens:
        cites.extend(lien.adresses + lien.services + lien.protocoles)
    for objet in locaux:
        cites.extend(objet.mentions_adresses + objet.mentions_services)
    while cites:
        nom = cites.pop()
        if nom in globaux and nom not in necessaires:
            necessaires.add(nom)
            cites.extend(globaux[nom].mentions_adresses + globaux[nom].mentions_services)

    finaux: dict[tuple[str, tuple], list[str]] = defaultdict(list)
    noms_locaux: dict[tuple[str, str], str] = {}
    for objet in inventaire.objets:
        if not objet.globale:
            noms_locaux[(ESPACE[objet.sorte], objet.nom)] = nom_final(objet)
    for objet in locaux:
        if objet.sorte in SORTES_GROUPE:
            espace = ESPACE[objet.sorte]
            membres = membres_tries(
                [noms_locaux.get((espace, nom), nom) for nom in objet.mentions_adresses + objet.mentions_services]
            )
            finaux[(objet.sorte, membres)].append(nom_final(objet))
        else:
            finaux[(objet.sorte, objet.empreinte)].append(nom_final(objet))
    pris_locaux = {(ESPACE[objet.sorte], nom_final(objet)) for objet in locaux}

    resultats: dict[str, RemplacementGlobal] = {}
    ordre: list[str] = []

    def traiter(nom: str, pile: tuple[str, ...] = ()) -> RemplacementGlobal | None:
        if nom in resultats:
            return resultats[nom]
        objet = globaux.get(nom)
        if objet is None or nom in pile:
            return None
        base = nom[len(PREFIXE_GLOBAL):]
        commun = {
            "sorte": objet.sorte,
            "ancien": nom,
            "contenu": objet.detail,
            "references": tuple(sorted(origines(objet))),
        }
        if nom not in necessaires:
            if inventaire.retraits_suspendus:
                remplacement = RemplacementGlobal(
                    action="revoir",
                    nouveau=None,
                    commentaire=f"retraits suspendus ({inventaire.retraits_suspendus}) : usage inconnu",
                    **commun,
                )
            else:
                remplacement = RemplacementGlobal(
                    action="supprimer", nouveau=None, commentaire=MOTIF_GLOBAL_INUTILE, **commun
                )
        elif objet.sorte in SORTES_GROUPE:
            remplacement = _groupe_global(objet, base, commun, pile, traiter, finaux, localisateur, nommer)
        elif finaux.get((objet.sorte, objet.empreinte)):
            remplacement = RemplacementGlobal(
                action="reutiliser", nouveau=min(finaux[(objet.sorte, objet.empreinte)]), **commun
            )
        elif objet.fige:
            if (ESPACE[objet.sorte], base) in pris_locaux:
                remplacement = RemplacementGlobal(
                    action="revoir",
                    nouveau=None,
                    commentaire=f"{objet.fige} ; nom déjà pris par un objet local",
                    **commun,
                )
            else:
                remplacement = RemplacementGlobal(action="creer", nouveau=base, **commun)
        else:
            localisation = None if objet.sorte in SANS_LOCALISATION else localisateur.objet(objet)
            commentaire = _commentaire(objet.sorte, localisation) if localisation else None
            if commentaire:
                remplacement = RemplacementGlobal(
                    action="revoir", nouveau=None, commentaire=commentaire, **commun
                )
            else:
                remplacement = RemplacementGlobal(
                    action="creer", nouveau=nommer(objet, base, localisation), **commun
                )
        if remplacement.action == "creer" and remplacement.nouveau:
            cle = remplacement.membres if objet.sorte in SORTES_GROUPE else objet.empreinte
            finaux[(objet.sorte, cle)].append(remplacement.nouveau)
        resultats[nom] = remplacement
        ordre.append(nom)
        return remplacement

    for nom in sorted(globaux, key=lambda nom: (globaux[nom].sorte in SORTES_GROUPE, globaux[nom].sorte, nom)):
        traiter(nom)
    return tuple(resultats[nom] for nom in ordre)


def _groupe_global(
    objet: Objet,
    base: str,
    commun: dict,
    pile: tuple[str, ...],
    traiter: Callable[[str, tuple[str, ...]], RemplacementGlobal | None],
    finaux: dict[tuple[str, tuple], list[str]],
    localisateur: Localisateur,
    nommer: Callable[[Objet, str, Localisation | None], str],
) -> RemplacementGlobal:
    traduits: list[str] = []
    a_revoir: list[str] = []
    for membre in objet.mentions_adresses + objet.mentions_services:
        remplacement = traiter(membre, pile + (objet.nom,))
        if remplacement is None or remplacement.nouveau is None:
            a_revoir.append(membre)
        else:
            traduits.append(remplacement.nouveau)
    if a_revoir:
        return RemplacementGlobal(
            action="revoir",
            nouveau=None,
            commentaire=f"membre sans remplaçant local : {', '.join(a_revoir)}",
            **commun,
        )
    membres = membres_tries(traduits)
    if finaux.get((objet.sorte, membres)):
        return RemplacementGlobal(
            action="reutiliser", nouveau=min(finaux[(objet.sorte, membres)]), membres=membres, **commun
        )
    localisation = None if objet.sorte in SANS_LOCALISATION else localisateur.objet(objet)
    commentaire = _commentaire(objet.sorte, localisation) if localisation else None
    if commentaire:
        return RemplacementGlobal(
            action="revoir", nouveau=None, membres=membres, commentaire=commentaire, **commun
        )
    return RemplacementGlobal(
        action="creer", nouveau=nommer(objet, base, localisation), membres=membres, **commun
    )


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
