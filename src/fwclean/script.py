"""Script CLI FortiGate à partir d'un plan relu. Rien n'est envoyé à l'équipement."""

from __future__ import annotations

from dataclasses import dataclass, field

from fwclean.fortigate import _tokeniser, blocs
from fwclean.model import ErreurLecture
from fwclean.naming import ESPACE

# Section de configuration de chaque sorte d'objet (calendriers : trouvée dans l'export).
SECTIONS_OBJETS = {
    "hote": ("firewall address",),
    "reseau": ("firewall address",),
    "plage": ("firewall address",),
    "fqdn": ("firewall address",),
    "groupe-adresses": ("firewall addrgrp",),
    "vip": ("firewall vip",),
    "service": ("firewall service custom",),
    "groupe-services": ("firewall service group",),
    "calendrier": (
        "firewall schedule recurring",
        "firewall schedule onetime",
        "firewall schedule group",
    ),
    "pool": ("firewall ippool",),
}

# Champs qui citent un objet, par espace de noms. mappedip d'une VIP est une IP, jamais un objet.
# « vpn ssl settings » n'a pas d'entrées : ses champs se modifient sans « edit ».
CHAMPS = {
    "adresse": (
        ("firewall policy", "srcaddr"),
        ("firewall policy", "dstaddr"),
        ("firewall addrgrp", "member"),
        ("firewall addrgrp", "exclude-member"),
        ("firewall local-in-policy", "srcaddr"),
        ("firewall local-in-policy", "dstaddr"),
        ("firewall shaping-policy", "srcaddr"),
        ("firewall shaping-policy", "dstaddr"),
        ("firewall proxy-policy", "srcaddr"),
        ("firewall proxy-policy", "dstaddr"),
        ("firewall central-snat-map", "orig-addr"),
        ("firewall central-snat-map", "dst-addr"),
        ("router policy", "srcaddr"),
        ("router policy", "dstaddr"),
        ("router static", "dstaddr"),
        ("vpn ssl web portal", "split-tunneling-routing-address"),
        ("vpn ssl web portal", "ip-pools"),
        ("vpn ssl settings", "source-address"),
        ("vpn ssl settings", "tunnel-ip-pools"),
    ),
    "service": (
        ("firewall policy", "service"),
        ("firewall service group", "member"),
        ("firewall local-in-policy", "service"),
        ("firewall shaping-policy", "service"),
        ("firewall proxy-policy", "service"),
    ),
    "calendrier": (
        ("firewall policy", "schedule"),
        ("firewall schedule group", "member"),
        ("firewall local-in-policy", "schedule"),
        ("firewall proxy-policy", "schedule"),
    ),
    "pool": (("firewall policy", "poolname"),),
}

# Champs à valeur unique : remplacés par « set », pas par append / unselect.
UNIQUES = {
    ("firewall policy", "schedule"),
    ("firewall local-in-policy", "schedule"),
    ("firewall proxy-policy", "schedule"),
    ("router static", "dstaddr"),
}

# Champs que FortiOS refuse de laisser vides.
OBLIGATOIRES = {
    ("firewall policy", "srcaddr"),
    ("firewall policy", "dstaddr"),
    ("firewall policy", "service"),
    ("firewall addrgrp", "member"),
    ("firewall service group", "member"),
    ("firewall schedule group", "member"),
}

SECTIONS_GLOBALES = {"vpn ssl settings"}

# Champs hors CHAMPS qui peuvent citer un objet : l'objet n'y est pas réécrit, et son delete
# serait refusé. Repéré par le nom du champ, dans n'importe quelle section.
INDICES_AILLEURS = {
    "adresse": ("addr", "address", "pool", "member"),
    "service": ("service", "member"),
    "calendrier": ("schedule", "member"),
    "pool": ("pool",),
}
EXACTS_AILLEURS = {"adresse": {"src", "dst"}}
# Les membres des groupes d'utilisateurs ou d'interfaces portent d'autres espaces de noms.
PREFIXES_AILLEURS = ("firewall ", "vpn ", "router ", "system sdwan")

# Objets créés par FortiOS : ils reviennent aux mises à jour et servent aux réglages par défaut.
DEFAUTS_FORTIGATE = {
    "adresse": {
        "all", "none", "FIREWALL_AUTH_PORTAL_ADDRESS", "FABRIC_DEVICE", "SSLVPN_TUNNEL_ADDR1",
        "EMS_ALL_UNKNOWN_CLIENTS", "EMS_ALL_UNMANAGEABLE_CLIENTS", "login.microsoft.com",
        "login.microsoftonline.com", "login.windows.net", "gmail.com", "wildcard.google.com",
        "wildcard.dropbox.com", "G Suite", "Microsoft Office 365",
    },
    "service": {
        "ALL", "ALL_TCP", "ALL_UDP", "ALL_ICMP", "ALL_ICMP6", "GRE", "AH", "ESP", "AOL", "BGP",
        "DHCP", "DHCP6", "DNS", "FINGER", "FTP", "FTP_GET", "FTP_PUT", "GOPHER", "H323", "HTTP",
        "HTTPS", "IKE", "IMAP", "IMAPS", "Internet-Locator-Service", "IRC", "L2TP", "LDAP",
        "LDAP_UDP", "NetMeeting", "NFS", "NNTP", "NTP", "OSPF", "PC-Anywhere", "PING", "PING6",
        "TIMESTAMP", "INFO_REQUEST", "INFO_ADDRESS", "ONC-RPC", "DCE-RPC", "POP3", "POP3S", "PPTP",
        "QUAKE", "RAUDIO", "REXEC", "RIP", "RLOGIN", "RSH", "SCCP", "SIP", "SIP-MSNmessenger",
        "SAMBA", "SMTP", "SMTPS", "SNMP", "SSH", "SYSLOG", "TALK", "TELNET", "TFTP", "MGCP", "UUCP",
        "VDOLIVE", "WAIS", "WINFRAME", "X-WINDOWS", "MS-SQL", "MYSQL", "RDP", "VNC", "SQUID",
        "SOCKS", "WINS", "RADIUS", "RADIUS-OLD", "CVSPSERVER", "AFS3", "TRACEROUTE", "RTSP", "MMS",
        "KERBEROS", "SMB", "NONE", "webproxy", "Email Access", "Web Access", "Windows AD",
        "Exchange Server",
    },
    "calendrier": {"always", "none", "default-darrp-optimize"},
    "pool": set(),
}

_SECTIONS_OBJETS = frozenset(section for sections in SECTIONS_OBJETS.values() for section in sections)
_CHAMPS_CONNUS = {paire: espace for espace, champs in CHAMPS.items() for paire in champs}
_ESPACE_SECTION = {
    section: ESPACE[sorte] for sorte, sections in SECTIONS_OBJETS.items() for section in sections
}


@dataclass
class _Config:
    """État simulé de la configuration, mis à jour commande après commande."""

    objets: dict[tuple[str, str], str] = field(default_factory=dict)
    valeurs: dict[tuple[str, str | None, str], list[str]] = field(default_factory=dict)
    ailleurs: dict[tuple[str, str], list[str]] = field(default_factory=dict)

    def references(self, espace: str, nom: str) -> list[tuple[str, str | None, str]]:
        return [
            (section, cle, champ)
            for (section, cle, champ), valeurs in self.valeurs.items()
            if _CHAMPS_CONNUS.get((section, champ)) == espace and nom in valeurs
        ]

    def renommer(self, espace: str, ancien: str, nouveau: str) -> None:
        section = self.objets.pop((espace, ancien))
        self.objets[(espace, nouveau)] = section
        for (s, cle, c), valeurs in list(self.valeurs.items()):
            if _CHAMPS_CONNUS.get((s, c)) == espace:
                self.valeurs[(s, cle, c)] = [nouveau if v == ancien else v for v in valeurs]
            if s == section and cle == ancien:
                self.valeurs[(s, nouveau, c)] = self.valeurs.pop((s, cle, c))
        if (espace, ancien) in self.ailleurs:
            self.ailleurs[(espace, nouveau)] = self.ailleurs.pop((espace, ancien))


@dataclass(frozen=True)
class Script:
    renommages: str
    fusions: str
    retraits: str
    ignores: tuple[str, ...]
    compteurs: dict[str, int]
    erreurs_deja_appliquees: tuple[str, ...] = ()
    rattrapage: str = ""
    # Stormshield : lot 04, remplacement des objets globaux SMC ; lot 05, leur suppression.
    globaux: str = ""
    suppression_globaux: str = ""
    # Stormshield : lot 06, natifs d'interface (Network_X, Firewall_X) remplacés dans les règles.
    natifs: str = ""
    # Stormshield : mêmes commandes en texte brut à coller dans la console CLI, par nom de lot.
    cli: dict[str, str] = field(default_factory=dict)


def generer_script(
    texte: str,
    plan: dict,
    lot: int = 20,
    inclure_defauts: bool = False,
    deja_appliques: tuple[str, ...] = (),
) -> Script:
    """Écrit les trois étapes. `deja_appliques` : scripts déjà passés sur l'équipement, rejoués
    sur la sauvegarde avant de calculer ce qu'il reste à faire."""
    if plan.get("constructeur") != "fortigate":
        raise ErreurLecture("Le script CLI ne concerne que FortiGate (plan d'un autre constructeur).")
    if lot < 1:
        raise ErreurLecture("--lot doit valoir au moins 1.")
    config = _lire(texte)
    initiaux = set(config.objets)
    erreurs: list[str] = []
    for script_applique in deja_appliques:
        erreurs += appliquer(config, script_applique)
    ignores: list[str] = []

    def defaut(espace: str, nom: str) -> bool:
        return not inclure_defauts and nom in DEFAUTS_FORTIGATE[espace]

    prevus = {(ESPACE[i["sorte"]], i["ancien"]): i["nouveau"] for i in plan.get("renommages", [])}
    renommes: dict[tuple[str, str], str] = {}
    supprimes: dict[tuple[str, str], str] = {}

    def courant(espace: str, nom: str) -> str | None:
        """Nom de l'objet au moment de la commande : renommé à l'étape 01, ou déjà sur l'équipement."""
        nom = renommes.get((espace, nom), nom)
        if (espace, nom) in config.objets:
            return nom
        nouveau = prevus.get((espace, nom))
        if nouveau and (espace, nouveau) in config.objets:
            return nouveau
        return None

    def absent(espace: str, nom: str) -> str:
        etape = supprimes.get((espace, renommes.get((espace, nom), nom)))
        if etape:
            return etape
        if (espace, nom) in initiaux:
            return "déjà supprimé par un script déjà appliqué"
        return "absent de l'export"

    doublons = {
        (ESPACE[f["sorte"]], d)
        for f in plan.get("fusions", [])
        for d in f["supprimes"]
        if not defaut(ESPACE[f["sorte"]], d)
    }

    renommages: list[list[str]] = []
    for item in plan.get("renommages", []):
        espace, ancien, nouveau = ESPACE[item["sorte"]], item["ancien"], item["nouveau"]
        if defaut(espace, ancien):
            ignores.append(f"renommage de {ancien} : objet par défaut FortiGate")
        elif (espace, ancien) in doublons:
            ignores.append(f"renommage de {ancien} : doublon supprimé à l'étape 02")
        elif (espace, ancien) not in config.objets:
            if (espace, nouveau) in config.objets and deja_appliques:
                ignores.append(f"renommage de {ancien} : déjà fait ({nouveau})")
            else:
                ignores.append(f"renommage de {ancien} : absent de l'export")
        elif (espace, nouveau) in config.objets:
            ignores.append(f"renommage de {ancien} : {nouveau} existe déjà")
        else:
            section = config.objets[(espace, ancien)]
            renommages.append([f"config {section}", f"    rename {_q(ancien)} to {_q(nouveau)}", "end"])
            config.renommer(espace, ancien, nouveau)
            renommes[(espace, ancien)] = nouveau

    fusions: list[list[str]] = []
    for fusion in plan.get("fusions", []):
        espace = ESPACE[fusion["sorte"]]
        cible = courant(espace, fusion["conserve"])
        if cible is None:
            ignores.append(f"fusion vers {fusion['conserve']} : objet conservé absent de l'export")
            continue
        for doublon in fusion["supprimes"]:
            if defaut(espace, doublon):
                ignores.append(f"fusion de {doublon} : objet par défaut FortiGate")
                continue
            nom = courant(espace, doublon)
            if nom is None:
                ignores.append(f"fusion de {doublon} : {absent(espace, doublon)}")
                continue
            if nom == cible:
                ignores.append(f"fusion de {doublon} : c'est l'objet conservé")
                continue
            entete = f"# doublon {_q(nom)} -> conservé {_q(cible)}"
            if fusion.get("contenu"):
                entete += f" ({fusion['contenu']})"
            commandes = [entete, *_reporter(config, espace, nom, cible)]
            cite = config.ailleurs.get((espace, nom))
            if cite:
                ignores.append(f"suppression de {nom} : encore cité dans {', '.join(cite)}, à reprendre à la main")
            else:
                commandes += _supprimer(config, espace, nom)
                supprimes[(espace, nom)] = f"déjà supprimé à l'étape 02 (doublon de {cible})"
            if len(commandes) > 1:
                fusions.append(commandes)

    retraits: list[list[str]] = []
    ordre = list(SECTIONS_OBJETS)
    for item in sorted(plan.get("retraits", []), key=lambda i: (ordre.index(i["sorte"]), i["nom"])):
        espace = ESPACE[item["sorte"]]
        nom = courant(espace, item["nom"])
        if defaut(espace, item["nom"]):
            ignores.append(f"retrait de {item['nom']} : objet par défaut FortiGate")
        elif nom is None:
            ignores.append(f"retrait de {item['nom']} : {absent(espace, item['nom'])}")
        elif config.references(espace, nom):
            ignores.append(f"retrait de {nom} : encore référencé dans l'export")
        elif config.ailleurs.get((espace, nom)):
            ignores.append(f"retrait de {nom} : encore cité dans {', '.join(config.ailleurs[(espace, nom)])}")
        else:
            retraits.append(_supprimer(config, espace, nom))
            supprimes[(espace, nom)] = "déjà retiré"

    return Script(
        renommages=_fichier("01", "Renommages", renommages, lot),
        fusions=_fichier("02", "Fusions de doublons stricts", fusions, lot),
        retraits=_fichier("03", "Retraits d'objets sans référence", retraits, lot),
        ignores=tuple(ignores),
        compteurs={"renommages": len(renommages), "fusions": len(fusions), "retraits": len(retraits)},
        erreurs_deja_appliquees=tuple(erreurs),
        rattrapage=_fichier(
            "02b", "Rattrapage des renommages et fusions restants", renommages + fusions, lot
        ),
    )


def _lire(texte: str) -> _Config:
    decoupe = blocs(texte, _SECTIONS_OBJETS)
    config = _Config()
    for sorte, sections in SECTIONS_OBJETS.items():
        for section in sections:
            for nom, _data in decoupe.get(section, []):
                config.objets.setdefault((ESPACE[sorte], nom), section)
    for chemin, cles, champ, valeurs in _parcourir(texte):
        if (chemin, champ) in _CHAMPS_CONNUS and len(cles) == (0 if chemin in SECTIONS_GLOBALES else 1):
            if valeurs:
                config.valeurs[(chemin, cles[0] if cles else None, champ)] = list(valeurs)
            continue
        if not chemin.startswith(PREFIXES_AILLEURS):
            continue
        for espace, indices in INDICES_AILLEURS.items():
            if any(indice in champ for indice in indices) or champ in EXACTS_AILLEURS.get(espace, ()):
                for valeur in valeurs:
                    if (espace, valeur) not in config.objets:
                        continue
                    if config.objets[(espace, valeur)] == chemin and cles[:1] == (valeur,):
                        continue
                    lieu = " ".join([chemin, *(_q(c) for c in cles[:1]), champ])
                    config.ailleurs.setdefault((espace, valeur), []).append(lieu)
    return config


def _parcourir(texte: str) -> list[tuple[str, tuple[str, ...], str, list[str]]]:
    """Chaque « set » de l'export : chemin des config imbriqués, clés des edit, champ, valeurs."""
    resultat = []
    pile: list[tuple[str, str | None]] = []
    for brut in texte.splitlines():
        ligne = brut.strip()
        if ligne.startswith("config "):
            pile.append(("config", ligne[len("config ") :].strip()))
        elif ligne.startswith("edit "):
            jetons = _tokeniser(ligne[len("edit ") :].strip())
            pile.append(("edit", jetons[0] if jetons else ""))
        elif ligne in ("end", "next"):
            if pile:
                pile.pop()
        elif ligne.startswith("set "):
            jetons = _tokeniser(ligne[len("set ") :].strip())
            if jetons:
                chemin = " ".join(n for genre, n in pile if genre == "config")
                cles = tuple(n for genre, n in pile if genre == "edit")
                resultat.append((chemin, cles, jetons[0], jetons[1:]))
    return resultat


def _reporter(config: _Config, espace: str, doublon: str, cible: str) -> list[str]:
    """Références du doublon reportées sur l'objet conservé : append avant unselect."""
    commandes: list[str] = []
    for section, cle, champ in config.references(espace, doublon):
        valeurs = config.valeurs[(section, cle, champ)]
        retrait = "    " if cle is None else "        "
        commandes.append(f"config {section}")
        if cle is not None:
            commandes.append(f"    edit {_q(cle) if not cle.isdigit() else cle}")
        if (section, champ) in UNIQUES:
            commandes.append(f"{retrait}set {champ} {_q(cible)}")
            valeurs[:] = [cible]
        else:
            if cible not in valeurs:
                commandes.append(f"{retrait}append {champ} {_q(cible)}")
                valeurs.append(cible)
            commandes.append(f"{retrait}unselect {champ} {_q(doublon)}")
            valeurs.remove(doublon)
        if cle is not None:
            commandes.append("    next")
        commandes.append("end")
    return commandes


def _supprimer(config: _Config, espace: str, nom: str) -> list[str]:
    section = config.objets.pop((espace, nom))
    return [f"config {section}", f"    delete {_q(nom)}", "end"]


def appliquer(config: _Config, texte: str) -> list[str]:
    """Rejoue un script sur l'état simulé, comme FortiOS : une commande refusée ne change rien.

    Rend les commandes refusées, avec la raison."""
    erreurs: list[str] = []
    section: str | None = None
    cle: str | None = None
    for numero, brut in enumerate(texte.splitlines(), 1):
        ligne = brut.strip()
        if not ligne or ligne.startswith("#"):
            continue
        jetons = _tokeniser(ligne)
        verbe = jetons[0]
        lieu = f"ligne {numero} : {ligne} — "

        if verbe == "config":
            section, cle = " ".join(jetons[1:]), None
        elif verbe == "end":
            section, cle = None, None
        elif verbe == "edit":
            cle = jetons[1]
        elif verbe == "next":
            cle = None
        elif verbe in ("rename", "delete"):
            espace = _ESPACE_SECTION.get(section or "")
            nom = jetons[1]
            if espace is None or config.objets.get((espace, nom)) != section:
                erreurs.append(lieu + "objet introuvable")
            elif verbe == "rename":
                nouveau = jetons[3]
                if (espace, nouveau) in config.objets:
                    erreurs.append(lieu + f"{nouveau} existe déjà")
                else:
                    config.renommer(espace, nom, nouveau)
            elif config.references(espace, nom) or config.ailleurs.get((espace, nom)):
                lieux = [" ".join(str(p) for p in r if p is not None) for r in config.references(espace, nom)]
                lieux += config.ailleurs.get((espace, nom), [])
                erreurs.append(lieu + "objet encore utilisé (" + ", ".join(lieux) + ")")
            else:
                del config.objets[(espace, nom)]
        elif verbe in ("append", "unselect", "set") and section:
            champ, valeur = jetons[1], jetons[2] if len(jetons) > 2 else ""
            espace = _CHAMPS_CONNUS.get((section, champ))
            if espace is None:
                continue
            valeurs = config.valeurs.setdefault((section, cle, champ), [])
            if verbe == "unselect":
                if valeur not in valeurs:
                    erreurs.append(lieu + "valeur absente du champ")
                elif valeurs == [valeur] and (section, champ) in OBLIGATOIRES:
                    erreurs.append(lieu + "le champ ne peut pas rester vide")
                else:
                    valeurs.remove(valeur)
            elif (espace, valeur) not in config.objets:
                erreurs.append(lieu + "objet introuvable")
            elif verbe == "set":
                valeurs[:] = [valeur]
            elif valeur not in valeurs:
                valeurs.append(valeur)
    return erreurs


def _fichier(etape: str, titre: str, blocs_commandes: list[list[str]], lot: int) -> str:
    lignes = [
        f"# fwclean — étape {etape} : {titre}.",
        "# Script à relire, puis à coller lot par lot dans la CLI FortiGate.",
        "# Sauvegarder la configuration avant chaque lot ; tester les flux après.",
        "# Étapes dans l'ordre : 01-renommages, 02-fusions, 03-retraits.",
    ]
    if etape != "01":
        lignes.append("# Les noms sont ceux d'après les étapes précédentes.")
    if not blocs_commandes:
        return "\n".join([*lignes, "# Rien à appliquer."]) + "\n"
    total = (len(blocs_commandes) + lot - 1) // lot
    for index in range(total):
        lignes += ["", f"# --- lot {index + 1}/{total} ---"]
        for bloc in blocs_commandes[index * lot : (index + 1) * lot]:
            lignes += bloc
    return "\n".join(lignes) + "\n"


def _q(nom: str) -> str:
    return '"' + nom.replace("\\", "\\\\").replace('"', '\\"') + '"'
