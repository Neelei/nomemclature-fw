"""Script CLI FortiGate à partir d'un plan relu. Rien n'est envoyé à l'équipement."""

from __future__ import annotations

from dataclasses import dataclass, field

from fwclean.fortigate import blocs
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
CHAMPS = {
    "adresse": (
        ("firewall policy", "srcaddr"),
        ("firewall policy", "dstaddr"),
        ("firewall addrgrp", "member"),
        ("firewall addrgrp", "exclude-member"),
        ("router policy", "srcaddr"),
        ("router policy", "dstaddr"),
        ("router static", "dstaddr"),
    ),
    "service": (
        ("firewall policy", "service"),
        ("firewall service group", "member"),
    ),
    "calendrier": (
        ("firewall policy", "schedule"),
        ("firewall schedule group", "member"),
    ),
    "pool": (("firewall policy", "poolname"),),
}

# Champs à valeur unique : remplacés par « set », pas par append / unselect.
UNIQUES = {
    ("firewall policy", "schedule"),
    ("router static", "dstaddr"),
}

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

_SECTIONS = frozenset(
    {section for sections in SECTIONS_OBJETS.values() for section in sections}
    | {section for champs in CHAMPS.values() for section, _champ in champs}
)


@dataclass
class _Config:
    """État simulé de la configuration, mis à jour commande après commande."""

    objets: dict[tuple[str, str], str] = field(default_factory=dict)
    valeurs: dict[tuple[str, str, str], list[str]] = field(default_factory=dict)

    def references(self, espace: str, nom: str) -> list[tuple[str, str, str]]:
        return [
            (section, cle, champ)
            for section, champ in CHAMPS[espace]
            for (s, cle, c), valeurs in self.valeurs.items()
            if s == section and c == champ and nom in valeurs
        ]

    def renommer(self, espace: str, ancien: str, nouveau: str) -> None:
        section = self.objets.pop((espace, ancien))
        self.objets[(espace, nouveau)] = section
        for (s, cle, c), valeurs in list(self.valeurs.items()):
            if (s, c) in CHAMPS[espace]:
                self.valeurs[(s, cle, c)] = [nouveau if v == ancien else v for v in valeurs]
            if s == section and cle == ancien:
                self.valeurs[(s, nouveau, c)] = self.valeurs.pop((s, cle, c))


@dataclass(frozen=True)
class Script:
    renommages: str
    fusions: str
    retraits: str
    ignores: tuple[str, ...]
    compteurs: dict[str, int]


def generer_script(texte: str, plan: dict, lot: int = 20, inclure_defauts: bool = False) -> Script:
    if plan.get("constructeur") != "fortigate":
        raise ErreurLecture("Le script CLI ne concerne que FortiGate (plan d'un autre constructeur).")
    if lot < 1:
        raise ErreurLecture("--lot doit valoir au moins 1.")
    config = _lire(texte)
    ignores: list[str] = []

    def defaut(espace: str, nom: str) -> bool:
        return not inclure_defauts and nom in DEFAUTS_FORTIGATE[espace]

    renommages: list[list[str]] = []
    for item in plan.get("renommages", []):
        espace, ancien, nouveau = ESPACE[item["sorte"]], item["ancien"], item["nouveau"]
        if defaut(espace, ancien):
            ignores.append(f"renommage de {ancien} : objet par défaut FortiGate")
        elif (espace, ancien) not in config.objets:
            ignores.append(f"renommage de {ancien} : absent de l'export")
        elif (espace, nouveau) in config.objets:
            ignores.append(f"renommage de {ancien} : {nouveau} existe déjà")
        else:
            section = config.objets[(espace, ancien)]
            renommages.append([f"config {section}", f"    rename {_q(ancien)} to {_q(nouveau)}", "end"])
            config.renommer(espace, ancien, nouveau)

    fusions: list[list[str]] = []
    noms_courants = {(ESPACE[i["sorte"]], i["ancien"]): i["nouveau"] for i in plan.get("renommages", [])}
    for fusion in plan.get("fusions", []):
        espace = ESPACE[fusion["sorte"]]
        cible = noms_courants.get((espace, fusion["conserve"]), fusion["conserve"])
        if (espace, cible) not in config.objets:
            cible = fusion["conserve"]
        if (espace, cible) not in config.objets:
            ignores.append(f"fusion vers {fusion['conserve']} : objet conservé absent de l'export")
            continue
        for doublon in fusion["supprimes"]:
            if defaut(espace, doublon):
                ignores.append(f"fusion de {doublon} : objet par défaut FortiGate")
                continue
            if (espace, doublon) not in config.objets:
                ignores.append(f"fusion de {doublon} : absent de l'export")
                continue
            fusions.append(_fusionner(config, espace, doublon, cible))

    retraits: list[list[str]] = []
    ordre = list(SECTIONS_OBJETS)
    for item in sorted(plan.get("retraits", []), key=lambda i: (ordre.index(i["sorte"]), i["nom"])):
        espace, nom = ESPACE[item["sorte"]], item["nom"]
        if defaut(espace, nom):
            ignores.append(f"retrait de {nom} : objet par défaut FortiGate")
        elif (espace, nom) not in config.objets:
            ignores.append(f"retrait de {nom} : absent de l'export")
        elif config.references(espace, nom):
            ignores.append(f"retrait de {nom} : encore référencé dans l'export")
        else:
            section = config.objets.pop((espace, nom))
            retraits.append([f"config {section}", f"    delete {_q(nom)}", "end"])

    return Script(
        renommages=_fichier("Renommages", 1, renommages, lot),
        fusions=_fichier("Fusions de doublons stricts", 2, fusions, lot),
        retraits=_fichier("Retraits d'objets sans référence", 3, retraits, lot),
        ignores=tuple(ignores),
        compteurs={"renommages": len(renommages), "fusions": len(fusions), "retraits": len(retraits)},
    )


def _lire(texte: str) -> _Config:
    decoupe = blocs(texte, _SECTIONS)
    config = _Config()
    for sorte, sections in SECTIONS_OBJETS.items():
        for section in sections:
            for nom, _data in decoupe.get(section, []):
                config.objets.setdefault((ESPACE[sorte], nom), section)
    for champs in CHAMPS.values():
        for section, champ in champs:
            for cle, data in decoupe.get(section, []):
                if data.get(champ):
                    config.valeurs[(section, cle, champ)] = list(data[champ])
    return config


def _fusionner(config: _Config, espace: str, doublon: str, cible: str) -> list[str]:
    """Références du doublon reportées sur l'objet conservé, puis suppression du doublon."""
    commandes: list[str] = []
    for section, cle, champ in config.references(espace, doublon):
        valeurs = config.valeurs[(section, cle, champ)]
        commandes += [f"config {section}", f"    edit {_q(cle) if not cle.isdigit() else cle}"]
        if (section, champ) in UNIQUES:
            commandes.append(f"        set {champ} {_q(cible)}")
            valeurs[:] = [cible]
        else:
            if cible not in valeurs:
                commandes.append(f"        append {champ} {_q(cible)}")
                valeurs.append(cible)
            commandes.append(f"        unselect {champ} {_q(doublon)}")
            valeurs.remove(doublon)
        commandes += ["    next", "end"]
    section = config.objets.pop((espace, doublon))
    commandes += [f"config {section}", f"    delete {_q(doublon)}", "end"]
    return commandes


def _fichier(titre: str, numero: int, blocs_commandes: list[list[str]], lot: int) -> str:
    lignes = [
        f"# fwclean — étape {numero} : {titre}.",
        "# Script à relire, puis à coller lot par lot dans la CLI FortiGate.",
        "# Sauvegarder la configuration avant chaque lot ; tester les flux après.",
        "# Étapes dans l'ordre : 01-renommages, 02-fusions, 03-retraits.",
    ]
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
