# Nomenclature firewall

Convention commune pour les objets et le nom des règles FortiGate et Stormshield. Elle ne décrit pas les flux : une règle garde son action, sa source, sa destination et son service. Seul le nom change, et seulement après relecture du plan proposé par `fwclean`.

## Forme

Objets : `{PREFIXE}-{SITE}-{ZONE}-{DETAIL}` — `HST-EPFR-LAN-ZABBIXSRV`, `NET-GRAS-LAN-VLAN210`.

Règles : `{ALLOW|DENY}-{SITE}-{ZONE_SRC}-{ZONE_DST}-{SERVICE}` — `ALLOW-EPFR-LAN-DMZ-HTTPS`.

Services : `SVC-{PROTOCOLE}-{DETAIL}`, sans site ni zone — `SVC-TCP-443`.

- majuscules uniquement (`A-Z`, `0-9`) ;
- segments séparés par un tiret simple, sans tiret en début, en fin, ni doublé ;
- pas d'espace, d'underscore, de point, ni d'accent ;
- au moins quatre segments pour un objet (préfixe, site, zone, détail), cinq pour une règle ;
- 79 caractères au plus (limite FortiGate sur le nom d'une adresse). La même limite est appliquée aux autres noms pour que la convention tienne sur les deux constructeurs.

## Préfixes

| Préfixe | Objet | Exemple |
| --- | --- | --- |
| `HST` | hôte | `HST-EPFR-DMZ-WEB-01` |
| `NET` | réseau | `NET-EPFR-LAN-UTILISATEURS` |
| `RNG` | plage d'adresses | `RNG-EPFR-VPN-CLIENTS` |
| `FQDN` | nom DNS | `FQDN-CTX-WAN-UPDATES` |
| `GRP` | groupe d'adresses | `GRP-EPFR-DMZ-WEB` |
| `SVC` | service | `SVC-TCP-443` |
| `SGRP` | groupe de services | `SGRP-CTX-DMZ-WEB` |
| `VIP` | VIP | `VIP-EPFR-MULTI-WEB` |
| `POOL` | pool d'adresses (FortiGate) | `POOL-EPFR-WAN-SORTANT` |
| `SCH` | calendrier | `SCH-CTX-LAN-BUREAU` |

Le préfixe doit correspondre au type réel de l'objet. `NET-EPFR-DMZ-WEB` n'est pas un nom conforme pour un hôte.

## Site et zone

Le **site** est le deuxième segment. Il est valide s'il figure dans le référentiel [`reseaux.csv`](#référentiel-reseauxcsv), ou s'il vaut `CTX` ou `MULTI`.

La **zone** est le troisième segment d'un objet, le troisième et le quatrième d'une règle. Elle est valide si elle figure dans [`contextes.txt`](../contextes.txt), ou si elle vaut `CTX` ou `MULTI`.

La comparaison est **case-insensitive** : les fichiers gardent leurs clés en minuscules (`epfr`, `lan`), les noms les écrivent en majuscules (`EPFR`, `LAN`). Ajouter un site ou une zone ne demande pas de modifier le programme.

Zones livrées dans `contextes.txt`, reprises des zones FortiGate d'EPFRFORTI01. Une zone tient en un seul segment : les noms FortiGate longs ou avec espaces sont raccourcis.

| Zone (fichier) | Dans un nom | Zone ou interface FortiGate |
| --- | --- | --- |
| `lan` | `LAN` | `LAN` : réseaux internes |
| `dmz` | `DMZ` | `DMZ` : zone exposée |
| `wan` | `WAN` | `WAN` (zone SD-WAN) : accès opérateur |
| `vpn` | `VPN` | `ssl.root` : VPN SSL |
| `mgmt` | `MGMT` | `MGMT NETWORKS` : iDRAC, Datacore, SAN |
| `bastion` | `BASTION` | `Bastion ADMIN_MGMT` |
| `users` | `USERS` | `Users LAN` : Wi-Fi corporate |
| `preprodfr` | `PREPRODFR` | `PreProd FRANCE` |
| `preprodth` | `PREPRODTH` | `PreProd THAILANDE` |
| `invite` | `INVITE` | `WIFI INVITE VLAN-42` |
| `mobile` | `MOBILE` | `WIFI MOBILE VLAN-41` |
| `oob` | `OOB` | port `mgmt` dédié, hors zone |
| `loop` | `LOOP` | `LOOPMGMT`, loopback d'administration, hors zone |

Valeurs réservées, toujours acceptées comme site et comme zone, à ne pas mettre dans les fichiers :

| Valeur | Sens |
| --- | --- |
| `CTX` | rien trouvé : l'objet n'est dans aucun réseau du référentiel, ou son nom ne contient aucune zone connue |
| `MULTI` | les membres (groupe, VIP, pool, sources d'une règle) appartiennent à plusieurs sites ou plusieurs zones |

Un nom est jugé sur sa forme : `HST-EPFR-LAN-X` est conforme dès que `EPFR` est un site connu et `LAN` une zone connue, même si l'adresse est en fait en DMZ. La déduction ci-dessous sert à **proposer** un nom pour ce qui ne l'est pas.

### Référentiel `reseaux.csv`

Fichier à la racine du projet, fourni par l'équipe réseau. Autre chemin : `--reseaux`.

```text
reseau;site;zone
10.1.0.0/16;epfr;lan
10.1.1.0/24;epfr;dmz
10.210.0.0/24;gras;lan
```

- séparateur `;`, en-tête `reseau;site;zone` obligatoire ;
- un réseau CIDR par ligne (IPv4 ou IPv6) ;
- site et zone en minuscules ; la zone doit être dans `contextes.txt` ;
- lignes vides et commentaires `#` ignorés ;
- un même réseau déclaré deux fois avec un site ou une zone différents est refusé.

Le plan d'adressage réel est sensible : `reseaux.csv` est ignoré par git. Le dépôt versionne seulement [`reseaux.exemple.csv`](../reseaux.exemple.csv), à copier. Sans `reseaux.csv`, l'audit tourne quand même : aucun site n'est connu, les sites proposés valent `CTX`.

### Déduction

| Objet | Site | Zone |
| --- | --- | --- |
| hôte, réseau, plage | réseau **le plus précis** du référentiel qui contient l'objet | idem |
| hôte, réseau, plage hors référentiel | `CTX` | zone trouvée dans l'ancien nom (`Web_DMZ` → `DMZ`), sinon `CTX` |
| groupe d'adresses | commun à tous les membres | commun à tous les membres, sinon zone de l'ancien nom |
| VIP | commun à l'IP externe et à l'IP ou l'objet mappé | idem, sinon zone de l'ancien nom |
| pool | réseau qui contient toute la plage, sinon commun aux deux bornes | idem |
| FQDN, groupe de services, calendrier | site trouvé dans l'ancien nom, sinon `CTX` | zone trouvée dans l'ancien nom, sinon `CTX` |

« Commun » : si tous les membres connus ont la même valeur, c'est elle ; s'ils en ont plusieurs, `MULTI` ; si aucun n'est connu, `CTX`. Un membre en `CTX` ne compte pas : un groupe d'un hôte `EPFR` et d'une adresse partenaire hors référentiel reste `EPFR`.

Avec le référentiel d'exemple, `10.1.1.10` est dans `10.1.0.0/16` (LAN) et dans `10.1.1.0/24` (DMZ) : le `/24` est plus précis, l'hôte devient `HST-EPFR-DMZ-…`.

Le détail reprend l'ancien nom sans préfixe, sans le premier jeton de site et sans le premier jeton de zone : `EPFR_zabbix` → `HST-EPFR-LAN-ZABBIX`. Un ancien nom déjà découpé en `{PREFIXE}-{SITE}-{ZONE}-…` garde seulement son détail, même si son site n'est pas connu.

## Services

Un service n'utilise ni site ni zone. Sa forme est `{SVC}-{PROTOCOLE}-{DETAIL}` :

- protocole : `TCP`, `UDP`, `ICMP`, `IP`, `SCTP` ou `ANY` ;
- détail : le port (`SVC-TCP-443`, `SVC-UDP-53`), une plage (`SVC-TCP-2000-2032`), ou un nom court pour ICMP (`SVC-ICMP-ECHO`).

Un groupe de services suit la forme des objets : `SGRP-CTX-DMZ-WEB`.

## Règles

`{ALLOW|DENY}-{SITE}-{ZONE_SRC}-{ZONE_DST}-{SERVICE}`

- `ALLOW` ou `DENY` reprend l'action déjà configurée (`accept` / `pass` → allow, `deny` / `block` → deny). On ne change pas l'action pour faire coller le nom ;
- site : commun aux objets source (`MULTI` s'ils sont sur plusieurs sites). Si aucune source n'a de site connu (source `all`, `any`), le site commun des destinations est pris ; sinon `CTX` ;
- zones : l'interface de la règle si elle porte un nom de zone de `contextes.txt` (`lan`, `dmz`) ; sinon (`port3`, plusieurs interfaces), la zone commune des objets source ou destination, déduite par le référentiel ;
- le dernier segment décrit le service, en un ou plusieurs morceaux : `HTTPS`, `TCP-443` ;
- un suffixe `-01` à `-99` lève un homonyme. Il n'est pas confondu avec un port : `ALLOW-EPFR-LAN-DMZ-TCP-80` garde `80` comme port, parce qu'il suit le protocole.

Exemples : `ALLOW-EPFR-LAN-DMZ-HTTPS`, `DENY-EPFR-WAN-LAN-ANY`, `ALLOW-MULTI-LAN-DMZ-TCP-443`, `ALLOW-EPFR-LAN-DMZ-HTTPS-01`.

Un nom déjà conforme n'est pas réécrit, même si l'outil aurait choisi un autre libellé de service. `ALLOW-EPFR-LAN-DMZ-HTTPS` reste, y compris si l'objet service s'appelle `SVC-TCP-443`.

## Exemples non conformes

Avec `reseaux.exemple.csv` :

| Nom actuel | Contenu | Pourquoi | Nom proposé (si l'objet est conservé) |
| --- | --- | --- | --- |
| `web_dmz_backup` | `10.1.1.20/32` | pas de préfixe ni de site | `HST-EPFR-DMZ-WEB-BACKUP` |
| `Vlan210` | `10.210.0.0/24` | pas de préfixe ni de site | `NET-GRAS-LAN-VLAN210` |
| `partenaire` | `192.0.2.10/32` | hors référentiel | `HST-CTX-CTX-PARTENAIRE` |
| `Clients web` | membres `EPFR` et `GRAS` en LAN | espace, deux sites | `GRP-MULTI-LAN-CLIENTS-WEB` |
| `HST-DMZ-WEB-01` | `10.1.1.10/32` | ancienne forme, sans site | `HST-EPFR-DMZ-WEB-01` |
| `HTTPS custom` | `tcp/443` | espace, pas de préfixe | `SVC-TCP-443` |
| `Acces web` | `lan` → `dmz`, `SVC-TCP-443`, source `EPFR` | ne suit pas action, site et zones | `ALLOW-EPFR-LAN-DMZ-TCP-443` |
| `ALLOW-LAN-DMZ-HTTPS` | règle | ancienne forme, sans site | `ALLOW-EPFR-LAN-DMZ-…` |
| `hst-epfr-dmz-web-01` | hôte | minuscules : la forme exige des majuscules | `HST-EPFR-DMZ-WEB-01` |

Si ce nom désigne un doublon strict, le plan ne le renomme pas : il le fusionne vers l'objet conservé. S'il ne sert nulle part, le plan propose son retrait, pas un renommage.

## Ce que la convention ne couvre pas

Utilisateurs, certificats, interfaces, zones constructeur, politiques VPN et objets géographiques ou dynamiques. Ces derniers sont signalés comme ignorés, sans proposition de nom. Les interfaces du firewall ne sont pas renommées : `lan` dans une règle est le nom de zone déjà en place, repris seulement pour proposer un nom de règle.
