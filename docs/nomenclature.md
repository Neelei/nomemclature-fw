# Nomenclature firewall

Convention commune pour les objets FortiGate et Stormshield. Elle ne décrit pas les flux : les règles gardent leur nom, leur action, leur source, leur destination et leur service. Seul le nom des objets change, et seulement après relecture du plan proposé par `fwclean`.

## Forme

Objets d'adresse (hôtes, réseaux, plages, FQDN, groupes, VIP, pools) : `{SITE}_{PREFIXE}_{ZONE}_{DETAIL}` — `SIEGE_HST_LAN_ZABBIXSRV`, `SIEGE_NET_LAN_VLAN11-SRV-ESX-MSA`. Le site vient en tête, puis le type, puis la zone.

Services : `SVC_{PROTOCOLE}_{PORTS}_{LIBELLE}`, sans site ni zone — `SVC_TCP_443_HTTPS`, `SVC_ANY_53_DNS`.

Groupes de services et calendriers : `{PREFIXE}_{DETAIL}`, sans site ni zone — `SG_ACTIVE-DIRECTORY`, `SCH_BUREAU`.

- majuscules uniquement (`A-Z`, `0-9`) ;
- les segments (site, type, zone, détail) sont séparés par un underscore `_` ;
- le tiret `-` est réservé à l'intérieur du dernier segment (`SIEGE_HST_LAN_ZABBIX-SRV`, `SIEGE_HST_DMZ_WEB-01`) et aux plages de ports d'un service (`SVC_UDP_67-68_DHCP`). Type, site et zone n'en contiennent jamais ;
- le point `.` n'existe que dans le segment des ports d'un service, pour séparer plusieurs ports (`SVC_ANY_88.464_KERBEROS`) ;
- ni `_`, `-` ou `.` en début, en fin, ou doublé ; pas d'espace ni d'accent ;
- exactement quatre segments pour un objet d'adresse (site, préfixe, zone, détail), trois ou quatre pour un service (préfixe, protocole, ports, libellé facultatif), deux pour un groupe de services ou un calendrier (préfixe, détail) ;
- un réseau dont le VLAN est connu dans la configuration porte `VLAN{ID}` dans son détail (voir [Réseaux et VLAN](#réseaux-et-vlan)).

Longueur maximale, reprise des limites FortiOS :

| Nom | FortiGate | Stormshield |
| --- | ---: | ---: |
| calendrier (`firewall schedule`) | 31 | 79 |
| autres objets (adresses, groupes, services, VIP, pools) | 79 | 79 |

Un nom proposé trop long est raccourci **dans son dernier segment seulement**, à une frontière de tiret quand c'est possible : type, site et zones restent entiers. `SCH_HORAIRES-USINE-ETE-NUITS-WEK` (32 caractères) devient `SCH_HORAIRES-USINE-ETE-NUITS` sur FortiGate. Un nom déjà en place qui dépasse la limite est signalé non conforme.

## Préfixes

| Préfixe | Objet | Exemple |
| --- | --- | --- |
| `HST` | hôte | `SIEGE_HST_DMZ_WEB-01` |
| `NET` | réseau | `SIEGE_NET_LAN_VLAN10-UTILISATEURS` |
| `RNG` | plage d'adresses | `SIEGE_RNG_VPN_CLIENTS` |
| `FQDN` | nom DNS | `SIEGE_FQDN_WAN_UPDATES` |
| `GRP` | groupe d'adresses | `SIEGE_GRP_DMZ_WEB` |
| `SVC` | service | `SVC_TCP_443_HTTPS` |
| `SG` | groupe de services | `SG_WEB` |
| `VIP` | VIP | `SIEGE_VIP_MULTI_WEB` |
| `POOL` | pool d'adresses (FortiGate) | `SIEGE_POOL_WAN_SORTANT` |
| `SCH` | calendrier | `SCH_BUREAU` |

Le préfixe doit correspondre au type réel de l'objet. `SIEGE_NET_DMZ_WEB` n'est pas un nom conforme pour un hôte.

## Site et zone

Le **site** est le premier segment d'un objet d'adresse, le préfixe le deuxième. Il est valide s'il figure dans le référentiel [`reseaux.csv`](#référentiel-reseauxcsv), ou s'il vaut `MULTI`.

La **zone** est le troisième segment. Elle est valide si elle figure dans [`contextes.txt`](../contextes.txt), ou si elle vaut `MULTI`.

La comparaison est **case-insensitive** : les fichiers gardent leurs clés en minuscules (`siege`, `lan`), les noms les écrivent en majuscules (`SIEGE`, `LAN`). Ajouter un site ou une zone ne demande pas de modifier le programme.

Zones livrées dans `contextes.txt`, reprises des zones FortiGate d'EPFRFORTI01. Une zone tient en un seul segment : les noms FortiGate longs ou avec espaces sont raccourcis. La correspondance s'écrit dans le fichier, `zone = nom FortiGate` (`mgmt = MGMT NETWORKS`), et sert à `fwclean reseaux`.

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

`MULTI` est réservé, toujours accepté comme site et comme zone, à ne pas mettre dans les fichiers : les membres (groupe, VIP, pool) appartiennent à plusieurs sites ou plusieurs zones.

**Pas de nom sans correspondance.** Un objet d'adresse dont le site ou la zone reste introuvable n'est pas renommé. Le rapport le liste avec le traitement `revoir` et un commentaire (« site introuvable : adresse absente de reseaux.csv », « site et zone introuvables : FQDN sans adresse IP… »), et le plan le reprend dans `a_revoir`. On complète `reseaux.csv` puis on relance l'audit. `CTX` n'apparaît dans aucun nom proposé, et un nom existant en `CTX` n'est pas conforme.

Un nom est jugé sur sa forme : `SIEGE_HST_LAN_X` est conforme dès que `SIEGE` est un site connu et `LAN` une zone connue, même si l'adresse est en fait en DMZ. La déduction ci-dessous sert à **proposer** un nom pour ce qui ne l'est pas.

### Référentiel `reseaux.csv`

Fichier à la racine du projet, fourni par l'équipe réseau. Autre chemin : `--reseaux`.

```text
reseau;site;zone;vlan
10.0.0.0/24;siege;lan;11
10.1.0.0/16;siege;lan;
10.1.1.0/24;siege;dmz;12
10.210.0.0/24;gras;lan
```

- séparateur `;`, en-tête `reseau;site;zone` ou `reseau;site;zone;vlan` obligatoire ;
- un réseau CIDR par ligne (IPv4 ou IPv6) ;
- site et zone en minuscules ; la zone doit être dans `contextes.txt` ;
- colonne `vlan` facultative : VLAN ID de 1 à 4094, vide si le réseau n'a pas de VLAN ; avec l'en-tête à quatre colonnes, une ligne à trois champs est acceptée (vlan vide) ;
- lignes vides et commentaires `#` ignorés ;
- un même réseau déclaré deux fois avec un site, une zone ou un VLAN différents est refusé.

**Sites distants.** Les réseaux connectés viennent de `fwclean reseaux` ; les autres (sites distants, pools VPN, IP publiques) s'ajoutent à la main, une ligne `reseau;site;zone;vlan` par réseau, par exemple `10.211.0.0/24;gras;dmz;211` ou `10.210.0.0/24;gras;lan;` sans VLAN. Un nouveau site est un ajout libre : l'écrire suffit à le rendre valide dans les noms (`GRAS_HST_DMZ_…`). La zone doit déjà figurer dans `contextes.txt`. `fwclean reseaux … --ajouter` complète ensuite le fichier avec les seuls réseaux absents et se relance sans écraser ces ajouts manuels (voir [la méthode](methode-nettoyage.md#référentiel-réseaux)).

Le plan d'adressage réel est sensible : `reseaux.csv` est ignoré par git. Le dépôt versionne seulement [`reseaux.exemple.csv`](../reseaux.exemple.csv), à copier. Sans `reseaux.csv`, l'audit tourne quand même : aucun site n'est connu, les objets d'adresse non conformes sont tous signalés à revoir.

### Déduction

| Objet | Site | Zone |
| --- | --- | --- |
| hôte, réseau, plage | réseau **le plus précis** du référentiel qui contient l'objet | idem |
| hôte, réseau, plage hors référentiel | introuvable → à revoir | idem |
| groupe d'adresses | commun à tous les membres | commun à tous les membres, sinon zone de l'ancien nom |
| VIP | commun à l'IP externe et à l'IP ou l'objet mappé | idem, sinon zone de l'ancien nom |
| pool | réseau qui contient toute la plage, sinon commun aux deux bornes | idem |
| FQDN | site trouvé dans l'ancien nom, sinon à revoir | zone trouvée dans l'ancien nom, sinon à revoir |

« Commun » : si tous les membres localisés ont la même valeur, c'est elle ; s'ils en ont plusieurs, `MULTI` ; si aucun n'est localisé, l'objet est à revoir. Un membre non localisé ne compte pas : un groupe d'un hôte `SIEGE` et d'une adresse partenaire hors référentiel reste `SIEGE`.

Avec le référentiel d'exemple, `10.1.1.10` est dans `10.1.0.0/16` (LAN) et dans `10.1.1.0/24` (DMZ) : le `/24` est plus précis, l'hôte devient `SIEGE_HST_DMZ_…`.

Le détail reprend l'ancien nom sans préfixe, et sans le site et la zone retenus : `SIEGE_zabbix` → `SIEGE_HST_LAN_ZABBIX`, `Web_DMZ` → `SIEGE_HST_DMZ_WEB`. Un autre mot de zone reste dans le détail : `MGMT [vlan13]` en LAN devient `SIEGE_NET_LAN_VLAN13-MGMT`. Un ancien nom déjà découpé garde seulement son détail, même si son site n'est pas connu, qu'il soit dans l'ordre actuel site, préfixe, zone (`GRAS_HST_DMZ_WEB-01`) ou dans l'ancien ordre préfixe, site, zone (`HST_SIEGE_DMZ_WEB-01`, `HST-SIEGE-DMZ-WEB-01`) : il devient `SIEGE_HST_DMZ_WEB-01` sans répéter site ni type.

## Réseaux et VLAN

Sur FortiGate, les interfaces VLAN de `config system interface` (`set vlanid`) donnent le VLAN d'un réseau :

- une adresse `interface-subnet` prend le VLAN de l'interface qu'elle cite ;
- une adresse `ipmask` prend le VLAN de l'interface dont le réseau connecté la contient (le plus précis s'il y en a plusieurs).

Sur Stormshield (fichiers natifs), les interfaces `[vlanN]` du fichier `Network` à adresse statique donnent le VLAN (`Tag=`) des réseaux qu'elles contiennent, de la même façon. Une interface en `dhcp` ne donne rien.

Un réseau sans VLAN connu dans la configuration prend ensuite le VLAN du **référentiel** : l'entrée de `reseaux.csv` la plus précise qui le contient, si elle a une colonne `vlan` renseignée. Si cette entrée la plus précise n'a pas de VLAN, rien n'est ajouté, même si un réseau plus large en a un. C'est ce qui donne `SIEGE_NET_LAN_VLAN11-RES` à `Res-VLAN11` (`10.0.0.0/24`) sur un SNS de sortie Internet dont les VLAN internes sont routés vers le FortiGate : `fwclean reseaux` sur le FortiGate écrit le `vlanid` de chaque interface dans la colonne `vlan`. Le VLAN de la configuration prime toujours sur celui du référentiel.

Le détail commence alors par `VLAN{ID}`, et les mentions de VLAN de l'ancien nom sont retirées : `SRV-ESX-MSA [vlan11]` → `SIEGE_NET_LAN_VLAN11-SRV-ESX-MSA`, `MEETING [valn50]` → `SIEGE_NET_LAN_VLAN50-MEETING`. L'ID vient de la configuration (ou du référentiel), jamais de l'ancien nom : `EDF [vlan20]`, sur une interface en VLAN 52, devient `SIEGE_NET_LAN_VLAN52-EDF`. Un réseau dont le VLAN est connu et dont le nom ne contient pas `VLAN{ID}` n'est pas conforme. Sans VLAN connu (réseau distant, CSV Stormshield, référentiel sans VLAN), rien n'est ajouté.

## Services

Un service n'a ni site ni zone. Sa forme est `SVC_{PROTOCOLE}_{PORTS}_{LIBELLE}` :

| Segment | Valeur | Exemples |
| --- | --- | --- |
| protocole | `TCP`, `UDP`, `ANY` quand TCP et UDP sont tous deux ouverts ; `ICMP`, `ICMP6`, `IP`, `SCTP` pour les autres | `SVC_TCP_443_HTTPS`, `SVC_UDP_389_LDAP`, `SVC_ANY_53_DNS` |
| ports | port de destination ; plage en `-` ; plusieurs ports séparés par `.` ; type ICMP ou numéro de protocole IP ; `ANY` pour tout ICMP ou tout IP | `SVC_UDP_67-68_DHCP`, `SVC_ANY_88.464_KERBEROS`, `SVC_ICMP_8_PING`, `SVC_IP_47_GRE` |
| libellé | l'ancien nom, sans les mots de protocole ni les numéros de port déjà présents ; facultatif | `HTTP-8080` → `SVC_TCP_8080_HTTP`, `MS Global Catalog` → `SVC_TCP_3268-3269_MS-GLOBAL-CATALOG`, `SVC_TCP_443` reste `SVC_TCP_443` |

Sur Stormshield, un objet `[Protocol]` (fichier natif `object`, cité par `ipproto` dans une règle) suit la même forme avec le protocole `IP` : `gre_tunnel=47` → `SVC_IP_47_GRE-TUNNEL`. Il a son propre espace de noms : un protocole `rdp` (IP 27) et un service `rdp` (TCP/3389) coexistent et deviennent `SVC_IP_27_RDP` et `SVC_TCP_3389_RDP`.

Protocole et ports sont calculés sur le **contenu** du service, pas sur son ancien nom : `SVC_UDP_443_HTTPS` pour un service TCP/443 n'est pas conforme. Quand TCP et UDP n'ouvrent pas les mêmes ports, `ANY` est suivi de tous les ports (`netbios` → `SVC_ANY_137.138.139_NETBIOS`) ; le détail par protocole reste dans le contenu, repris par le rapport. Les ports source ne figurent pas dans le nom.

## Groupes de services, calendriers

Ni site ni zone. Leur forme est `{PREFIXE}_{DETAIL}`, et le détail **garde le libellé de l'ancien nom** : `Active Directory` → `SG_ACTIVE-DIRECTORY`, `Bureau` → `SCH_BUREAU`.

L'ancien préfixe `SGRP` n'est plus conforme : `SGRP_WEB` est proposé au renommage en `SG_WEB`, sans répéter `SGRP` dans le détail.

## Règles

Les règles ne sont **pas renommées** pour le moment : `fwclean` ne signale pas leur nom et n'en propose aucun. Elles servent seulement à compter les références des objets (source, destination, service, calendrier, pool), y compris quand elles sont désactivées.

## Exemples non conformes

Avec `reseaux.exemple.csv` :

| Nom actuel | Contenu | Pourquoi | Nom proposé (si l'objet est conservé) |
| --- | --- | --- | --- |
| `web_dmz_backup` | `10.1.1.20/32` | pas de préfixe ni de site | `SIEGE_HST_DMZ_WEB-BACKUP` |
| `Vlan210` | `10.210.0.0/24` | pas de préfixe ni de site | `GRAS_NET_LAN_VLAN210` |
| `partenaire` | `192.0.2.10/32` | hors référentiel | aucun : à revoir, « site et zone introuvables » |
| `Clients web` | membres `SIEGE` et `GRAS` en LAN | espace, deux sites | `MULTI_GRP_LAN_CLIENTS-WEB` |
| `HST-DMZ-WEB-01` | `10.1.1.10/32` | ancienne forme, sans site | `SIEGE_HST_DMZ_WEB-01` |
| `LAN Utilisateurs` | `10.0.0.0/24`, VLAN 10 | espace, pas de VLAN | `SIEGE_NET_LAN_VLAN10-UTILISATEURS` |
| `Appli metier 8443` | `tcp/8443` | espaces, pas de préfixe | `SVC_TCP_8443_APPLI-METIER` |
| `SVC_HTTPS` | `tcp/443` | ni protocole ni port | `SVC_TCP_443_HTTPS` |
| `DNS` | `tcp/53, udp/53` | pas de préfixe | `SVC_ANY_53_DNS` |
| `HST-SIEGE-DMZ-WEB-01` | hôte | segments séparés par des tirets au lieu de `_` | `SIEGE_HST_DMZ_WEB-01` |
| `hst_siege_dmz_web-01` | hôte | minuscules : la forme exige des majuscules | `SIEGE_HST_DMZ_WEB-01` |
| `HST_SIEGE_DMZ_WEB-01` | hôte | ancien ordre : le type avant le site | `SIEGE_HST_DMZ_WEB-01` |
| `SGRP_WEB` | groupe de services | ancien préfixe `SGRP` | `SG_WEB` |

Si ce nom désigne un doublon strict, le plan ne le renomme pas : il le fusionne vers l'objet conservé. S'il ne sert nulle part, le plan propose son retrait, pas un renommage.

## Ce que la convention ne couvre pas

Noms de règles, utilisateurs, certificats, interfaces, zones constructeur, politiques VPN et objets géographiques ou dynamiques. Ces derniers sont signalés comme ignorés, sans proposition de nom.

Sur Stormshield, le nom d'un objet `[Fqdn]` ou d'un hôte `resolve=dynamic` est le nom DNS que le SNS résout : le renommer casserait la résolution. Ces objets sont listés à revoir avec ce commentaire, jamais renommés. Les objets globaux SMC (`global_*`) ne sont pas dans les fichiers locaux : ils sont seulement cités, ni audités ni renommés.

Les objets natifs du SNS (base par défaut : `http`, `dns_udp`, `rfc5735_private_1`, `update1.stormshield.eu`, protocoles `[Protocol]`…) gardent leur nom Stormshield : ils ne sont pas soumis à la convention, ni renommés ni retirés, et le rapport les liste à part. Voir [la liste](methode-nettoyage.md#objets-natifs-sns).
