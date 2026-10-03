# Nomenclature firewall

Convention commune pour les objets FortiGate et Stormshield. Elle ne décrit pas les flux : les règles gardent leur nom, leur action, leur source, leur destination et leur service. Seul le nom des objets change, et seulement après relecture du plan proposé par `fwclean`.

## Forme

Le troisième segment des objets d'adresse est l'**interface** du réseau qui contient l'objet, lue dans [`reseaux.csv`](#référentiel-reseauxcsv). La zone FortiGate ne sert plus qu'aux objets réseau.

| Objets | Forme | Exemple |
| --- | --- | --- |
| hôtes, plages, FQDN, groupes d'adresses, VIP, pools | `{SITE}_{PREFIXE}_{INTERFACE}_{DETAIL}` | `HQ_HST_CABINES_PC01` |
| réseau dans une zone FortiGate | `{SITE}_NET_{ZONE}_V{VLAN}_{INTERFACE}` | `HQ_NET_LAN_V16_CABINES` |
| réseau sans zone FortiGate, et tous les réseaux Stormshield | `{SITE}_NET_V{VLAN}_{INTERFACE}` | `HQ_NET_V16_CABINES` |
| services | `SVC_{PROTOCOLE}_{PORTS}_{LIBELLE}` | `SVC_TCP_443_HTTPS`, `SVC_ANY_53_DNS` |
| groupes de services, calendriers | `{PREFIXE}_{DETAIL}` | `SG_ACTIVE-DIRECTORY`, `SCH_BUREAU` |

Services, groupes de services et calendriers n'ont ni site ni interface ; leur forme ne change pas.

- majuscules uniquement (`A-Z`, `0-9`) ;
- les segments sont séparés par un underscore `_` ;
- le tiret `-` sert à l'intérieur du détail (`HQ_HST_CABINES_ZABBIX-SRV`), du nom d'interface (`HQ_HST_LABO-ANA_PC01`), et aux plages de ports d'un service (`SVC_UDP_67-68_DHCP`). Site, type et zone n'en contiennent jamais ;
- le point `.` n'existe que dans le segment des ports d'un service, pour séparer plusieurs ports (`SVC_ANY_88.464_KERBEROS`) ;
- ni `_`, `-` ou `.` en début, en fin, ou doublé ; pas d'espace ni d'accent ;
- un objet d'adresse non réseau a exactement quatre segments ; un réseau en a de trois à cinq selon qu'il a une zone et un VLAN (voir [Réseaux](#réseaux)).

Longueur maximale, reprise des limites FortiOS :

| Nom | FortiGate | Stormshield |
| --- | ---: | ---: |
| calendrier (`firewall schedule`) | 31 | 79 |
| autres objets (adresses, groupes, services, VIP, pools) | 79 | 79 |

Un nom proposé trop long est raccourci **dans son détail seulement**, à une frontière de tiret quand c'est possible : type, site, zone, VLAN et interface restent entiers. Pour un sous-réseau (`…_CABINES-IMPRIMANTES`), c'est le détail après l'interface qui est coupé, jamais l'interface. `SCH_HORAIRES-USINE-ETE-NUITS-WEK` (32 caractères) devient `SCH_HORAIRES-USINE-ETE-NUITS` sur FortiGate. Un nom déjà en place qui dépasse la limite est signalé non conforme.

## Préfixes

| Préfixe | Objet | Exemple |
| --- | --- | --- |
| `HST` | hôte | `SIEGE_HST_DMZ_WEB-01` |
| `NET` | réseau | `SIEGE_NET_LAN_V10_LAN-USERS` |
| `RNG` | plage d'adresses | `SIEGE_RNG_VPN-SSL_CLIENTS` |
| `FQDN` | nom DNS | `SIEGE_FQDN_WAN_UPDATES` |
| `GRP` | groupe d'adresses | `SIEGE_GRP_DMZ_WEB` |
| `SVC` | service | `SVC_TCP_443_HTTPS` |
| `SG` | groupe de services | `SG_WEB` |
| `VIP` | VIP | `SIEGE_VIP_DMZ_WEB` |
| `POOL` | pool d'adresses (FortiGate) | `SIEGE_POOL_WAN_SORTANT` |
| `SCH` | calendrier | `SCH_BUREAU` |

Le préfixe doit correspondre au type réel de l'objet. `SIEGE_NET_DMZ_WEB` n'est pas un nom conforme pour un hôte.

## Site, interface et zone

Le **site** est le premier segment d'un objet d'adresse, le préfixe le deuxième. Il est valide s'il figure dans le référentiel [`reseaux.csv`](#référentiel-reseauxcsv), ou s'il vaut `MULTI`.

L'**interface** est le troisième segment des objets non réseau et le dernier des réseaux. C'est la colonne `interface` de `reseaux.csv`, **normalisée** : `_`, espaces et autres signes deviennent `-`, accents retirés, majuscules. `LABO_ANA` → `LABO-ANA`, `WIFI INVITE` → `WIFI-INVITE`, `SAN Mgmt` → `SAN-MGMT`. Sans cela on ne pourrait plus découper le nom sur `_`. Deux interfaces qui donnent le même nom normalisé (`VLAN-20` et `VLAN_20`) sont signalées par `fwclean reseaux` : en renommer une dans la colonne.

La **zone** n'apparaît que dans les réseaux FortiGate. C'est la zone FortiGate traduite par [`contextes.txt`](../contextes.txt) en nom court d'un seul segment (`mgmt = MGMT NETWORKS`). Stormshield n'a pas de zones : ses réseaux n'ont jamais de segment zone.

La comparaison est **case-insensitive** : les fichiers gardent leurs clés en minuscules (`siege`, `lan`), les noms les écrivent en majuscules. Ajouter un site, une interface ou une zone ne demande pas de modifier le programme.

Zones livrées dans `contextes.txt`, reprises des zones FortiGate d'EPFRFORTI01 :

| Zone (fichier) | Dans un nom | Zone FortiGate |
| --- | --- | --- |
| `lan` | `LAN` | `LAN` : réseaux internes |
| `dmz` | `DMZ` | `DMZ` : zone exposée |
| `wan` | `WAN` | `WAN` (zone SD-WAN) : accès opérateur |
| `mgmt` | `MGMT` | `MGMT NETWORKS` : iDRAC, Datacore, SAN |
| `bastion` | `BASTION` | `Bastion ADMIN_MGMT` |
| `users` | `USERS` | `Users LAN` : Wi-Fi corporate |
| `preprodfr` | `PREPRODFR` | `PreProd FRANCE` |
| `preprodth` | `PREPRODTH` | `PreProd THAILANDE` |
| `invite` | `INVITE` | `WIFI INVITE VLAN-42` |
| `mobile` | `MOBILE` | `WIFI MOBILE VLAN-41` |

Les anciennes entrées `vpn`, `oob` et `loop` (interfaces hors zone `ssl.root`, `mgmt`, `LOOPMGMT`) et les correspondances d'interfaces Stormshield (`FObouygues`, `HA`, `VTI_FRSI_THUS`…) sont retirées : ces interfaces ont maintenant leur propre nom dans la colonne `interface`.

`MULTI` est réservé, toujours accepté comme site et comme interface, à ne pas mettre dans les fichiers : les membres d'un groupe (ou les bornes d'un pool) sont sur plusieurs sites ou plusieurs interfaces.

**Pas de nom sans correspondance.** Un objet d'adresse dont le site ou l'interface reste introuvable n'est pas renommé. Le rapport le liste avec le traitement `revoir` et un commentaire (« site et interface introuvables : adresse absente de reseaux.csv », « interface introuvable : réseau de reseaux.csv sans colonne interface… »), et le plan le reprend dans `a_revoir`. On complète `reseaux.csv` puis on relance l'audit. `CTX` n'apparaît dans aucun nom proposé, et un nom existant en `CTX` n'est pas conforme.

**Conformité.** Quand le site et l'interface d'un objet sont connus, son nom doit les porter : `SIEGE_HST_DMZ_X` n'est pas conforme pour une adresse du réseau `SERVEURS`, et un nom de l'ancienne convention par zone (`HQ_HST_LAN_PC01`) ne l'est plus. Un réseau doit en plus porter la bonne zone et le bon VLAN. Pour un objet non localisable, seule la forme est vérifiée (site et interface connus de `reseaux.csv`).

### Référentiel `reseaux.csv`

Fichier à la racine du projet, fourni par l'équipe réseau. Autre chemin : `--reseaux`.

```text
reseau;site;zone;vlan;interface
10.0.16.0/24;hq;lan;16;CABINES
10.118.131.0/24;hq;mgmt;131;IDRAC
192.168.1.0/24;hq;;;mgmt
89.90.126.128/29;hq;;;FObouygues
10.210.0.0/24;gras;;210;SRV
```

- séparateur `;`, en-tête `reseau;site;zone;vlan;interface` ;
- un réseau CIDR par ligne (IPv4 ou IPv6) ;
- site et zone en minuscules ; `zone` facultative : vide hors zone FortiGate, toujours vide pour Stormshield ; si elle est remplie, elle doit être dans `contextes.txt` ;
- `vlan` facultatif : VLAN ID de 1 à 4094 ;
- `interface` : nom de l'interface tel que l'écrit l'équipement (`VLAN-16`, `LABO_ANA`), remplie par `fwclean reseaux` et **modifiable à la main**, par exemple pour remplacer avant la migration un nom qui ne dit rien (`port3`, `VLAN-16`) par le libellé du réseau (`CABINES`) ;
- lignes vides et commentaires `#` ignorés ; un en-tête répété plus bas (bloc collé) est ignoré ;
- un même réseau déclaré deux fois avec un site, une zone, un VLAN ou une interface différents est refusé.

**Ancien format.** Un fichier `reseau;site;zone;vlan` (ou `reseau;site;zone`), ou une ligne plus courte que l'en-tête, reste lu : l'interface manque, les objets de ces réseaux sont **à revoir** (« interface introuvable : réseau de reseaux.csv sans colonne interface »), et une zone absente de `contextes.txt` y est ignorée. `fwclean reseaux … --ajouter` migre ces lignes (voir [la méthode](methode-nettoyage.md#référentiel-réseaux)).

**Sites distants.** Les réseaux connectés viennent de `fwclean reseaux` ; les autres (sites distants, pools VPN, IP publiques) s'ajoutent à la main. Pour un site distant, l'interface est le libellé du VLAN (`SRV`, `POSTE-FILAIRE`…) et la zone reste vide : `10.210.0.0/24;gras;;210;SRV`. Un nouveau site est un ajout libre : l'écrire suffit à le rendre valide dans les noms (`GRAS_HST_SRV_…`).

Le plan d'adressage réel est sensible : `reseaux.csv` est ignoré par git. Le dépôt versionne seulement [`reseaux.exemple.csv`](../reseaux.exemple.csv), à copier. Sans `reseaux.csv`, l'audit tourne quand même : aucun site n'est connu, les objets d'adresse non conformes sont tous signalés à revoir.

### Déduction

| Objet | Site | Interface |
| --- | --- | --- |
| hôte, réseau, plage | réseau **le plus précis** du référentiel qui contient l'objet | idem |
| hôte, réseau, plage hors référentiel | introuvable → à revoir | idem |
| groupe d'adresses | commun à tous les membres | commune à tous les membres, `MULTI` s'ils sont sur plusieurs interfaces ; aucun membre localisé : interface citée dans l'ancien nom |
| VIP | celui de l'adresse interne (`mappedip`) | idem ; adresse interne inconnue → à revoir, sans repli |
| pool | réseau qui contient toute la plage, sinon commun aux deux bornes | idem |
| FQDN | site trouvé dans l'ancien nom, sinon à revoir | interface trouvée dans l'ancien nom, sinon à revoir |

« Commun » : si tous les membres localisés ont la même valeur, c'est elle ; s'ils en ont plusieurs, `MULTI` ; si aucun n'est localisé, l'objet est à revoir. Un membre non localisé ne compte pas : un groupe d'un hôte `SIEGE` et d'une adresse partenaire hors référentiel reste `SIEGE`. Exemple : `HQ_GRP_CABINES_…` ou `HQ_GRP_MULTI_…`.

Avec le référentiel d'exemple, `10.1.1.10` est dans `10.1.0.0/16` (`SERVEURS`) et dans `10.1.1.0/24` (`DMZ`) : le `/24` est plus précis, l'hôte devient `SIEGE_HST_DMZ_…`.

Le détail reprend l'ancien nom sans préfixe, et sans le site et l'interface retenus : `SIEGE_zabbix` → `SIEGE_HST_LAN-USERS_ZABBIX`, `Web_DMZ` → `SIEGE_HST_DMZ_WEB`. Un ancien nom déjà découpé garde seulement son dernier segment, même si son site n'est pas connu, qu'il soit dans l'ordre site, préfixe (`GRAS_HST_DMZ_WEB-01`) ou dans l'ancien ordre préfixe, site (`HST_SIEGE_DMZ_WEB-01`) : il devient `SIEGE_HST_DMZ_WEB-01`. L'ancienne zone n'est jamais recopiée dans le détail : les noms du lot 01 déjà appliqués sur le lab (`HQ_NET_LAN_VLAN11-RES`, `HQ_GRP_LAN_…`, `HQ_HST_LOOP_…`) sont reconnus, `HQ_GRP_LAN_IMPRIMANTES` devient `HQ_GRP_CABINES_IMPRIMANTES`.

## Réseaux

Un objet réseau prend le site, la zone, le VLAN et l'interface de la ligne de `reseaux.csv` la plus précise qui le contient :

- **réseau identique** à celui de l'interface : le nom se termine par l'interface et ne garde rien de l'ancien nom. `Res-VLAN16` (`10.0.16.0/24`) → `HQ_NET_LAN_V16_CABINES` ;
- **sous-réseau** plus petit (une `/28` dans une `/24`) : l'ancien nom reste en détail après l'interface, sinon plusieurs objets auraient le même nom. `Imprimantes` (`10.0.16.0/28`) → `HQ_NET_LAN_V16_CABINES-IMPRIMANTES` ;
- **sans VLAN** (port physique, ligne sans `vlan`) : pas de segment `V`. `HQ_NET_LAN_CABINES` ;
- **sans zone** (interface hors zone FortiGate, Stormshield) : pas de segment zone. `HQ_NET_V16_CABINES` ;
- un réseau à cheval sur plusieurs lignes de `reseaux.csv` est à revoir.

Le VLAN vient toujours de la colonne `vlan` de la ligne retenue, jamais de l'ancien nom : les mentions `VLAN11`, `vlan-11`, `[valn50]` sont retirées du détail et `V{ID}` a son propre segment (l'ancien `HQ_NET_LAN_VLAN25-RES` devient `HQ_NET_LAN_V25_…`). Un réseau dont le nom ne porte pas la bonne zone, le bon VLAN et la bonne interface n'est pas conforme.

## Services

Un service n'a ni site ni interface. Sa forme est `SVC_{PROTOCOLE}_{PORTS}_{LIBELLE}` :

| Segment | Valeur | Exemples |
| --- | --- | --- |
| protocole | `TCP`, `UDP`, `ANY` quand TCP et UDP sont tous deux ouverts ; `ICMP`, `ICMP6`, `IP`, `SCTP` pour les autres | `SVC_TCP_443_HTTPS`, `SVC_UDP_389_LDAP`, `SVC_ANY_53_DNS` |
| ports | port de destination ; plage en `-` ; plusieurs ports séparés par `.` ; type ICMP ou numéro de protocole IP ; `ANY` pour tout ICMP ou tout IP | `SVC_UDP_67-68_DHCP`, `SVC_ANY_88.464_KERBEROS`, `SVC_ICMP_8_PING`, `SVC_IP_47_GRE` |
| libellé | l'ancien nom, sans les mots de protocole ni les numéros de port déjà présents ; facultatif | `HTTP-8080` → `SVC_TCP_8080_HTTP`, `MS Global Catalog` → `SVC_TCP_3268-3269_MS-GLOBAL-CATALOG`, `SVC_TCP_443` reste `SVC_TCP_443` |

Sur Stormshield, un objet `[Protocol]` (fichier natif `object`, cité par `ipproto` dans une règle) suit la même forme avec le protocole `IP` : `gre_tunnel=47` → `SVC_IP_47_GRE-TUNNEL`. Il a son propre espace de noms : un protocole `rdp` (IP 27) et un service `rdp` (TCP/3389) coexistent et deviennent `SVC_IP_27_RDP` et `SVC_TCP_3389_RDP`.

Protocole et ports sont calculés sur le **contenu** du service, pas sur son ancien nom : `SVC_UDP_443_HTTPS` pour un service TCP/443 n'est pas conforme. Quand TCP et UDP n'ouvrent pas les mêmes ports, `ANY` est suivi de tous les ports (`netbios` → `SVC_ANY_137.138.139_NETBIOS`) ; le détail par protocole reste dans le contenu, repris par le rapport. Les ports source ne figurent pas dans le nom.

## Groupes de services, calendriers

Ni site ni interface. Leur forme est `{PREFIXE}_{DETAIL}`, et le détail **garde le libellé de l'ancien nom** : `Active Directory` → `SG_ACTIVE-DIRECTORY`, `Bureau` → `SCH_BUREAU`.

L'ancien préfixe `SGRP` n'est plus conforme : `SGRP_WEB` est proposé au renommage en `SG_WEB`, sans répéter `SGRP` dans le détail.

## Règles

Les règles ne sont **pas renommées** pour le moment : `fwclean` ne signale pas leur nom et n'en propose aucun. Elles servent seulement à compter les références des objets (source, destination, service, calendrier, pool), y compris quand elles sont désactivées.

## Exemples non conformes

Avec `reseaux.exemple.csv` :

| Nom actuel | Contenu | Pourquoi | Nom proposé (si l'objet est conservé) |
| --- | --- | --- | --- |
| `web_dmz_backup` | `10.1.1.20/32` | pas de préfixe ni de site | `SIEGE_HST_DMZ_WEB-BACKUP` |
| `Vlan210` | `10.210.0.0/24`, site distant | pas de préfixe ni de site | `GRAS_NET_V210_GRAS-210` |
| `partenaire` | `192.0.2.10/32` | hors référentiel | aucun : à revoir, « site et interface introuvables » |
| `Clients web` | membres `SIEGE` et `GRAS` | espace, deux sites et deux interfaces | `MULTI_GRP_MULTI_CLIENTS-WEB` |
| `HST-DMZ-WEB-01` | `10.1.1.10/32` | ancienne forme, sans site | `SIEGE_HST_DMZ_WEB-01` |
| `LAN Utilisateurs` | `10.0.0.0/24`, réseau de l'interface `LAN-USERS` | espace, pas de VLAN | `SIEGE_NET_LAN_V10_LAN-USERS` |
| `SRV-ESX [vlan11]` | `10.1.2.0/24` dans `10.1.0.0/16` (`SERVEURS`) | sous-réseau | `SIEGE_NET_LAN_SERVEURS-SRV-ESX` |
| `SIEGE_HST_LAN_LEGACY` | `10.0.0.50/32` | ancienne zone au lieu de l'interface | `SIEGE_HST_LAN-USERS_LEGACY` |
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
