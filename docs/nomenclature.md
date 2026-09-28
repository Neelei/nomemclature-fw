# Nomenclature firewall

Convention commune pour les objets et le nom des règles FortiGate et Stormshield. Elle ne décrit pas les flux : une règle garde son action, sa source, sa destination et son service. Seul le nom change, et seulement après relecture du plan proposé par `fwclean`.

## Forme

`{PREFIXE}-{CONTEXTE}-{DETAIL}`

- majuscules uniquement (`A-Z`, `0-9`) ;
- segments séparés par un tiret simple, sans tiret en début, en fin, ni doublé ;
- pas d'espace, d'underscore, de point, ni d'accent ;
- au moins trois segments : préfixe, contexte, détail ;
- 79 caractères au plus (limite FortiGate sur le nom d'une adresse). La même limite est appliquée aux autres noms pour que la convention tienne sur les deux constructeurs.

## Préfixes

| Préfixe | Objet | Exemple |
| --- | --- | --- |
| `HST` | hôte | `HST-DMZ-WEB-01` |
| `NET` | réseau | `NET-LAN-UTILISATEURS` |
| `RNG` | plage d'adresses | `RNG-VPN-CLIENTS` |
| `FQDN` | nom DNS | `FQDN-WAN-UPDATES` |
| `GRP` | groupe d'adresses | `GRP-DMZ-WEB` |
| `SVC` | service | `SVC-TCP-443` |
| `SGRP` | groupe de services | `SGRP-DMZ-WEB` |
| `VIP` | VIP | `VIP-WAN-WEB` |
| `POOL` | pool d'adresses (FortiGate) | `POOL-WAN-SORTANT` |
| `SCH` | calendrier | `SCH-LAN-BUREAU` |

Le préfixe doit correspondre au type réel de l'objet. `NET-DMZ-WEB` n'est pas un nom conforme pour un hôte.

## Contexte organisationnel

Le deuxième segment est un contexte d'organisation : zone ou code site. La liste vit dans [`contextes.txt`](../contextes.txt), à la racine du projet.

Le fichier `contextes.txt` garde les clés en **minuscules** (`dmz`, `lan`, …). L'outil les lit ainsi et les compare de façon **case-insensitive**. Les noms proposés et les noms conformes utilisent le contexte en **majuscules** (`DMZ`, `LAN`, …). Ajouter un code site ne demande pas de modifier le programme.

Liste livrée :

| Contexte (fichier) | Dans un nom | Sens |
| --- | --- | --- |
| `dmz` | `DMZ` | zone exposée |
| `lan` | `LAN` | réseau interne |
| `wan` | `WAN` | accès Internet ou opérateur |
| `vpn` | `VPN` | accès distants |
| `ctx` | `CTX` | contexte provisoire |

`CTX` sert quand le nom d'origine ne contient aucun contexte connu. Le plan propose alors `HST-CTX-…`, le temps d'ajuster la liste sur le vocabulaire réel. Une fois les codes site ajoutés, on peut retirer `ctx` : le repli devient le premier contexte du fichier.

Les interfaces du firewall ne sont pas renommées. `lan` dans une règle est le nom de zone déjà en place, repris seulement pour proposer un nom de règle.

## Services

Un service n'utilise pas le contexte d'organisation. Sa forme est `{SVC}-{PROTOCOLE}-{DETAIL}` :

- protocole : `TCP`, `UDP`, `ICMP`, `IP`, `SCTP` ou `ANY` ;
- détail : le port (`SVC-TCP-443`, `SVC-UDP-53`), une plage (`SVC-TCP-2000-2032`), ou un nom court pour ICMP (`SVC-ICMP-ECHO`).

Un groupe de services reste organisationnel : `SGRP-DMZ-WEB`.

## Règles

`{ALLOW|DENY}-{ZONE-SOURCE}-{ZONE-DESTINATION}-{SERVICE}`

- `ALLOW` ou `DENY` reprend l'action déjà configurée (`accept` / `pass` → allow, `deny` / `block` → deny). On ne change pas l'action pour faire coller le nom ;
- les deux zones sont des contextes organisationnels (`DMZ`, `LAN`, `WAN`, `VPN`, ou un code site de la liste) ;
- le dernier segment décrit le service, en un ou plusieurs morceaux : `HTTPS`, `TCP-443` ;
- un suffixe `-01` à `-99` lève un homonyme. Il n'est pas confondu avec un port : `ALLOW-LAN-DMZ-TCP-80` garde `80` comme port, parce qu'il suit le protocole.

Exemples : `ALLOW-LAN-DMZ-HTTPS`, `DENY-WAN-LAN-ANY`, `ALLOW-LAN-DMZ-TCP-443`, `ALLOW-LAN-DMZ-HTTPS-01`.

Un nom déjà conforme n'est pas réécrit, même si l'outil aurait choisi un autre libellé de service. `ALLOW-LAN-DMZ-HTTPS` reste, y compris si l'objet service s'appelle `SVC-TCP-443`.

## Exemples non conformes

| Nom actuel | Pourquoi | Nom proposé (si l'objet est conservé) |
| --- | --- | --- |
| `Web_DMZ` | underscore, pas de préfixe | `HST-DMZ-WEB` |
| `LAN Utilisateurs` | espace | `NET-LAN-UTILISATEURS` |
| `HTTPS custom` | espace, pas de préfixe | `SVC-TCP-443` si le contenu est TCP/443 |
| `Acces web` | le nom de règle ne suit pas l'action et les zones | `ALLOW-LAN-DMZ-TCP-443` quand les interfaces sont `lan` et `dmz` et le service `SVC-TCP-443` |
| `hst-dmz-web-01` | minuscules : la forme exige des majuscules | `HST-DMZ-WEB-01` |

Si ce nom désigne un doublon strict, le plan ne le renomme pas : il le fusionne vers l'objet conservé. S'il ne sert nulle part, le plan propose son retrait, pas un renommage.

## Ce que la convention ne couvre pas

Utilisateurs, certificats, interfaces, zones constructeur, politiques VPN et objets géographiques ou dynamiques. Ces derniers sont signalés comme ignorés, sans proposition de nom.
