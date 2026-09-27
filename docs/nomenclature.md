# Nomenclature firewall

Convention commune pour les objets et le nom des règles FortiGate et Stormshield. Elle ne décrit pas les flux : une règle garde son action, sa source, sa destination et son service. Seul le nom change, et seulement après relecture du plan proposé par `fwclean`.

## Forme

`{prefixe}-{contexte}-{detail}`

- minuscules uniquement (`a-z`, `0-9`) ;
- segments séparés par un tiret simple, sans tiret en début, en fin, ni doublé ;
- pas d'espace, d'underscore, de point, ni d'accent ;
- au moins trois segments : préfixe, contexte, détail ;
- 79 caractères au plus (limite FortiGate sur le nom d'une adresse). La même limite est appliquée aux autres noms pour que la convention tienne sur les deux constructeurs.

## Préfixes

| Préfixe | Objet | Exemple |
| --- | --- | --- |
| `hst` | hôte | `hst-dmz-web-01` |
| `net` | réseau | `net-lan-utilisateurs` |
| `rng` | plage d'adresses | `rng-vpn-clients` |
| `fqdn` | nom DNS | `fqdn-wan-updates` |
| `grp` | groupe d'adresses | `grp-dmz-web` |
| `svc` | service | `svc-tcp-443` |
| `sgrp` | groupe de services | `sgrp-dmz-web` |
| `vip` | VIP | `vip-wan-web` |
| `pool` | pool d'adresses (FortiGate) | `pool-wan-sortant` |
| `sch` | calendrier | `sch-lan-bureau` |

Le préfixe doit correspondre au type réel de l'objet. `net-dmz-web` n'est pas un nom conforme pour un hôte.

## Contexte organisationnel

Le deuxième segment est un contexte d'organisation : zone ou code site. La liste vit dans [`contextes.txt`](../contextes.txt), à la racine du projet. L'outil la lit telle quelle. Ajouter un code site ne demande pas de modifier le programme.

Liste livrée :

| Contexte | Sens |
| --- | --- |
| `dmz` | zone exposée |
| `lan` | réseau interne |
| `wan` | accès Internet ou opérateur |
| `vpn` | accès distants |
| `ctx` | contexte provisoire |

`ctx` sert quand le nom d'origine ne contient aucun contexte connu. Le plan propose alors `hst-ctx-…`, le temps d'ajuster la liste sur le vocabulaire réel. Une fois les codes site ajoutés, on peut retirer `ctx` : le repli devient le premier contexte du fichier.

Les interfaces du firewall ne sont pas renommées. `lan` dans une règle est le nom de zone déjà en place, repris seulement pour proposer un nom de règle.

## Services

Un service n'utilise pas le contexte d'organisation. Sa forme est `{svc}-{protocole}-{detail}` :

- protocole : `tcp`, `udp`, `icmp`, `ip`, `sctp` ou `any` ;
- détail : le port (`svc-tcp-443`, `svc-udp-53`), une plage (`svc-tcp-2000-2032`), ou un nom court pour ICMP (`svc-icmp-echo`).

Un groupe de services reste organisationnel : `sgrp-dmz-web`.

## Règles

`{allow|deny}-{zone-source}-{zone-destination}-{service}`

- `allow` ou `deny` reprend l'action déjà configurée (`accept` / `pass` → `allow`, `deny` / `block` → `deny`). On ne change pas l'action pour faire coller le nom ;
- les deux zones sont des contextes organisationnels (`dmz`, `lan`, `wan`, `vpn`, ou un code site de la liste) ;
- le dernier segment décrit le service, en un ou plusieurs morceaux : `https`, `tcp-443` ;
- un suffixe `-01` à `-99` lève un homonyme. Il n'est pas confondu avec un port : `allow-lan-dmz-tcp-80` garde `80` comme port, parce qu'il suit le protocole.

Exemples : `allow-lan-dmz-https`, `deny-wan-lan-any`, `allow-lan-dmz-tcp-443`, `allow-lan-dmz-https-01`.

Un nom déjà conforme n'est pas réécrit, même si l'outil aurait choisi un autre libellé de service. `allow-lan-dmz-https` reste, y compris si l'objet service s'appelle `svc-tcp-443`.

## Exemples non conformes

| Nom actuel | Pourquoi | Nom proposé (si l'objet est conservé) |
| --- | --- | --- |
| `Web_DMZ` | majuscules, underscore, pas de préfixe | `hst-dmz-web` |
| `LAN Utilisateurs` | espace et majuscules | `net-lan-utilisateurs` |
| `HTTPS custom` | espace, pas de préfixe | `svc-tcp-443` si le contenu est TCP/443 |
| `Acces web` | le nom de règle ne suit pas l'action et les zones | `allow-lan-dmz-tcp-443` quand les interfaces sont `lan` et `dmz` et le service `svc-tcp-443` |

Si ce nom désigne un doublon strict, le plan ne le renomme pas : il le fusionne vers l'objet conservé. S'il ne sert nulle part, le plan propose son retrait, pas un renommage.

## Ce que la convention ne couvre pas

Utilisateurs, certificats, interfaces, zones constructeur, politiques VPN et objets géographiques ou dynamiques. Ces derniers sont signalés comme ignorés, sans proposition de nom.
