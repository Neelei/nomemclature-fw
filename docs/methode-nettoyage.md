# Méthode de nettoyage

Trois opérations, toujours dans cet ordre, et seulement après relecture humaine du rapport et du plan. `fwclean` ne se connecte pas aux firewalls et n'écrit rien dans l'export.

1. **Renommage** — l'objet ou la règle ne change pas de contenu, seulement de nom. Les références suivent.
2. **Fusion de doublons stricts** — même type et même contenu. Les références des objets supprimés sont réécrites vers l'objet conservé.
3. **Orphelins** — objet sans aucune référence. Le plan liste un retrait. Rien n'est supprimé automatiquement.

Un objet utilisé seulement par une règle désactivée n'est pas orphelin.

## Renommage

Le contenu (adresse, membres, ports, action, source, destination, service) reste celui de l'export. Le nom proposé suit [la nomenclature](nomenclature.md).

Le site et la zone d'un nom proposé viennent d'abord du réseau : l'adresse de l'objet est cherchée dans `reseaux.csv`, le réseau le plus précis qui la contient donne le site et la zone. Hors référentiel, la zone vient de l'ancien nom et le site vaut `CTX`. Groupes, VIP, pools et règles prennent le site et la zone communs à leurs membres, ou `MULTI`. Le détail est dans [la nomenclature](nomenclature.md#déduction).

L'outil ne renomme pas un objet qui part en fusion, ni un orphelin : le retrait ou la fusion suffit. Le rapport Markdown les montre quand même dans les noms non conformes, avec le traitement prévu.

Si le nom proposé est déjà pris par un objet qui existe encore au moment du renommage, un suffixe `-01`, `-02`, … est ajouté.

## Doublon strict

Deux objets sont fusionnables seulement s'ils ont le même type et la même empreinte :

| Type | Contenu comparé |
| --- | --- |
| Hôte | adresses IP (v4 et v6 si les deux sont renseignées), masque d'hôte |
| Réseau | adresse réseau et longueur de préfixe (`255.255.255.0` et `/24` sont le même masque) |
| Plage | première et dernière adresse |
| FQDN | le nom DNS, sans tenir compte de la casse ni d'un point final |
| Groupe d'adresses | les mêmes membres, l'ordre ne compte pas. Les noms des membres sont comparés tels quels : deux groupes qui pointent vers des hôtes équivalents mais nommés différemment ne sont pas fusionnés |
| Service | protocole et ports (plages comprises). `tcp/443` et `tcp/443-443` sont identiques |
| Groupe de services | les mêmes membres |
| VIP | IP externe, IP ou objet mappé, ports et protocole. L'interface d'écoute n'entre pas dans la comparaison |
| Pool | première et dernière adresse |
| Calendrier | jours (après normalisation) et horaires, ou fenêtre unique. `monday-friday` équivaut à la liste lundi–vendredi |

Les commentaires, UUID et couleurs ne comptent pas.

L'objet conservé est choisi dans cet ordre :

1. celui dont le nom est déjà conforme ;
2. sinon le plus référencé ;
3. sinon le nom le plus court ;
4. à égalité, le nom qui arrive en premier dans l'ordre alphabétique.

Les règles ne sont pas fusionnées, même si deux règles se ressemblent. Le NAT n'est pas réécrit : seules les références d'objets qui y figurent sont comptées, pour ne pas déclarer orphelin un objet qui ne sert qu'au NAT.

## Orphelins

Une référence est l'une des suivantes, qu'elle vienne d'un objet lui-même inutilisé ou non :

- règle de filtrage active ou désactivée (source, destination, service, calendrier, pool) ;
- membre d'un groupe d'adresses ou de services ;
- objet mappé par une VIP ;
- règle de NAT ;
- route statique ou policy-route, quand l'export la contient.

L'objet conservé d'une fusion n'est pas listé comme doublon à retirer. S'il n'a ensuite aucune référence, il apparaît dans les retraits : la fusion a d'abord éliminé les copies, le retrait concerne le survivant.

## Hors périmètre

Chevauchements de réseaux, fusion ou réordonnancement de règles, changement d'action, de NAT, d'utilisateurs ou de certificats, poussée vers l'équipement. Le premier passage sur les exports réels sert à compléter `reseaux.csv` et à ajuster [`contextes.txt`](../contextes.txt), pas à réécrire les règles.

Un objet dont le nom est conforme mais dont le site ou la zone ne correspond pas à son adresse n'est pas signalé : la conformité porte sur la forme du nom.

## Exports lus

Les fichiers réels se déposent dans `inbox/` (ignoré par git). Les exemples du dépôt sont synthétiques.

### Référentiel réseaux

`reseaux.csv` à la racine (ignoré par git), ou le fichier donné par `--reseaux`. Format `reseau;site;zone`, un CIDR par ligne, site et zone en minuscules, commentaires `#` acceptés :

```text
reseau;site;zone
10.1.0.0/16;epfr;lan
10.1.1.0/24;epfr;dmz
10.210.0.0/24;gras;lan
```

Partir de [`reseaux.exemple.csv`](../reseaux.exemple.csv). Un réseau invalide, une zone absente de `contextes.txt` ou un même réseau déclaré avec deux sites arrêtent l'audit avec un message. Sans référentiel, l'audit tourne et tous les sites proposés valent `CTX`.

### FortiGate

Sauvegarde texte `.conf`. Sections lues :

- `config firewall address`
- `config firewall addrgrp`
- `config firewall service custom`
- `config firewall service group`
- `config firewall vip`
- `config firewall ippool`
- `config firewall schedule recurring` et `schedule onetime`
- `config firewall policy`
- `config router static` et `config router policy`

Un hôte FortiGate est une adresse `ipmask` en `/32`. Une adresse `iprange` est une plage, une adresse `fqdn` un nom DNS. Les types `geography`, `dynamic` et `mac` sont ignorés et signalés dans le rapport.

```bash
fwclean audit inbox/pare-feu.conf --sortie out
```

### Stormshield

Une sauvegarde `.na` est chiffrée : elle n'est pas lue. Exporter deux CSV, et éventuellement les routes.

**Objets** — module Objets > OBJETS RÉSEAU / TEMPS, une ligne par objet, virgule, sans en-tête. Les champs vides restent entre deux virgules. C'est le format décrit dans l'annexe « Structure d'une base objets au format CSV » (SNS).

| Type | Champs utilisés |
| --- | --- |
| `host` | nom, IPv4, IPv6 |
| `network` | nom, IPv4, masque |
| `range` | nom, première IPv4, dernière IPv4 |
| `fqdn` | le nom de l'objet est le FQDN |
| `group` | nom, membres entre guillemets, séparés par des virgules |
| `service` | nom, protocole (`tcp`, `udp`, `any`), port ou bornes de plage |
| `servicegroup` | nom, membres |
| `protocol` | nom, numéro IANA (traité comme un service `ip`) |
| `time` | nom, horaire (`08:00-18:00`), jours (`monday-friday`), période éventuelle |
| `router` | ignoré |

```text
host,HST-EPFR-DMZ-WEB-01,10.1.1.10,,,,"Serveur web"
network,NET-EPFR-LAN-UTILISATEURS,10.0.0.0,255.255.255.0,,,"LAN"
service,SVC-TCP-443,tcp,443,,,"HTTPS"
group,GRP-EPFR-DMZ-WEB,"HST-EPFR-DMZ-WEB-01",""
time,SCH-CTX-LAN-BUREAU,08:00-18:00,monday-friday,,""
```

**Règles de filtrage** — CSV avec en-tête, virgule ou point-virgule. Une ligne `nat` (colonne `type` ou action `nat`) n'est pas auditée comme une règle : elle sert uniquement à connaître les objets qu'elle cite.

| Colonne | Alias acceptés | Rôle |
| --- | --- | --- |
| `nom` | `name`, `rulename` | nom de la règle |
| `etat` | `status`, `state` | `on` / `off` (les deux comptent comme référence) |
| `action` | | `pass` ou `accept` → allow, `block` ou `deny` → deny |
| `type` | `type_slot` | `filter` ou `nat` |
| `source` | `src` | objets source, séparés par des virgules |
| `destination` | `dst` | objets destination |
| `service` | `port`, `dstport` | objet service |
| `interface_source` | `srcif`, `srcintf` | zone source si elle figure dans `contextes.txt` (sinon zone des objets via `reseaux.csv`) |
| `interface_destination` | `dstif`, `dstintf` | zone destination |
| `planification` | `schedule`, `time` | objet calendrier |
| `source_traduite` | `pool`, `nat_src` | objet cité par le NAT |
| `destination_traduite` | `vip`, `nat_dst` | objet cité par le NAT |

**Routes** (facultatif) — en-tête `destination,passerelle` (alias `dst`, `gateway`). Une passerelle qui est une adresse IP n'est pas un objet. Sans ce fichier, une route absente de l'export ne peut pas empêcher un faux orphelin : le déposer si des objets ne servent qu'au routage.

```bash
fwclean audit inbox/objets.csv inbox/regles.csv inbox/routes.csv --sortie out
```

Un dossier qui contient ces CSV marche aussi : `fwclean audit inbox/ --sortie out`.

## Sorties

Dans le dossier `--sortie` (défaut `out/`, ignoré par git) :

- `rapport.md` — référentiel réseaux utilisé, noms non conformes, doublons, orphelins, compteurs ;
- `plan.json` — la proposition, et rien d'autre.

Clés du plan :

| Clé | Contenu |
| --- | --- |
| `avertissement` | rappel que rien n'a été appliqué |
| `constructeur` | `fortigate` ou `stormshield` |
| `sources` | fichiers lus |
| `renommages` | `sorte`, `ancien`, `nouveau`, `references` |
| `fusions` | `sorte`, `contenu`, `conserve`, `nouveau_nom`, `supprimes`, `references_reecrites` |
| `retraits` | `sorte`, `nom`, `motif` (`aucune reference`) |

`nouveau_nom` est le nom de l'objet conservé après un éventuel renommage. Il est identique à `conserve` quand le nom était déjà conforme.

Les valeurs de `sorte` sont stables : `hote`, `reseau`, `plage`, `fqdn`, `groupe-adresses`, `service`, `groupe-services`, `vip`, `pool`, `calendrier`, `regle`.
