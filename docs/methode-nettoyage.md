# Méthode de nettoyage

Trois opérations, toujours dans cet ordre, et seulement après relecture humaine du rapport et du plan. `fwclean` ne se connecte pas aux firewalls et n'écrit rien dans l'export.

1. **Renommage** — l'objet ne change pas de contenu, seulement de nom. Les références suivent. Les règles ne sont pas renommées pour le moment.
2. **Fusion de doublons stricts** — même type et même contenu. Les références des objets supprimés sont réécrites vers l'objet conservé.
3. **Orphelins** — objet sans aucune référence. Le plan liste un retrait. Rien n'est supprimé automatiquement.

Un objet utilisé seulement par une règle désactivée n'est pas orphelin.

## Renommage

Le contenu (adresse, membres, ports, action, source, destination, service) reste celui de l'export. Le nom proposé suit [la nomenclature](nomenclature.md).

Le site et la zone d'un nom proposé viennent d'abord du réseau : l'adresse de l'objet est cherchée dans `reseaux.csv`, le réseau le plus précis qui la contient donne le site et la zone. Groupes, VIP et pools prennent le site et la zone communs à leurs membres, ou `MULTI`. Un réseau dont le VLAN est connu (interface VLAN FortiGate ou SNS, sinon colonne `vlan` de `reseaux.csv`) porte `VLAN{ID}` dans son détail. Services, groupes de services et calendriers n'ont ni site ni zone. Un service porte son protocole et ses ports, calculés sur son contenu, puis le libellé de son ancien nom (`HTTP-8080` → `SVC_TCP_8080_HTTP`). Le détail est dans [la nomenclature](nomenclature.md#déduction).

Un objet d'adresse sans correspondance de site ou de zone n'est **pas renommé** : il est listé à revoir, avec un commentaire qui dit ce qui manque. Compléter `reseaux.csv` puis relancer l'audit.

L'outil ne renomme pas un objet qui part en fusion, ni un orphelin : le retrait ou la fusion suffit. Le rapport Markdown les montre quand même dans les noms non conformes, avec le traitement prévu.

Si le nom proposé est déjà pris par un objet qui existe encore au moment du renommage, un suffixe `-01`, `-02`, … est ajouté au dernier segment. Le nom reste dans la limite du constructeur (31 caractères pour un calendrier FortiGate, 79 sinon) : c'est le détail qui est raccourci.

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

1. sur Stormshield, un [objet natif du SNS](#objets-natifs-sns) ;
2. sinon celui dont le nom est déjà conforme ;
3. sinon le plus référencé ;
4. sinon le nom le plus court ;
5. à égalité, le nom qui arrive en premier dans l'ordre alphabétique.

Un objet natif n'est jamais dans les objets fusionnés à supprimer : `rdp_admin` (`3389/tcp`) est fusionné dans le service natif `rdp`, qui garde son nom. Un doublon composé seulement d'objets natifs n'est pas proposé.

Les règles ne sont pas fusionnées, même si deux règles se ressemblent. Le NAT n'est pas réécrit : seules les références d'objets qui y figurent sont comptées, pour ne pas déclarer orphelin un objet qui ne sert qu'au NAT.

## Orphelins

Une référence est l'une des suivantes, qu'elle vienne d'un objet lui-même inutilisé ou non :

- règle de filtrage active ou désactivée (source, destination, service, calendrier, pool) ;
- membre d'un groupe d'adresses ou de services ;
- objet mappé par une VIP ;
- règle de NAT ;
- route statique ou policy-route, quand l'export la contient ;
- sur Stormshield : route par défaut, routes statiques, routeur ou passerelle cité par une règle (`route`), objets traduits du NAT (`->`).

Si l'export ne permet pas de voir toutes les références, **aucun retrait n'est proposé** : le rapport affiche « Orphelins : suspendus » et la raison, le plan garde `retraits` vide et l'explique dans `avertissements.retraits_suspendus`. C'est le cas sur Stormshield tant que `objectgroup` et `servicegroup` ne sont pas tous deux lus (voir [Stormshield](#stormshield-fichiers-natifs)). Les orphelins sont alors traités comme les autres objets : renommés s'ils sont non conformes.

Un objet natif du SNS n'est jamais proposé au retrait, même sans référence.

L'objet conservé d'une fusion n'est pas listé comme doublon à retirer. S'il n'a ensuite aucune référence, il apparaît dans les retraits : la fusion a d'abord éliminé les copies, le retrait concerne le survivant.

## Hors périmètre

Chevauchements de réseaux, renommage, fusion ou réordonnancement de règles, changement d'action, de NAT, d'utilisateurs ou de certificats, poussée vers l'équipement. Le premier passage sur les exports réels sert à compléter `reseaux.csv` et à ajuster [`contextes.txt`](../contextes.txt), pas à réécrire les règles.

Un objet dont le nom est conforme mais dont le site ou la zone ne correspond pas à son adresse n'est pas signalé : la conformité porte sur la forme du nom.

## Exports lus

Les fichiers réels se déposent dans `inbox/` (ignoré par git). Les exemples du dépôt sont synthétiques.

### Référentiel réseaux

`reseaux.csv` à la racine (ignoré par git), ou le fichier donné par `--reseaux`. Format `reseau;site;zone` ou `reseau;site;zone;vlan`, un CIDR par ligne, site et zone en minuscules, vlan vide permis, commentaires `#` acceptés :

```text
reseau;site;zone;vlan
10.1.0.0/16;siege;lan;
10.1.1.0/24;siege;dmz;12
10.210.0.0/24;gras;lan;210
```

Partir de [`reseaux.exemple.csv`](../reseaux.exemple.csv), ou le générer depuis une sauvegarde FortiGate :

```bash
fwclean reseaux inbox/pare-feu.conf --site siege
```

La commande lit `config system interface` (une ligne par interface qui porte une IP), `config system zone` et les zones SD-WAN (`config system sdwan` → `members`). La zone FortiGate de l'interface, ou le nom de l'interface si elle n'est dans aucune zone, est traduite par les correspondances de `contextes.txt` (`mgmt = MGMT NETWORKS`, `oob = mgmt`) ; un nom qui est déjà une zone (`LAN` → `lan`) n'a pas besoin de correspondance. Une interface sans zone traduite est écrite en commentaire, à compléter. Le fichier existant n'est remplacé qu'avec `--ecraser`.

Sur un SNS, la même commande lit le fichier natif `Network` (le fichier ou le dossier qui le contient). Le SNS n'a pas de zones : c'est le nom de l'interface (`Name=`) qui est traduit par `contextes.txt` (`wan = FObouygues, FOFreePro, INTERCO-WAN-EP`, `vpn = ssl.root, VTI_FRSI_THUS`, `oob = mgmt, HA`).

**Compléter sans écraser.** Avec `--ajouter`, la commande complète le `reseaux.csv` existant au lieu de le refuser :

```bash
fwclean reseaux inbox/stormshield --site siege --ajouter
```

- seuls les réseaux absents du fichier sont ajoutés, en fin de fichier, sous un commentaire `# Ajouté par fwclean reseaux --ajouter depuis Network :` ;
- les lignes et commentaires existants restent tels quels, y compris les ajouts manuels ;
- un réseau déjà présent avec le même site et la même zone est compté « déjà présent » ; un VLAN absent de l'interface ne contredit pas celui du fichier ;
- un réseau déjà présent avec un autre site, une autre zone ou un autre VLAN est affiché « différent, non modifié » : à trancher à la main ;
- une interface désactivée ou sans zone traduite est « écartée » et n'est pas écrite ;
- la commande se relance sans risque : un second passage n'ajoute rien.

`--ajouter` et `--ecraser` s'excluent. Sans fichier existant, `--ajouter` l'écrit comme d'habitude.

**Ajouter un site distant à la main.** Les réseaux non connectés au firewall audité (sites distants, pools VPN, IP publiques) s'écrivent à la main, une ligne `reseau;site;zone;vlan` par réseau :

```text
# Site distant de Gras (hors firewall audité)
10.210.0.0/24;gras;lan;
10.211.0.0/24;gras;dmz;211
```

Un nouveau site est un ajout libre : il suffit de l'écrire en minuscules (lettres et chiffres, ni `ctx` ni `multi`), il devient alors un site valide pour la nomenclature. La zone, elle, doit figurer dans [`contextes.txt`](../contextes.txt) : l'y ajouter d'abord si besoin. Le `vlan` est facultatif (champ vide). Ces lignes survivent à `fwclean reseaux --ajouter`, qui ne réécrit jamais le fichier.

Une ligne par adresse statique d'interface (`AddressN`/`MaskN`, `IPv6AddressN`/`IPv6MaskN`), loopback exclue ; les interfaces en `dhcp` n'apparaissent pas. La zone vient du nom de l'interface (`Name=`), traduit par `contextes.txt` (ajouter par exemple `wan = FOFreePro, FObouygues`) ; sinon la ligne est écrite en commentaire. Une interface désactivée (`State=0`) est aussi laissée en commentaire. `vlan` reprend le `Tag=` de l'interface VLAN.

La colonne `vlan` (facultative) donne le VLAN d'un réseau quand la configuration auditée ne le connaît pas ; `fwclean reseaux` la remplit avec le `vlanid` FortiGate ou le `Tag` SNS. Voir [la nomenclature](nomenclature.md#réseaux-et-vlan).

Un réseau invalide, une zone absente de `contextes.txt`, un VLAN invalide ou un même réseau déclaré avec deux sites arrêtent l'audit avec un message. Sans référentiel, l'audit tourne et les objets d'adresse non conformes sont tous listés à revoir.

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

### Stormshield (fichiers natifs)

Le plus fiable : copier les fichiers de configuration du SNS, dans `/usr/Firewall/ConfigFiles`. Par SSH sur le firewall (compte `admin`) :

```bash
cd /usr/Firewall/ConfigFiles && tar czf /tmp/sns-config.tgz object objectgroup servicegroup router Network route Filter global
```

puis récupérer `/tmp/sns-config.tgz` (scp), le décompresser dans `inbox/stormshield/` et lancer :

```bash
fwclean audit inbox/stormshield --sortie out/stormshield
```

Un fichier absent sur le SNS fait échouer `tar` : le retirer de la liste et relancer. Les fichiers n'ont pas de suffixe ; ils sont reconnus par leur nom, ou par leur contenu (sections `[Host]`, `[Filter]`, `[StaticRoutes]`, `[ethernetN]`…).

| Fichier | Contenu | Lu |
| --- | --- | --- |
| `object` | `[Network]`, `[Host]` (hôtes et plages `a-b`), `[Fqdn]`, `[Service]` (`port[-port]/tcp\|udp\|any`, `any` = TCP et UDP), `[Protocol]` (numéro IP) | oui ; valeurs MAC seules et plages MAC ignorées et signalées ; `[Internet]` ignoré |
| `objectgroup` | groupes d'adresses : `[nom]` puis un membre par ligne | oui |
| `servicegroup` | groupes de services, même forme | oui |
| `router` | objets routeur (passerelles) | reconnu, non géré (signalé dans les avertissements) |
| `Filter` | slot de filtrage actif : `[NAT]` et `[Filter]`, une règle par ligne | oui ; un dossier `Filter/` de slots aussi (règles préfixées par le nom du slot) |
| `Network` | interfaces (`[ethernetN]`, `[vlanN]` avec `Tag=`, …) | pour le VLAN des réseaux et `fwclean reseaux` |
| `route` | `DefaultRoute=`, `[StaticRoutes]` (`[off ]DEST,IFACE->PASSERELLE`) | oui ; `[ReverseRoutes]` ignoré |
| `global/` | objets et politique globaux poussés par SMC | reconnu, non géré |

Dans une règle, `from`, `to`, `port`, `ipproto`, `route` et, après `->`, les champs traduits citent des objets (listes en `a|b`, négation `!a`, `user=login@objet` → `objet`). Les lignes `separator`, `on IFACE` (interface), `via ipsec`, `any`, `internet`, `none`, `original`, et les objets créés par le SNS (`Firewall_*`, `Network_*`, `ephemeral_fw*`) ne sont pas des objets de l'export. Une ligne `off` est une règle désactivée : elle compte comme référence. Le NAT ne compte que comme référence.

**Groupes requis pour les retraits.** Sans `objectgroup` ou `servicegroup`, un membre de groupe paraîtrait orphelin : les retraits sont suspendus (voir [Orphelins](#orphelins)).

**Routeurs et objets globaux non gérés.** Les objets routeur (`router`) et les objets globaux SMC (`global/`) ne sont pas lus, et leur absence ne suspend pas les retraits : ils sont peu nombreux et à la marge. Un hôte qui ne sert que de passerelle dans un objet routeur, ou qui n'est cité que par des objets globaux, peut donc apparaître à tort comme orphelin. Le rapport le signale dans ses avertissements.

**Vérifier l'utilisation avant chaque suppression.** Seuls Filter, route et les groupes sont lus comme références : un objet utilisé ailleurs (routeur, objet global, VPN IPsec ou SSL, DHCP, proxys, authentification, autres slots) paraît orphelin. Avant de supprimer un objet proposé en retrait, lancer « Vérifier l'utilisation » sur l'objet dans l'interface SNS (ou dans SMC). Le rapport le rappelle en tête de la liste des orphelins.

**Objets globaux SMC.** Un SNS géré par SMC reçoit des objets globaux (`global_*` dans les règles, `Global_*` dans les groupes) qui ne sont pas dans les fichiers locaux. Ils sont listés dans la section Avertissements du rapport avec les autres noms cités mais non définis (routeurs, groupes d'un fichier non fourni). Ils se renomment dans SMC, pas sur le firewall.

#### Objets natifs SNS

Les objets de la base par défaut du SNS ne sont ni renommés, ni supprimés dans une fusion, ni proposés au retrait, et ne comptent pas comme non conformes. Le rapport les compte (« Objets natifs SNS ignorés ») et les liste dans une section à part ; le plan les reprend dans `natifs_ignores`. Un objet natif peut être l'objet conservé d'une fusion. La liste est dans [`sns_natifs.py`](../src/fwclean/sns_natifs.py), établie sur un export SNS réel (411 objets natifs sur 1 347) :

| Espace | Natifs |
| --- | --- |
| Adresses | motifs `rfc3330_*`, `rfc5735_*`, `rfc4291_*`, `IANA_v6_*`, `*.netasq.com`, `*.stormshield.eu`, `*.stormshieldcs.eu` ; `localhost`, `members.dyndns.org`, `checkip.dyndns.org`, `dns1.google.com`, `dns2.google.com`, `dns1.dns0.eu`, `dns2.dns0.eu`, objets MAC multicast (`dcp_multicast`…) ; groupes `rfc3330`, `rfc5735`, `IANA_v6_reserved` |
| Services | les 217 services de la base (`auth` … `vmware`, dont `http`, `https`, `dns_udp`, `ssh_udp`, `router`) et ceux ajoutés par le firmware (`ldap_udp`, `ad2003-dyn_tcp`, `agent_ad`, `modbus`, `rdp`, `quic_443`, `mqtt_tcp`…) ; groupes `full`, `mail`, `web`, `Admin_srv`, `Auth_srv`, `ActiveDirectory2003`, `ActiveDirectory2008`, `quic`, `ses_srv_*`… |
| Protocoles | les 22 protocoles de `[Protocol]` (`egp`, `ospf`, `vrrp`, `rdp`, `icmpv6`…) |

Les noms sont comparés par espace : le service `router` (`520/udp`) est natif, l'hôte `router` (`192.168.137.1`) ne l'est pas. Tout le reste est un objet d'administrateur : `EP*`, `Res-VLAN*`, `NW_*`, `Veeam_https`, `https_EP`, `ssh_ep`, `UDP_9001`, `TCP-UDP_3478`, `grp_admin`, `flux_ad`… Quelques cas douteux sont classés administrateur, donc traités normalement : `udpvpn`, `sybase`, `lpr` (placés parmi les services ajoutés à la main), `0.fr.pool.ntp.org` et `www.googleapis.com` (hôtes `resolve=dynamic`, de toute façon jamais renommés). Un firmware plus récent peut ajouter des objets natifs : les ajouter à la liste s'ils apparaissent dans les renommages.

#### Noms DNS, VLAN

**Noms DNS.** Un objet `[Fqdn]` ou un hôte `resolve=dynamic` porte le nom DNS résolu par le SNS : il n'est jamais renommé, il est listé à revoir avec ce motif.

**VLAN.** Une interface `[vlanN]` à adresse statique donne son `Tag` aux réseaux qu'elle contient. Sur un SNS de sortie Internet dont les VLAN internes sont en `dhcp` ou routés vers un autre firewall, le VLAN vient de la colonne `vlan` de `reseaux.csv` (générée depuis le FortiGate).

Pas d'écriture vers le SNS pour l'instant : le plan se relit puis s'applique à la main (ou dans SMC).

### Stormshield (CSV)

Une sauvegarde `.na` est chiffrée : elle n'est pas lue. Autre possibilité que les fichiers natifs : exporter deux CSV, et éventuellement les routes. CSV et fichiers natifs ne se mélangent pas dans un même audit.

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
host,SIEGE_HST_DMZ_WEB-01,10.1.1.10,,,,"Serveur web"
network,SIEGE_NET_LAN_UTILISATEURS,10.0.0.0,255.255.255.0,,,"LAN"
service,SVC_TCP_443_HTTPS,tcp,443,,,"HTTPS"
group,SIEGE_GRP_DMZ_WEB,"SIEGE_HST_DMZ_WEB-01",""
time,SCH_BUREAU,08:00-18:00,monday-friday,,""
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
| `interface_source` | `srcif`, `srcintf` | lue, pas utilisée tant que les règles ne sont pas renommées |
| `interface_destination` | `dstif`, `dstintf` | idem |
| `planification` | `schedule`, `time` | objet calendrier |
| `source_traduite` | `pool`, `nat_src` | objet cité par le NAT |
| `destination_traduite` | `vip`, `nat_dst` | objet cité par le NAT |

**Routes** (facultatif) — en-tête `destination,passerelle` (alias `dst`, `gateway`). Une passerelle qui est une adresse IP n'est pas un objet. Sans ce fichier, une route absente de l'export ne peut pas empêcher un faux orphelin : le déposer si des objets ne servent qu'au routage.

```bash
fwclean audit inbox/objets.csv inbox/regles.csv inbox/routes.csv --sortie out
```

Un dossier qui contient ces CSV marche aussi : `fwclean audit inbox/ --sortie out`.

## Appliquer le plan sur FortiGate

`fwclean` ne se connecte pas au firewall. Il écrit le script CLI qui applique le plan relu :

```bash
fwclean script inbox/pare-feu.conf --plan out/plan.json --sortie out/fortigate
```

Le plan peut être modifié avant (retirer une ligne suffit à l'exclure). La commande relit la sauvegarde pour trouver les références, et écrit dans `out/fortigate/` :

| Fichier | Contenu |
| --- | --- |
| `01-renommages.txt` | `rename "ancien" to "nouveau"` ; FortiOS met à jour toutes les références |
| `02-fusions.txt` | pour chaque doublon : `append` de l'objet conservé puis `unselect` du doublon dans chaque règle, groupe ou route qui le cite (`set` pour un champ à valeur unique : calendrier, route statique), puis `delete` du doublon |
| `03-retraits.txt` | `delete` des objets sans référence |
| `ignores.txt` | opérations du plan non reprises, avec la raison |

Chaque fichier est découpé en lots (`--lot`, 20 objets par défaut). Les commandes tiennent compte des étapes précédentes : un groupe renommé est édité sous son nouveau nom lors des fusions.

Ne sont pas repris : les objets par défaut de FortiOS (`all`, `ALL`, `HTTP`, `DNS`, `always`, `Web Access`, …, sauf `--inclure-defauts`), les objets absents de la sauvegarde, un renommage vers un nom déjà pris, et un retrait d'objet encore cité dans la sauvegarde.

Les références lues sont celles des règles (`srcaddr`, `dstaddr`, `service`, `schedule`, `poolname`), des groupes d'adresses, de services et de calendriers, et des routes. Un objet cité ailleurs (VPN SSL, IPsec, local-in, proxy, SD-WAN) n'est pas réécrit : FortiGate refuse alors le `delete`, et l'objet reste. C'est le filet de sécurité voulu : ne pas forcer.

Ordre : 01, puis 02, puis 03, un lot à la fois, avec sauvegarde avant et test des flux après. Ré-exporter la configuration et relancer l'audit entre deux passes. Si le firewall est piloté par FortiManager, appliquer dans FortiManager.

## Sorties

Dans le dossier `--sortie` (défaut `out/`, ignoré par git) :

- `rapport.md` — référentiel réseaux utilisé, avertissements (retraits suspendus, noms cités non définis), noms non conformes (avec un commentaire pour ceux à revoir), doublons, orphelins, compteurs ;
- `plan.json` — la proposition, et rien d'autre.

Clés du plan :

| Clé | Contenu |
| --- | --- |
| `avertissement` | rappel que rien n'a été appliqué |
| `constructeur` | `fortigate` ou `stormshield` |
| `sources` | fichiers lus |
| `avertissements` | `messages` (textes du rapport), `retraits_suspendus` (raison, ou `null`), `noms_non_definis` (noms cités mais définis nulle part dans l'export, hors objets implicites) |
| `renommages` | `sorte`, `ancien`, `nouveau`, `references` |
| `fusions` | `sorte`, `contenu`, `conserve`, `nouveau_nom`, `supprimes`, `references_reecrites` |
| `retraits` | `sorte`, `nom`, `motif` (`aucune reference`) ; vide si les retraits sont suspendus |
| `a_revoir` | `sorte`, `nom`, `commentaire` : objets non conformes sans nom proposé (site ou zone introuvable, nom DNS SNS) |

`nouveau_nom` est le nom de l'objet conservé après un éventuel renommage. Il est identique à `conserve` quand le nom était déjà conforme.

Les valeurs de `sorte` sont stables : `hote`, `reseau`, `plage`, `fqdn`, `groupe-adresses`, `service`, `protocole` (objet `[Protocol]` SNS), `groupe-services`, `vip`, `pool`, `calendrier`.
