# Méthode de nettoyage

Trois opérations, toujours dans cet ordre, et seulement après relecture humaine du rapport et du plan. `fwclean` ne se connecte pas aux firewalls et n'écrit rien dans l'export.

1. **Renommage** — l'objet ne change pas de contenu, seulement de nom. Les références suivent. Les règles ne sont pas renommées pour le moment.
2. **Fusion de doublons stricts** — même type et même contenu. Les références des objets supprimés sont réécrites vers l'objet conservé.
3. **Orphelins** — objet sans aucune référence. Le plan liste un retrait. Rien n'est supprimé automatiquement.

Un objet utilisé seulement par une règle désactivée n'est pas orphelin.

## Renommage

Le contenu (adresse, membres, ports, action, source, destination, service) reste celui de l'export. Le nom proposé suit [la nomenclature](nomenclature.md).

Le site et l'interface d'un nom proposé viennent du réseau : l'adresse de l'objet est cherchée dans `reseaux.csv`, la ligne la plus précise qui la contient donne le site et l'interface (`HQ_HST_CABINES_PC01`). Un objet réseau prend en plus le VLAN de cette ligne (`HQ_NET_V16_CABINES`) ; un sous-réseau garde son ancien nom après l'interface (`HQ_NET_V16_CABINES-IMPRIMANTES`). Groupes et pools prennent le site et l'interface communs à leurs membres, ou `MULTI` ; une VIP prend ceux de son adresse interne. Services, groupes de services (`SG_{LIBELLE}`, ancien préfixe `SGRP` renommé) et calendriers n'ont ni site ni interface. Un service porte son protocole et ses ports, calculés sur son contenu, puis le libellé de son ancien nom (`HTTP-8080` → `SVC_TCP_8080_HTTP`). Le détail est dans [la nomenclature](nomenclature.md#déduction).

Un objet d'adresse sans site ou sans interface n'est **pas renommé** : il est listé à revoir, avec un commentaire qui dit ce qui manque (adresse absente de `reseaux.csv`, ou ligne sans colonne `interface`). Compléter `reseaux.csv` puis relancer l'audit.

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

Chevauchements de réseaux, renommage, fusion ou réordonnancement de règles, changement d'action, de NAT, d'utilisateurs ou de certificats, poussée vers l'équipement. Le premier passage sur les exports réels sert à compléter `reseaux.csv`, pas à réécrire les règles.

Quand le site et l'interface d'un objet sont connus, un nom qui porte un autre site ou une autre interface (ou, pour un réseau, un autre VLAN) n'est pas conforme et est renommé. Un objet non localisable n'est jugé que sur sa forme.

## Exports lus

Les fichiers réels se déposent dans `inbox/` (ignoré par git). Les exemples du dépôt sont synthétiques.

### Référentiel réseaux

`reseaux.csv` à la racine (ignoré par git), ou le fichier donné par `--reseaux`. Format `reseau;site;vlan;interface`, un CIDR par ligne, site en minuscules, vlan vide permis, commentaires `#` acceptés :

```text
reseau;site;vlan;interface
10.1.0.0/16;siege;;SERVEURS
10.1.1.0/24;siege;12;DMZ
192.168.1.0/24;siege;;mgmt
10.210.0.0/24;gras;210;SRV
```

Aucune zone ni contexte : seuls le site, le VLAN et l'interface comptent. Les anciens formats avec colonne zone restent lus, zone ignorée quelle que soit sa valeur. `reseau;site;zone;vlan` n'a pas d'interface : ses objets sont à revoir jusqu'à la migration (`--ajouter`, ci-dessous).

Partir de [`reseaux.exemple.csv`](../reseaux.exemple.csv), ou le générer depuis une sauvegarde FortiGate :

```bash
fwclean reseaux inbox/pare-feu.conf --site siege
```

La commande lit `config system interface` (une ligne par interface qui porte une IP) ; la zone FortiGate (`config system zone`, zones SD-WAN) n'est rappelée qu'en commentaire de ligne. La colonne `interface` reçoit l'**alias** de l'interface (`set alias`) : `VLAN-25` d'alias `CENTRALE DETECTION GAZ` donne `HQ_NET_V25_CENTRALE-DETECTION-GAZ` et `HQ_HST_CENTRALE-DETECTION-GAZ_…`. Sans alias, c'est le nom de l'interface, avec un avertissement en commentaire de ligne (« sans alias : nom de l'interface ») et en fin de commande. Le fichier existant n'est remplacé qu'avec `--ecraser`.

Un alias ou un nom qui ne dit rien (`VLAN-131`, `port3`) est signalé en commentaire de la ligne et en fin de commande, avec le nom technique en suggestion s'il est plus parlant (`IDRAC (VLAN-131), zone MGMT NETWORKS — alias peu parlant (nom : IDRAC)`). Deux interfaces au même nom normalisé (`LABO_ANA` et `LABO-ANA`) le sont aussi. Avec `--ajouter`, une ligne FortiGate qui porte encore le nom technique de son interface reçoit l'alias (« alias appliqué ») ; une interface renommée à la main n'est pas touchée et apparaît en « différent, non modifié ». Remplacer ces noms à la main dans la colonne `interface` **avant** de produire les scripts : c'est ce nom qui entre dans les objets.

Sur un SNS, la même commande lit le fichier natif `Network` (le fichier ou le dossier qui le contient). L'interface est le `Name=` de l'interface (`FObouygues`, `HA`, `VTI_FRSI_THUS`).

**Compléter sans écraser.** Avec `--ajouter`, la commande complète le `reseaux.csv` existant au lieu de le refuser :

```bash
fwclean reseaux inbox/stormshield --site siege --ajouter
```

- les réseaux absents du fichier sont ajoutés, en fin de fichier, sous un commentaire `# Ajouté par fwclean reseaux --ajouter depuis Network :` ;
- **migration de l'ancien format** : une ligne du même site sans interface est réécrite avec le VLAN et l'interface de l'équipement ; dès qu'une ligne change, la colonne zone est retirée de tout le fichier et l'en-tête passe à `reseau;site;vlan;interface` ;
- les autres lignes et commentaires restent tels quels, y compris les ajouts manuels et les lignes d'un autre site ;
- un réseau déjà présent avec le même site et la même interface est compté « déjà présent » ; un VLAN absent de l'interface ne contredit pas celui du fichier ;
- un réseau déjà présent avec un autre site, un autre VLAN ou une autre interface (renommée à la main, par exemple) est affiché « différent, non modifié » : à trancher à la main ;
- une interface désactivée est « écartée » et n'est pas écrite ;
- la commande se relance sans risque : un second passage n'ajoute rien.

`--ajouter` et `--ecraser` s'excluent. Sans fichier existant, `--ajouter` l'écrit comme d'habitude.

**Ajouter un site distant à la main.** Les réseaux non connectés au firewall audité (sites distants, pools VPN, IP publiques) s'écrivent à la main, une ligne `reseau;site;vlan;interface` par réseau. L'interface est le libellé du VLAN sur le site distant :

```text
# Site distant de Gras (hors firewall audité)
10.210.0.0/24;gras;210;SRV
10.211.0.0/24;gras;211;POSTE-FILAIRE
```

Un nouveau site est un ajout libre : il suffit de l'écrire en minuscules (lettres et chiffres, ni `ctx` ni `multi`), il devient alors un site valide pour la nomenclature. Le `vlan` est facultatif (champ vide). Ces lignes survivent à `fwclean reseaux --ajouter`, qui ne réécrit que les lignes de son site sans interface.

Côté SNS : une ligne par adresse statique d'interface (`AddressN`/`MaskN`, `IPv6AddressN`/`IPv6MaskN`), loopback exclue ; les interfaces en `dhcp` n'apparaissent pas. Une interface désactivée (`State=0`) est laissée en commentaire. `vlan` reprend le `Tag=` de l'interface VLAN.

La colonne `vlan` donne le segment `V{ID}` des réseaux ; `fwclean reseaux` la remplit avec le `vlanid` FortiGate ou le `Tag` SNS. Le VLAN vu dans la configuration auditée ou dans l'ancien nom n'est pas utilisé. Voir [la nomenclature](nomenclature.md#réseaux).

Un réseau ou un site invalide, un VLAN ou une interface invalides, ou un même réseau déclaré deux fois différemment arrêtent l'audit avec un message. Sans référentiel, l'audit tourne et les objets d'adresse non conformes sont tous listés à revoir.

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
cd /usr/Firewall/ConfigFiles && tar czf /tmp/sns-config.tgz object objectgroup servicegroup router Network route Filter Global
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
| `Network` | interfaces (`[ethernetN]`, `[vlanN]` avec `Tag=`, …) | pour `fwclean reseaux` |
| `route` | `DefaultRoute=`, `[StaticRoutes]` (`[off ]DEST,IFACE->PASSERELLE`) | oui ; `[ReverseRoutes]` ignoré |
| `Global/` | objets et politique globaux poussés par SMC : `object`, `objectgroup`, `servicegroup` (même format que les fichiers locaux), `Filter`… | `object`, `objectgroup`, `servicegroup` lus (voir [Objets globaux SMC](#objets-globaux-smc)) ; le reste reconnu, non géré |

Dans une règle, `from`, `to`, `port`, `ipproto`, `route` et, après `->`, les champs traduits citent des objets (listes en `a|b`, négation `!a`, `user=login@objet` → `objet`). Les lignes `separator`, `on IFACE` (interface), `via ipsec`, `any`, `internet`, `none`, `original`, et les objets créés par le SNS (`Firewall_*`, `Network_*`, `ephemeral_fw*`) ne sont pas des objets de l'export. Une ligne `off` est une règle désactivée : elle compte comme référence. Le NAT ne compte que comme référence.

**Groupes requis pour les retraits.** Sans `objectgroup` ou `servicegroup`, un membre de groupe paraîtrait orphelin : les retraits sont suspendus (voir [Orphelins](#orphelins)).

**Routeurs non gérés.** Les objets routeur (`router`) ne sont pas lus, et leur absence ne suspend pas les retraits : ils sont peu nombreux et à la marge. Un hôte qui ne sert que de passerelle dans un objet routeur peut donc apparaître à tort comme orphelin. Le rapport le signale dans ses avertissements. Sans dossier `Global/`, il signale aussi qu'un hôte cité seulement par des objets globaux peut paraître orphelin.

**Vérifier l'utilisation avant chaque suppression.** Seuls Filter, route et les groupes sont lus comme références : un objet utilisé ailleurs (routeur, objet global, VPN IPsec ou SSL, DHCP, proxys, authentification, autres slots) paraît orphelin. Avant de supprimer un objet proposé en retrait, lancer « Vérifier l'utilisation » sur l'objet dans l'interface SNS (ou dans SMC). Le rapport le rappelle en tête de la liste des orphelins.

#### Objets globaux SMC

Un SNS géré par SMC reçoit des objets globaux, rangés dans `Global/object`, `Global/objectgroup` et `Global/servicegroup` (mêmes noms et même format que les fichiers locaux). Les règles et les groupes locaux les citent `global_<nom>` ou `Global_<nom>`. Ils ne sont pas modifiables sur le firewall, et ils ne disparaissent pas quand la SMC est retirée : il faut les supprimer une fois remplacés.

**Lecture.** Les objets de `Global/` sont lus sous le nom `global_<nom>` ; les membres d'un groupe global aussi. Les références `Global_X` et `global_X` des règles, du NAT, des routes et des groupes locaux sont ramenées à ce nom (sans tenir compte de la casse). Un nom local identique garde la priorité. Un `global_X` sans définition dans `Global/` reste dans les noms cités non définis. Les globaux ne sont jamais renommés, fusionnés ni retirés par les lots 01 à 03, et ne comptent pas comme non conformes.

**Plan.** La section `globaux` de `plan.json` et la section « Objets globaux SMC » du rapport donnent, pour chaque global, une action :

| Action | Quand | Objet local |
| --- | --- | --- |
| `reutiliser` | un objet local conservé a le même contenu (même adresse, même service ; pour un groupe, mêmes membres après traduction) | l'objet local, sous son nom après renommages et fusions |
| `creer` | aucun objet local identique, et l'objet se localise par `reseaux.csv` (ou n'a pas besoin de l'être : services, groupes de services) | nom selon la nomenclature, calculé à partir du nom sans `global_` (gardé s'il est déjà conforme et libre) ; un FQDN ou un hôte `resolve=dynamic` garde son nom DNS |
| `revoir` | adresse absente de `reseaux.csv`, membre de groupe sans remplaçant, nom DNS déjà pris, ou retraits suspendus (usage inconnu) | aucun, le motif est en commentaire |
| `supprimer` | cité par aucune règle (active ou non), route, NAT, ni objet local, même via un groupe global | aucun |

Les groupes sont traités après leurs membres : un groupe imbriqué est créé après le groupe qu'il contient, avec les membres traduits (`membres` dans le plan).

**Lots 04 et 05.** `fwclean script` écrit alors `04-globaux.py` et `05-suppression-globaux.py`, à passer après 01, 02 et 03 :

1. création des objets locaux (`CONFIG OBJECT HOST|NETWORK|RANGE|FQDN|SERVICE|PROTOCOL NEW`, `GROUP|SERVICEGROUP NEW` puis `ADDTO`), commentaire `remplace global_X (SMC)` ;
2. remplacement du global par l'objet local dans les règles (`CONFIG FILTER RULE UPDATE … global=0`) et dans les groupes locaux (`ADDTO` / `REMOVEFROM`) ; les groupes globaux ne sont pas modifiés ;
3. activation du lot 04 : `CONFIG OBJECT ACTIVATE`, `CONFIG FILTER ACTIVATE` ;
4. lot 05, suppression des globaux remplacés ou cités par rien : `CONFIG OBJECT <TYPE> DELETE name=<nom sans global_> global=1`, groupes englobants d'abord, puis `CONFIG OBJECT ACTIVATE global=1`.

`global=1` n'est pas documenté sur `CONFIG OBJECT … DELETE` dans le guide CLI serverd : s'il est ignoré, la commande vise l'objet **local** de même nom. Le lot 05 écarte donc tout global dont le nom sans `global_` existe aussi en local ou parmi les objets natifs (`dns`, `bootps`, objets créés par le lot 04…) : il reste dans `ignores.txt`, à supprimer depuis SMC ou l'interface. Sur le SNS de test, passer d'abord une seule commande du lot 05 et vérifier que c'est bien le global qui disparaît.

Restent dans `ignores.txt`, sans suppression : les globaux à revoir ; ceux cités par une route ou un NAT (l'objet local est créé, la route ou le NAT est à reprendre à la main) ; ceux encore cités par un groupe global conservé ou par un `ipproto` ; les créations non gérées (réseau IPv6, service à plusieurs plages : à créer à la main). Les syntaxes `NEW` et `global=1` n'ont pas été vérifiées sur un équipement : valider les lots en `--dry-run`, puis sur un SNS de test.

**Décommissionner la SMC.**

1. Dans la SMC, copier les règles globales dans la politique locale du firewall (elles citent encore les objets globaux), déployer une dernière fois, puis détacher le firewall de la SMC.
2. Refaire l'export du SNS, dossier `Global/` compris, dans `inbox/stormshield/`.
3. `fwclean audit inbox/stormshield --sortie out/stormshield`, relire la section « Objets globaux SMC » du rapport (les `revoir` : compléter `reseaux.csv` ou traiter à la main).
4. `fwclean script inbox/stormshield --plan out/stormshield/plan.json --sortie out/stormshield`, puis `01` → `02` → `03` → `04` → `05`, chacun en `--dry-run` d'abord.
5. Ne plus redéployer depuis la SMC : elle recréerait les objets globaux et écraserait la politique locale.
6. Refaire l'export et l'audit : il ne doit plus rester d'objets globaux, sauf ceux de `ignores.txt` traités à la main.

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

**VLAN et interface.** Le VLAN et l'interface d'un réseau SNS viennent de `reseaux.csv` : `fwclean reseaux` sur le fichier `Network` y écrit le `Tag` et le `Name` des interfaces à adresse statique. Sur un SNS de sortie Internet dont les VLAN internes sont en `dhcp` ou routés vers un autre firewall, ce sont les lignes générées depuis le FortiGate qui donnent VLAN et interface. La forme des noms réseau est la même que FortiGate (`{SITE}_NET_[V{VLAN}_]{INTERFACE}`).

Le plan relu s'applique avec les scripts Python (`stormshield.sns.sslclient`) de `fwclean script` (voir le README). Chaque script prend la main (`MODIFY ON`), lit le mot de passe dans `$SNS_PASS`, sépare les objets d'une règle par `,` (la CLI ; le fichier `Filter` utilise `|`), continue après une suppression refusée mais s'arrête à toute autre erreur sans rien activer ; `--depuis N` reprend à la commande N. Les positions de règles sont les numéros de ligne de la section `[Filter]` du slot, séparateurs compris : les comparer à l'interface avant le lot 04.

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
network,SIEGE_NET_V10_LAN-USERS,10.0.0.0,255.255.255.0,,,"LAN"
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

Chaque fichier est découpé en lots (`--lot`, 20 objets par défaut). Chaque lot est calculé sur l'état laissé par les précédents : 02 et 03 citent les noms d'après 01 (objet conservé, groupe ou portail édité), un doublon n'est pas renommé en 01 puisqu'il disparaît en 02, un objet supprimé en 02 n'est pas repris en 03, et dans 02 chaque `delete` vient après les `append` / `unselect` qui retirent ses références. Une ligne `# doublon "…" -> conservé "…" (contenu)` précède chaque fusion. Les tests rejouent 01, 02 puis 03 sur la sauvegarde avec les refus de FortiOS (objet introuvable, objet encore utilisé, champ vidé) et n'attendent aucun refus.

Ne sont pas repris : les objets par défaut de FortiOS (`all`, `ALL`, `HTTP`, `DNS`, `always`, `Web Access`, …, sauf `--inclure-defauts`), les objets absents de la sauvegarde, un renommage vers un nom déjà pris, et un retrait d'objet encore cité dans la sauvegarde.

Les références réécrites sont celles des règles (`srcaddr`, `dstaddr`, `service`, `schedule`, `poolname`), des politiques local-in, shaping et proxy, du NAT central, des groupes d'adresses, de services et de calendriers, des routes, et du VPN SSL (`split-tunneling-routing-address`, `ip-pools` des portails, `source-address` et `tunnel-ip-pools` des réglages). Un objet cité ailleurs (SD-WAN, IPsec, …) est seulement signalé dans `ignores.txt` : ses références connues sont reportées, mais il n'est pas supprimé.

### Scripts déjà appliqués

Si une version précédente des scripts a déjà été collée, ne pas la recoller. Lui donner les fichiers passés, dans l'ordre :

```bash
fwclean script inbox/pare-feu.conf --plan out/plan.json \
  --deja-applique ancien/01-renommages.txt --deja-applique ancien/02-fusions.txt
```

Les scripts sont rejoués sur la sauvegarde comme FortiOS le ferait. `deja-applique.txt` liste les commandes refusées, `02b-rattrapage.txt` contient ce qui reste des renommages et fusions, et `03-retraits.txt` est récrit pour cet état. 01 et 02 ne sont pas récrits. La simulation suppose que l'équipement partait de la sauvegarde donnée : en cas de doute, recharger cette sauvegarde et rejouer les scripts à jour.

**Changement de convention.** Quand la convention change après un premier passage (passage de la zone à l'interface, puis retrait de la zone des noms réseau, par exemple), ne pas renommer une seconde fois par-dessus les noms déjà appliqués : recharger la sauvegarde d'origine sur l'équipement, puis coller les lots régénérés sans `--deja-applique` (`out/fortigate/rejeu-depuis-sauvegarde/`). L'audit reconnaît malgré tout les anciens noms (`HQ_NET_LAN_VLAN11-RES`, `HQ_NET_LAN_V16_CABINES`, `HQ_GRP_LAN_…`) et ne recopie ni l'ancienne zone ni le VLAN dans le détail.

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
| `a_revoir` | `sorte`, `nom`, `commentaire` : objets non conformes sans nom proposé (site ou interface introuvable, nom DNS SNS) |

`nouveau_nom` est le nom de l'objet conservé après un éventuel renommage. Il est identique à `conserve` quand le nom était déjà conforme.

Les valeurs de `sorte` sont stables : `hote`, `reseau`, `plage`, `fqdn`, `groupe-adresses`, `service`, `protocole` (objet `[Protocol]` SNS), `groupe-services`, `vip`, `pool`, `calendrier`.
