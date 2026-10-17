# fwclean

Audit de nomenclature pour FortiGate et Stormshield. L'outil signale les noms qui ne suivent pas la convention, les doublons stricts et les objets sans référence. Il ne modifie pas les flux, ne se connecte à aucun équipement et n'applique rien.

La convention est dans [docs/nomenclature.md](docs/nomenclature.md). L'ordre des opérations et les formats d'export sont dans [docs/methode-nettoyage.md](docs/methode-nettoyage.md).

## Installation

[uv](https://docs.astral.sh/uv/) et Python 3.12.

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync
```

Vérifier l'aide :

```bash
uv run fwclean --help
uv run fwclean audit --help
```

## Où déposer un export

Créer le dossier `inbox/` à la racine du projet et y copier l'export. Ce dossier est ignoré par git : les sauvegardes réelles restent sur la machine.

```bash
mkdir -p inbox
```

- FortiGate : la sauvegarde texte `.conf`.
- Stormshield : de préférence les fichiers natifs de `/usr/Firewall/ConfigFiles` (`object`, `objectgroup`, `servicegroup`, `router`, `Network`, `route`, `Filter`, `Global`) dans `inbox/stormshield/`. La commande SSH qui les rassemble est dans [la méthode](docs/methode-nettoyage.md#stormshield-fichiers-natifs). Sinon, le CSV des objets et le CSV des règles de filtrage (et `routes.csv` si des objets ne sont cités que par le routage). Une sauvegarde `.na` est chiffrée, elle est refusée.

## Lancer l'audit

```bash
uv run fwclean audit inbox/pare-feu.conf --sortie out
uv run fwclean audit inbox/objets.csv inbox/regles.csv --sortie out
uv run fwclean audit inbox/ --sortie out
uv run fwclean audit inbox/stormshield --sortie out/stormshield
```

Un audit porte sur un seul constructeur et un seul format (FortiGate, CSV Stormshield ou fichiers natifs SNS). Sans `--sortie`, les fichiers vont dans `out/` (ignoré par git). `--reseaux` pointe vers un autre référentiel que `./reseaux.csv`.

## Sites et interfaces

Les noms d'objets portent le site puis l'interface du réseau de l'objet : `HQ_HST_CABINES_PC01`. Les réseaux portent en plus le VLAN optionnel : `HQ_NET_V16_CABINES`, ou `HQ_NET_CABINES` sans VLAN. Les règles ne sont pas renommées pour le moment. Site, VLAN et interface viennent de `reseaux.csv` :

```text
reseau;site;vlan;interface
10.0.16.0/24;hq;16;CABINES
10.0.28.0/24;hq;28;LABO_ANA
192.168.1.0/24;hq;;mgmt
```

Le réseau le plus précis qui contient l'objet gagne. Le nom d'interface est normalisé (`LABO_ANA` → `LABO-ANA`). Un sous-réseau garde son ancien nom après l'interface (`HQ_NET_V16_CABINES-IMPRIMANTES`). Un groupe dont les membres sont sur plusieurs sites ou interfaces prend `MULTI` ; une VIP prend l'interface de son adresse interne. Un objet hors référentiel, ou dont le réseau n'a pas d'interface (ancien `reseaux.csv` `reseau;site;zone;vlan`), n'est pas renommé : il est listé à revoir avec un commentaire. Services, groupes de services (`SG_WEB`) et calendriers n'ont ni site ni interface. Un service porte protocole (`TCP`, `UDP`, `ANY` pour les deux) et port, puis son libellé : `SVC_TCP_8080_HTTP`, `SVC_ANY_53_DNS`.

`reseaux.csv` est le référentiel versionné (édition manuelle). Pour démarrer depuis l'exemple : `cp reseaux.exemple.csv reseaux.csv`, puis adapter les lignes. Sans `reseaux.csv`, l'audit tourne quand même et liste les objets d'adresse à revoir. L'ancien format avec colonne `zone` (`reseau;site;zone;vlan;interface`) reste lu : la zone est ignorée, quelle que soit sa valeur.

La commande affiche les compteurs et écrit :

- `out/rapport.md` — avertissements, noms non conformes, doublons, orphelins ;
- `out/plan.json` — renommages, fusions et retraits proposés.

Rien n'est appliqué. Le plan se relit avant toute modification sur l'équipement, dans l'ordre : renommage, fusion des doublons stricts, retrait des orphelins.

Pour voir le comportement sans export réel :

```bash
uv run fwclean audit examples/fortigate/nomenclature.conf --reseaux reseaux.exemple.csv --sortie out/fortigate
uv run fwclean audit examples/stormshield --reseaux reseaux.exemple.csv --sortie out/stormshield
uv run fwclean audit examples/stormshield-natif --reseaux reseaux.exemple.csv --sortie out/stormshield-natif
```

Ces exemples contiennent chacun un nom à reprendre, un doublon strict et un objet sans référence. `SIEGE_HST_LAN-USERS_LEGACY` n'est cité que par une règle désactivée : il n'est pas orphelin. `Vlan210` devient `GRAS_NET_V210_GRAS-210` par son réseau, et le groupe `Clients web`, qui mélange SIEGE et GRAS, devient `MULTI_GRP_MULTI_CLIENTS-WEB`. Dans l'exemple FortiGate, `partenaire` (hors référentiel) est listé à revoir sans nom proposé, et le service `Appli metier 8443` devient `SVC_TCP_8443_APPLI-METIER`. Dans l'exemple SNS natif, la section Avertissements liste les noms cités mais non définis (routeur, objet global SMC absent de `Global/`, groupe absent), et la section « Objets globaux SMC » montre chaque action sur les globaux de `Global/` : réutiliser, créer, revoir, supprimer.

Sur Stormshield, les retraits d'orphelins ne sont proposés que si `objectgroup` et `servicegroup` sont lus : sans eux, un membre de groupe paraîtrait orphelin. Les objets routeur ne sont pas gérés : un hôte qui ne sert que de passerelle de routeur peut apparaître à tort comme orphelin. Les objets globaux SMC (`Global/object`, `Global/objectgroup`, `Global/servicegroup`) sont lus pour être remplacés par des objets locaux puis supprimés (voir [la méthode](docs/methode-nettoyage.md#objets-globaux-smc)). Avant chaque suppression, lancer « Vérifier l'utilisation » sur l'objet dans le SNS. Les objets FQDN et les hôtes `resolve=dynamic` (le nom est le nom DNS) ne sont jamais renommés. Les objets natifs du SNS (base par défaut : `http`, `dns_udp`, `rfc5735_private_1`, `update1.stormshield.eu`…) ne sont ni renommés, ni supprimés, ni retirés, et ne comptent pas comme non conformes ; le rapport les liste à part (« Objets natifs SNS ignorés »). La liste est décrite dans [la méthode](docs/methode-nettoyage.md#objets-natifs-sns).

## Tests

```bash
uv run pytest
```

## Générer reseaux.csv

`reseaux.csv` est la source de vérité versionnée : `fwclean reseaux` (surtout `--ecraser`) ne doit pas l'écraser à la légère ; préférer `--ajouter` ou une édition manuelle.

```bash
uv run fwclean reseaux inbox/pare-feu.conf --site siege
```

Écrit `./reseaux.csv` avec les réseaux directement connectés du FortiGate : `vlanid` dans la colonne `vlan` ; **alias** de l'interface (`set alias`) dans la colonne `interface`, par exemple `CENTRALE DETECTION GAZ` pour `VLAN-25`, ce qui donne `HQ_NET_V25_CENTRALE-DETECTION-GAZ`. Une interface sans alias garde son nom technique, signalé en commentaire de ligne et en fin de commande ; un alias ou un nom qui ne dit rien (`VLAN-131`, `port3`) est signalé aussi. Les remplacer à la main dans la colonne avant de produire les scripts. Relancé avec `--ajouter` sur un fichier qui porte encore les noms techniques, il les remplace par l'alias, sans toucher aux noms corrigés à la main. `--ecraser` remplace un fichier existant.

Sur un SNS, `uv run fwclean reseaux inbox/stormshield --site siege` lit le fichier `Network` : une ligne par interface à adresse statique, `vlan` = `Tag`, `interface` = `Name`.

Pour compléter un `reseaux.csv` existant avec un second firewall, sans rien écraser :

```bash
uv run fwclean reseaux inbox/stormshield --site siege --ajouter
```

`--ajouter` ajoute les réseaux absents en fin de fichier et migre l'ancien format : les lignes du même site sans interface reçoivent VLAN et interface, la colonne zone est retirée et l'en-tête passe à `reseau;site;vlan;interface`. Il garde les autres lignes et commentaires, et signale sans le modifier un réseau déjà présent avec un autre site, un autre VLAN ou une autre interface. La commande peut être relancée : elle n'ajoute rien de plus et ne touche pas aux lignes écrites à la main.

### Ajouter un site distant à la main

Les réseaux non connectés au firewall audité (sites distants, pools VPN, IP publiques) s'ajoutent à la main dans `reseaux.csv`, une ligne par réseau :

```text
reseau;site;vlan;interface
10.210.0.0/24;gras;210;SRV
10.211.0.0/24;gras;211;POSTE-FILAIRE
```

- format `reseau;site;vlan;interface`, séparateur `;`, site en minuscules ;
- un nouveau site s'ajoute librement : il suffit de l'écrire (lettres et chiffres, ni `ctx` ni `multi`) ;
- l'interface est le libellé du VLAN sur le site distant ;
- `vlan` est facultatif : laisser le champ vide.

Un exemple de site distant figure dans [`reseaux.exemple.csv`](reseaux.exemple.csv).

## Produire le script d'application

### FortiGate

```bash
uv run fwclean script inbox/pare-feu.conf --plan out/plan.json
```

Écrit dans `out/fortigate/` trois fichiers de commandes CLI FortiGate à relire puis à coller lot par lot : `01-renommages.txt`, `02-fusions.txt`, `03-retraits.txt`, et `ignores.txt` pour ce qui n'est pas repris (objets par défaut de FortiOS, objets encore cités). Chaque lot tient compte des précédents (noms d'après 01, références retirées avant chaque `delete`). Si d'anciens scripts ont déjà été collés, `--deja-applique` les rejoue et écrit `02b-rattrapage.txt` et un `03-retraits.txt` pour l'état obtenu. Rien n'est envoyé au firewall. Détail dans [la méthode](docs/methode-nettoyage.md#appliquer-le-plan-sur-fortigate).

### Stormshield (SNS)

```bash
uv run fwclean script inbox/stormshield --plan out/stormshield/plan.json --sortie out/stormshield
```

Écrit `01-renommages.py`, `02-fusions.py`, `03-retraits.py` et `ignores.txt`, plus `04-globaux.py` et `05-suppression-globaux.py` si l'export contient des objets globaux SMC (04 : création des objets locaux de remplacement et réécriture des règles ; 05 : suppression `global=1` des globaux). Dépendance : `pip install stormshield.sns.sslclient`. Chaque script accepte `--host`, `--user`, `--dry-run`, `--depuis N` et `--jusqua N` ; le mot de passe est lu dans `$SNS_PASS`, sinon demandé (jamais en argument). Il prend la main (`MODIFY ON`), s'arrête à la première erreur hors suppression sans rien activer, et indique la commande à reprendre. Ordre : 01 → 02 → 03 → 04 → 05. Procédure de décommissionnement de la SMC : [la méthode](docs/methode-nettoyage.md#objets-globaux-smc). Ne pas redéployer depuis SMC après exécution (écraserait les changements locaux). Valider d'abord en `--dry-run`, puis sur un SNS de test après sauvegarde. `global=1` n'est pas documenté sur `CONFIG OBJECT … DELETE` : passer 05 sur un seul objet d'abord.

## Premier passage sur un export réel

Générer ou remplir `reseaux.csv` avec les réseaux et sites réels, relire la colonne `interface` (interfaces sans alias, noms peu parlants), puis relancer l'audit. Les objets « à revoir » restants montrent les adresses absentes du référentiel ou les réseaux sans interface. Les noms proposés sont en majuscules (`SIEGE_HST_DMZ_WEB-01`). Une fois le plan relu, produire le script, l'appliquer lot par lot, puis ré-exporter et relancer l'audit. Ce passage ne sert pas à réécrire les règles.
