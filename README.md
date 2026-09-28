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
- Stormshield : de préférence les fichiers natifs de `/usr/Firewall/ConfigFiles` (`object`, `objectgroup`, `servicegroup`, `router`, `Network`, `route`, `Filter`, `global`) dans `inbox/stormshield/`. La commande SSH qui les rassemble est dans [la méthode](docs/methode-nettoyage.md#stormshield-fichiers-natifs). Sinon, le CSV des objets et le CSV des règles de filtrage (et `routes.csv` si des objets ne sont cités que par le routage). Une sauvegarde `.na` est chiffrée, elle est refusée.

## Lancer l'audit

```bash
uv run fwclean audit inbox/pare-feu.conf --sortie out
uv run fwclean audit inbox/objets.csv inbox/regles.csv --sortie out
uv run fwclean audit inbox/ --sortie out
uv run fwclean audit inbox/stormshield --sortie out/stormshield
```

Un audit porte sur un seul constructeur et un seul format (FortiGate, CSV Stormshield ou fichiers natifs SNS). Sans `--sortie`, les fichiers vont dans `out/` (ignoré par git). `--contextes` pointe vers un autre fichier de zones que `./contextes.txt`, `--reseaux` vers un autre référentiel que `./reseaux.csv`.

## Sites et zones

Les noms d'objets prennent la forme `HST_SIEGE_LAN_ZABBIXSRV`. Les règles ne sont pas renommées pour le moment. Le site et la zone sont déduits de l'adresse grâce à `reseaux.csv` :

```text
reseau;site;zone;vlan
10.1.0.0/16;siege;lan;
10.1.1.0/24;siege;dmz;12
```

Le réseau le plus précis qui contient l'objet gagne. Un groupe dont les membres sont sur plusieurs sites prend `MULTI`. Un objet hors référentiel n'est pas renommé : il est listé à revoir avec un commentaire. Un réseau porte son VLAN ID (`NET_SIEGE_LAN_VLAN11-SRV-ESX-MSA`) : celui de l'interface VLAN FortiGate ou SNS qui le contient, sinon celui de la colonne facultative `vlan` de `reseaux.csv`. Services, groupes de services et calendriers n'ont ni site ni zone. Un service porte protocole (`TCP`, `UDP`, `ANY` pour les deux) et port, puis son libellé : `SVC_TCP_8080_HTTP`, `SVC_ANY_53_DNS`.

Le plan d'adressage réel est sensible : `reseaux.csv` est ignoré par git. Pour commencer :

```bash
cp reseaux.exemple.csv reseaux.csv
```

puis remplacer les lignes par les réseaux réels. Sans `reseaux.csv`, l'audit tourne quand même et liste les objets d'adresse à revoir. Les zones autorisées (`lan`, `dmz`, `wan`, `vpn`, `mgmt`, `bastion`, …, reprises des zones FortiGate) sont dans `contextes.txt`.

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

Ces exemples contiennent chacun un nom à reprendre, un doublon strict et un objet sans référence. `HST_SIEGE_LAN_LEGACY` n'est cité que par une règle désactivée : il n'est pas orphelin. `Vlan210` devient `NET_GRAS_LAN_VLAN210` par son réseau, et le groupe `Clients web`, qui mélange SIEGE et GRAS, devient `GRP_MULTI_LAN_CLIENTS-WEB`. Dans l'exemple FortiGate, `partenaire` (hors référentiel) est listé à revoir sans nom proposé, et le service `Appli metier 8443` devient `SVC_TCP_8443_APPLI-METIER`. L'exemple SNS natif n'a pas de fichier `router` : ses retraits sont suspendus, et la section Avertissements liste les noms cités mais non définis (routeur, objet global SMC, groupe absent).

Sur Stormshield, les retraits d'orphelins ne sont proposés que si `objectgroup`, `servicegroup` et `router` sont lus : sans eux, un membre de groupe ou une passerelle paraîtrait orphelin. Les objets FQDN et les hôtes `resolve=dynamic` (le nom est le nom DNS) ne sont jamais renommés.

## Tests

```bash
uv run pytest
```

## Générer reseaux.csv

```bash
uv run fwclean reseaux inbox/pare-feu.conf --site siege
```

Écrit `./reseaux.csv` avec les réseaux directement connectés du FortiGate, la zone venant de la zone FortiGate de chaque interface, traduite par les correspondances de `contextes.txt` (`mgmt = MGMT NETWORKS`), et le `vlanid` dans la colonne `vlan`. Ajouter ensuite à la main les réseaux non connectés. `--ecraser` remplace un fichier existant.

Sur un SNS, `uv run fwclean reseaux inbox/stormshield --site siege` lit le fichier `Network` : une ligne par interface à adresse statique, zone d'après le nom de l'interface, `vlan` = `Tag`.

## Produire le script d'application

```bash
uv run fwclean script inbox/pare-feu.conf --plan out/plan.json
```

Écrit dans `out/script/` trois fichiers de commandes CLI FortiGate à relire puis à coller lot par lot : `01-renommages.txt`, `02-fusions.txt`, `03-retraits.txt`, et `ignores.txt` pour ce qui n'est pas repris (objets par défaut de FortiOS, objets encore cités). Rien n'est envoyé au firewall. Détail dans [la méthode](docs/methode-nettoyage.md#appliquer-le-plan-sur-fortigate).

## Premier passage sur un export réel

Générer ou remplir `reseaux.csv` avec les réseaux et sites réels, ajuster les zones de `contextes.txt` (clés en minuscules), puis relancer l'audit. Les objets « à revoir » restants montrent les adresses absentes du référentiel. Les noms proposés sont en majuscules (`HST_SIEGE_DMZ_WEB-01`). Une fois le plan relu, produire le script, l'appliquer lot par lot, puis ré-exporter et relancer l'audit. Ce passage ne sert pas à réécrire les règles.
