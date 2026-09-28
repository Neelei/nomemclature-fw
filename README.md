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
- Stormshield : le CSV des objets et le CSV des règles de filtrage. Une sauvegarde `.na` est chiffrée, elle est refusée. Le détail des colonnes est dans la méthode de nettoyage. Déposer aussi `routes.csv` si des objets ne sont cités que par le routage.

## Lancer l'audit

```bash
uv run fwclean audit inbox/pare-feu.conf --sortie out
uv run fwclean audit inbox/objets.csv inbox/regles.csv --sortie out
uv run fwclean audit inbox/ --sortie out
```

Sans `--sortie`, les fichiers vont dans `out/` (ignoré par git). `--contextes` pointe vers un autre fichier de zones que `./contextes.txt`, `--reseaux` vers un autre référentiel que `./reseaux.csv`.

## Sites et zones

Les noms prennent la forme `HST_EPFR_LAN_ZABBIXSRV` (objets) et `ALLOW_EPFR_LAN_DMZ_HTTPS` (règles). Le site et la zone sont déduits de l'adresse grâce à `reseaux.csv` :

```text
reseau;site;zone
10.1.0.0/16;epfr;lan
10.1.1.0/24;epfr;dmz
```

Le réseau le plus précis qui contient l'objet gagne. Hors référentiel, le site vaut `CTX` et la zone vient de l'ancien nom. Un groupe ou une règle dont les membres sont sur plusieurs sites prend `MULTI`.

Le plan d'adressage réel est sensible : `reseaux.csv` est ignoré par git. Pour commencer :

```bash
cp reseaux.exemple.csv reseaux.csv
```

puis remplacer les lignes par les réseaux réels. Sans `reseaux.csv`, l'audit tourne quand même et propose `CTX` comme site. Les zones autorisées (`lan`, `dmz`, `wan`, `vpn`, `mgmt`, `bastion`, …, reprises des zones FortiGate) sont dans `contextes.txt`.

La commande affiche les compteurs et écrit :

- `out/rapport.md` — noms non conformes, doublons, orphelins ;
- `out/plan.json` — renommages, fusions et retraits proposés.

Rien n'est appliqué. Le plan se relit avant toute modification sur l'équipement, dans l'ordre : renommage, fusion des doublons stricts, retrait des orphelins.

Pour voir le comportement sans export réel :

```bash
uv run fwclean audit examples/fortigate/nomenclature.conf --reseaux reseaux.exemple.csv --sortie out/fortigate
uv run fwclean audit examples/stormshield --reseaux reseaux.exemple.csv --sortie out/stormshield
```

Ces exemples contiennent chacun un nom à reprendre, un doublon strict et un objet sans référence. `HST_EPFR_LAN_LEGACY` n'est cité que par une règle désactivée : il n'est pas orphelin. `Vlan210` devient `NET_GRAS_LAN_VLAN210` par son réseau, et le groupe `Clients web`, qui mélange EPFR et GRAS, devient `GRP_MULTI_LAN_CLIENTS-WEB`.

## Tests

```bash
uv run pytest
```

## Premier passage sur un export réel

Remplir `reseaux.csv` avec les réseaux et sites réels, ajuster les zones de `contextes.txt` (clés en minuscules), puis relancer l'audit. Les noms en `CTX` restants montrent les adresses absentes du référentiel. Les noms proposés sont en majuscules (`HST_EPFR_DMZ_WEB-01`). Ce passage ne sert pas à réécrire les règles.
