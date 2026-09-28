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

Sans `--sortie`, les fichiers vont dans `out/` (ignoré par git). `--contextes` pointe vers un autre fichier que `./contextes.txt` si les codes site ne sont pas encore ceux du dépôt.

La commande affiche les compteurs et écrit :

- `out/rapport.md` — noms non conformes, doublons, orphelins ;
- `out/plan.json` — renommages, fusions et retraits proposés.

Rien n'est appliqué. Le plan se relit avant toute modification sur l'équipement, dans l'ordre : renommage, fusion des doublons stricts, retrait des orphelins.

Pour voir le comportement sans export réel :

```bash
uv run fwclean audit examples/fortigate/nomenclature.conf --sortie out/fortigate
uv run fwclean audit examples/stormshield --sortie out/stormshield
```

Ces exemples contiennent chacun un nom à reprendre, un doublon strict et un objet sans référence. `HST-LAN-LEGACY` n'est cité que par une règle désactivée : il n'est pas orphelin.

## Tests

```bash
uv run pytest
```

## Premier passage sur un export réel

Ajuster la liste `dmz`, `lan`, `wan`, `vpn` et les codes site dans `contextes.txt` (clés en minuscules), puis relancer l'audit. Les noms proposés sont en majuscules (`HST-DMZ-WEB-01`). Ce passage ne sert pas à réécrire les règles.
