import hashlib
import json

import pytest

from fwclean.cli import executer
from fwclean.model import ErreurLecture
from fwclean.charger import charger


def test_aide_en_francais(capsys):
    with pytest.raises(SystemExit) as sortie:
        executer(["--help"])
    assert sortie.value.code == 0
    texte = capsys.readouterr().out
    assert "nomenclature" in texte
    assert "orphelins" in texte
    assert "N'applique aucun changement" in texte


def test_audit_cli_ecrit_le_plan(racine, tmp_path, capsys):
    source = racine / "examples" / "fortigate" / "nomenclature.conf"
    empreinte = hashlib.sha256(source.read_bytes()).hexdigest()
    sortie = tmp_path / "sortie"
    code = executer(
        [
            "audit",
            str(source),
            "--sortie",
            str(sortie),
            "--contextes",
            str(racine / "contextes.txt"),
        ]
    )
    assert code == 0
    assert hashlib.sha256(source.read_bytes()).hexdigest() == empreinte
    rapport = (sortie / "rapport.md").read_text(encoding="utf-8")
    plan = json.loads((sortie / "plan.json").read_text(encoding="utf-8"))
    assert "règle désactivée n'est pas orphelin" in rapport
    assert "Web_DMZ" in rapport
    assert "srv-oublie" in rapport
    assert set(plan) == {
        "avertissement",
        "constructeur",
        "sources",
        "renommages",
        "fusions",
        "retraits",
    }
    assert "appliqu" in plan["avertissement"]
    assert plan["constructeur"] == "fortigate"
    assert any(item["ancien"] == "web_dmz_backup" for item in plan["renommages"])
    assert any(item["nom"] == "srv-oublie" for item in plan["retraits"])
    assert "Aucune modification appliquée." in capsys.readouterr().out


def test_sauvegarde_na_refusee(tmp_path, capsys):
    fichier = tmp_path / "firewall.na"
    fichier.write_bytes(b"chiffre")
    code = executer(["audit", str(fichier), "--sortie", str(tmp_path / "out")])
    assert code == 2
    assert ".na" in capsys.readouterr().err


def test_melange_de_constructeurs(racine):
    with pytest.raises(ErreurLecture):
        charger(
            [
                racine / "examples" / "fortigate" / "nomenclature.conf",
                racine / "examples" / "stormshield" / "objets.csv",
            ]
        )


def test_gitignore_inbox_et_out(racine):
    texte = (racine / ".gitignore").read_text(encoding="utf-8")
    assert "inbox/" in texte
    assert "out/" in texte
