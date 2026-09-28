from pathlib import Path

import pytest

from fwclean.naming import lire_contextes
from fwclean.sites import lire_reseaux

RACINE = Path(__file__).resolve().parents[1]


@pytest.fixture
def racine() -> Path:
    return RACINE


@pytest.fixture
def contextes() -> tuple[str, ...]:
    return lire_contextes(RACINE / "contextes.txt")


@pytest.fixture
def referentiel(contextes):
    return lire_reseaux(RACINE / "reseaux.exemple.csv", contextes)
