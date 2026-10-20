from pathlib import Path

import pytest

from fwclean.sites import lire_reseaux

RACINE = Path(__file__).resolve().parents[1]


@pytest.fixture
def racine() -> Path:
    return RACINE


@pytest.fixture
def referentiel():
    return lire_reseaux(RACINE / "reseaux.exemple.csv")
