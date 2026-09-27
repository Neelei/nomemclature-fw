from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]


@pytest.fixture
def racine() -> Path:
    return RACINE
