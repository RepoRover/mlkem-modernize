from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def dataset_path() -> Path:
    return REPO_ROOT / "data" / "weather_data.csv"
