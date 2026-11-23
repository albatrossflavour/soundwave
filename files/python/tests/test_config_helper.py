"""Run from files/python with: python3 -m pytest tests -q"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lib.config_helper import load_pe_token  # noqa: E402


# load_pe_token: rbac_token renews the file between runs, so each run reads it,
# and a run with no usable token has to say why rather than send an empty header.

def test_token_from_config_stands_without_token_file():
    params = {"token": "FROM-CONFIG", "token_file": ""}
    load_pe_token(params)
    assert params["token"] == "FROM-CONFIG"


def test_token_file_is_read_and_stripped(tmp_path):
    path = tmp_path / "pe.token"
    path.write_text("  RENEWED\n\n")
    params = {"token_file": str(path)}
    load_pe_token(params)
    assert params["token"] == "RENEWED"


def test_a_missing_token_file_fails_naming_it(tmp_path):
    path = tmp_path / "pe.token"
    with pytest.raises(RuntimeError, match=f"Cannot read the PE token from {path}"):
        load_pe_token({"token_file": str(path)})


@pytest.mark.parametrize("content", ["", " \n\t\n"])
def test_an_empty_token_file_fails(tmp_path, content):
    path = tmp_path / "pe.token"
    path.write_text(content)
    with pytest.raises(RuntimeError, match="is empty"):
        load_pe_token({"token_file": str(path)})
