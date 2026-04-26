# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Tests for extension module-loading trust-boundary checks."""

import sys

import pytest

from superset.extensions.utils import (
    _validate_file_dict,
    _validate_source_base_path,
    install_in_memory_importer,
)

# ---------------------------------------------------------------------------
# _validate_source_base_path
# ---------------------------------------------------------------------------


def test_validate_source_base_path_accepts_supx_scheme() -> None:
    _validate_source_base_path("supx://my-extension-id")


def test_validate_source_base_path_accepts_absolute_path() -> None:
    _validate_source_base_path("/opt/extensions/my-ext/dist")


def test_validate_source_base_path_rejects_empty_supx_id() -> None:
    with pytest.raises(ValueError, match="Invalid supx://"):
        _validate_source_base_path("supx://")


def test_validate_source_base_path_rejects_supx_with_slash() -> None:
    with pytest.raises(ValueError, match="Invalid supx://"):
        _validate_source_base_path("supx://ext/../../etc/passwd")


def test_validate_source_base_path_rejects_relative_path() -> None:
    with pytest.raises(ValueError, match="must be absolute"):
        _validate_source_base_path("relative/path/to/extension")


def test_validate_source_base_path_rejects_dotdot_in_path() -> None:
    with pytest.raises(ValueError, match="must be absolute"):
        _validate_source_base_path("/opt/extensions/../secret/ext")


# ---------------------------------------------------------------------------
# _validate_file_dict
# ---------------------------------------------------------------------------


def test_validate_file_dict_accepts_valid_py_files() -> None:
    _validate_file_dict(
        {
            "my_module.py": b"print('hello')",
            "__init__.py": b"",
            "sub/pkg/__init__.py": b"",
            "sub/pkg/helpers.py": b"x = 1",
        }
    )


def test_validate_file_dict_rejects_absolute_path() -> None:
    with pytest.raises(ValueError, match="must be relative"):
        _validate_file_dict({"/etc/passwd.py": b""})


def test_validate_file_dict_rejects_path_traversal() -> None:
    with pytest.raises(ValueError, match="Path traversal"):
        _validate_file_dict({"../../../etc/cron.d/evil.py": b""})


def test_validate_file_dict_rejects_non_py_file() -> None:
    with pytest.raises(ValueError, match="Only .py files"):
        _validate_file_dict({"payload.sh": b"#!/bin/bash\nrm -rf /"})


def test_validate_file_dict_rejects_non_py_file_hidden_ext() -> None:
    with pytest.raises(ValueError, match="Only .py files"):
        _validate_file_dict({"module.py.bak": b""})


# ---------------------------------------------------------------------------
# install_in_memory_importer (integration of both validations)
# ---------------------------------------------------------------------------


def test_install_in_memory_importer_rejects_bad_base_path() -> None:
    with pytest.raises(ValueError, match="must be absolute"):
        install_in_memory_importer(
            {"mod.py": b"x = 1"},
            source_base_path="relative/bad",
        )


def test_install_in_memory_importer_rejects_bad_file_dict() -> None:
    with pytest.raises(ValueError, match="Path traversal"):
        install_in_memory_importer(
            {"../../evil.py": b"import os; os.system('id')"},
            source_base_path="/opt/extensions/my-ext/dist",
        )


def test_install_in_memory_importer_succeeds_for_valid_inputs() -> None:
    source_base_path = "supx://test-ext"
    file_dict: dict[str, bytes] = {"hello.py": b"GREETING = 'hi'"}
    meta_path_before = len(sys.meta_path)
    install_in_memory_importer(file_dict, source_base_path)
    assert len(sys.meta_path) == meta_path_before + 1
    # Clean up: remove the finder we just inserted
    sys.meta_path.pop(0)
