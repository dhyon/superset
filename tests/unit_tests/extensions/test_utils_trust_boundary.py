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

"""Tests for extension loader trust-boundary checks (Bandit B102)."""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from superset.extensions.utils import (
    _trusted_source_bases,
    _validate_source_base_path,
    InMemoryFinder,
    InMemoryLoader,
    install_in_memory_importer,
)

# ---------------------------------------------------------------------------
# _validate_source_base_path
# ---------------------------------------------------------------------------


def test_validate_supx_virtual_scheme_accepted() -> None:
    _validate_source_base_path("supx://my-extension-id")


def test_validate_supx_virtual_scheme_with_subpath_accepted() -> None:
    _validate_source_base_path("supx://my-extension-id/backend/src")


def test_validate_allowed_local_path_exact_match(tmp_path: Path) -> None:
    dist = tmp_path / "ext" / "dist"
    dist.mkdir(parents=True)
    _validate_source_base_path(str(dist), allowed_local_paths=[str(dist)])


def test_validate_allowed_local_path_child(tmp_path: Path) -> None:
    dist = tmp_path / "ext" / "dist"
    dist.mkdir(parents=True)
    child = dist / "backend" / "src"
    child.mkdir(parents=True)
    _validate_source_base_path(str(child), allowed_local_paths=[str(dist)])


def test_validate_rejects_unrelated_filesystem_path(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    rogue = tmp_path / "rogue"
    rogue.mkdir()
    with pytest.raises(ValueError, match="outside the trusted"):
        _validate_source_base_path(str(rogue), allowed_local_paths=[str(allowed)])


def test_validate_rejects_when_no_allowed_paths() -> None:
    with pytest.raises(ValueError, match="outside the trusted"):
        _validate_source_base_path("/some/random/path", allowed_local_paths=[])


def test_validate_rejects_none_allowed_paths() -> None:
    with pytest.raises(ValueError, match="outside the trusted"):
        _validate_source_base_path("/some/random/path", allowed_local_paths=None)


def test_validate_rejects_path_traversal_escape(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    # Attempt to escape via ".." should resolve outside the allowed directory
    rogue = str(allowed) + "/../rogue"
    with pytest.raises(ValueError, match="outside the trusted"):
        _validate_source_base_path(rogue, allowed_local_paths=[str(allowed)])


# ---------------------------------------------------------------------------
# InMemoryFinder -- path traversal in bundle file paths
# ---------------------------------------------------------------------------


def test_finder_rejects_path_traversal_in_file_dict() -> None:
    file_dict = {"../../etc/passwd": b"print('pwned')"}
    with pytest.raises(ValueError, match="Path traversal"):
        InMemoryFinder(file_dict, source_base_path="supx://test-ext")


def test_finder_accepts_clean_file_paths() -> None:
    file_dict = {"mypkg/__init__.py": b"", "mypkg/tasks.py": b"x = 1"}
    finder = InMemoryFinder(file_dict, source_base_path="supx://test-ext")
    assert "mypkg" in finder.modules
    assert "mypkg.tasks" in finder.modules


# ---------------------------------------------------------------------------
# InMemoryLoader.exec_module -- defense-in-depth origin check
# ---------------------------------------------------------------------------


def test_loader_rejects_untrusted_origin(tmp_path: Path) -> None:
    rogue_base = str(tmp_path / "rogue")
    rogue_origin = f"{rogue_base}/backend/src/evil.py"
    _trusted_source_bases.discard(rogue_base)

    loader = InMemoryLoader(
        module_name="evil",
        source="x = 1",
        is_package=False,
        origin=rogue_origin,
    )
    module = types.ModuleType("evil")
    with pytest.raises(RuntimeError, match="untrusted origin"):
        loader.exec_module(module)


def test_loader_accepts_trusted_origin() -> None:
    base = "supx://good-ext"
    _trusted_source_bases.add(base)
    try:
        origin = f"{base}/backend/src/tasks.py"
        loader = InMemoryLoader(
            module_name="tasks",
            source="x = 42",
            is_package=False,
            origin=origin,
        )
        module = types.ModuleType("tasks")
        loader.exec_module(module)
        assert module.x == 42  # noqa: S101
    finally:
        _trusted_source_bases.discard(base)


# ---------------------------------------------------------------------------
# install_in_memory_importer -- integration checks
# ---------------------------------------------------------------------------


def test_install_importer_registers_supx_origin() -> None:
    base = "supx://integration-test-ext"
    _trusted_source_bases.discard(base)
    original_meta_path = sys.meta_path[:]
    try:
        install_in_memory_importer(
            {"tasks.py": b"val = 99"},
            source_base_path=base,
        )
        assert base in _trusted_source_bases
    finally:
        sys.meta_path[:] = original_meta_path
        _trusted_source_bases.discard(base)


def test_install_importer_rejects_rogue_filesystem_path(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    rogue = tmp_path / "rogue"
    rogue.mkdir()
    with pytest.raises(ValueError, match="outside the trusted"):
        install_in_memory_importer(
            {"tasks.py": b"x = 1"},
            source_base_path=str(rogue),
            allowed_local_paths=[str(allowed)],
        )


def test_install_importer_accepts_allowed_filesystem_path(tmp_path: Path) -> None:
    dist = tmp_path / "myext" / "dist"
    dist.mkdir(parents=True)
    original_meta_path = sys.meta_path[:]
    try:
        install_in_memory_importer(
            {"tasks.py": b"val = 7"},
            source_base_path=str(dist),
            allowed_local_paths=[str(dist)],
        )
        assert (
            str(dist.resolve()) in _trusted_source_bases
            or str(dist) in _trusted_source_bases
        )
    finally:
        sys.meta_path[:] = original_meta_path
        _trusted_source_bases.discard(str(dist))
        _trusted_source_bases.discard(str(dist.resolve()))
