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

"""Tests for extension module loading trust-boundary checks."""

import sys
from types import ModuleType

import pytest

from superset.extensions.utils import (
    InMemoryLoader,
    install_in_memory_importer,
    UntrustedExtensionPathError,
    validate_extension_source_path,
)

# ---------------------------------------------------------------------------
# validate_extension_source_path – supx:// paths
# ---------------------------------------------------------------------------


def test_valid_supx_path_simple() -> None:
    validate_extension_source_path("supx://my-extension")


def test_valid_supx_path_with_segments() -> None:
    validate_extension_source_path("supx://publisher.name/ext-1.0")


def test_invalid_supx_path_empty_host() -> None:
    with pytest.raises(UntrustedExtensionPathError, match="Invalid supx://"):
        validate_extension_source_path("supx://")


def test_invalid_supx_path_special_chars() -> None:
    with pytest.raises(UntrustedExtensionPathError, match="Path traversal"):
        validate_extension_source_path("supx://../../etc/passwd")


def test_invalid_supx_path_spaces() -> None:
    with pytest.raises(UntrustedExtensionPathError, match="Invalid supx://"):
        validate_extension_source_path("supx://some path/ext")


# ---------------------------------------------------------------------------
# validate_extension_source_path – filesystem paths
# ---------------------------------------------------------------------------


def test_valid_absolute_path_no_allowlist() -> None:
    validate_extension_source_path("/opt/extensions/my-ext/dist")


def test_relative_path_rejected() -> None:
    with pytest.raises(UntrustedExtensionPathError, match="must be absolute"):
        validate_extension_source_path("relative/path/ext")


def test_absolute_path_under_allowed() -> None:
    validate_extension_source_path(
        "/opt/extensions/my-ext/dist",
        allowed_base_paths=["/opt/extensions"],
    )


def test_absolute_path_outside_allowed() -> None:
    with pytest.raises(UntrustedExtensionPathError, match="not under any allowed"):
        validate_extension_source_path(
            "/srv/untrusted/ext",  # noqa: S108
            allowed_base_paths=["/opt/extensions"],
        )


def test_absolute_path_with_multiple_allowed() -> None:
    validate_extension_source_path(
        "/var/lib/superset/extensions/ext1/dist",
        allowed_base_paths=["/opt/extensions", "/var/lib/superset/extensions"],
    )


def test_path_traversal_blocked_by_allowlist(
    tmp_path: "pytest.TempPathFactory",
) -> None:
    allowed = str(tmp_path / "safe")
    traversal = str(tmp_path / "safe" / ".." / "unsafe")
    with pytest.raises(UntrustedExtensionPathError, match="not under any allowed"):
        validate_extension_source_path(traversal, allowed_base_paths=[allowed])


# ---------------------------------------------------------------------------
# install_in_memory_importer – integration with validation
# ---------------------------------------------------------------------------


def test_install_in_memory_importer_valid_supx(monkeypatch: pytest.MonkeyPatch) -> None:
    original_meta_path = sys.meta_path.copy()
    try:
        install_in_memory_importer(
            {"hello.py": b"x = 1"},
            source_base_path="supx://test-ext",
        )
        assert len(sys.meta_path) == len(original_meta_path) + 1
    finally:
        sys.meta_path[:] = original_meta_path


def test_install_in_memory_importer_rejects_relative() -> None:
    with pytest.raises(UntrustedExtensionPathError):
        install_in_memory_importer(
            {"hello.py": b"x = 1"},
            source_base_path="relative/bad",
        )


def test_install_in_memory_importer_rejects_outside_allowed() -> None:
    with pytest.raises(UntrustedExtensionPathError):
        install_in_memory_importer(
            {"hello.py": b"x = 1"},
            source_base_path="/srv/untrusted",  # noqa: S108
            allowed_base_paths=["/opt/extensions"],
        )


# ---------------------------------------------------------------------------
# InMemoryLoader.exec_module – defense-in-depth origin check
# ---------------------------------------------------------------------------


def test_exec_module_accepts_absolute_origin() -> None:
    loader = InMemoryLoader(
        module_name="test_mod",
        source="x = 42",
        is_package=False,
        origin="/opt/extensions/ext/backend/src/test_mod.py",
    )
    module = ModuleType("test_mod")
    loader.exec_module(module)
    assert module.x == 42  # noqa: E501


def test_exec_module_accepts_supx_origin() -> None:
    loader = InMemoryLoader(
        module_name="test_mod",
        source="y = 99",
        is_package=False,
        origin="supx://ext-id/backend/src/test_mod.py",
    )
    module = ModuleType("test_mod")
    loader.exec_module(module)
    assert module.y == 99  # noqa: E501


def test_exec_module_rejects_relative_origin() -> None:
    loader = InMemoryLoader(
        module_name="test_mod",
        source="z = 1",
        is_package=False,
        origin="relative/path/test_mod.py",
    )
    module = ModuleType("test_mod")
    with pytest.raises(UntrustedExtensionPathError, match="untrusted origin"):
        loader.exec_module(module)
