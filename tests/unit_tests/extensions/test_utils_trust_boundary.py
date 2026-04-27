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

import types

import pytest

from superset.extensions.utils import (
    _validate_source_base_path,
    InMemoryLoader,
    install_in_memory_importer,
    UntrustedExtensionOriginError,
)

# ---------------------------------------------------------------------------
# _validate_source_base_path
# ---------------------------------------------------------------------------


class TestValidateSourceBasePath:
    """Acceptance / rejection of source_base_path values."""

    # --- accepted paths ---

    def test_supx_scheme_accepted(self) -> None:
        _validate_source_base_path("supx://my-extension")

    def test_supx_scheme_with_dots_accepted(self) -> None:
        _validate_source_base_path("supx://org.ext-1.0")

    def test_absolute_filesystem_path_accepted(self) -> None:
        _validate_source_base_path("/opt/extensions/my-ext/dist")

    def test_absolute_path_nonexistent_accepted(self) -> None:
        _validate_source_base_path("/nonexistent/but/absolute/path")

    # --- rejected paths ---

    def test_relative_path_rejected(self) -> None:
        with pytest.raises(UntrustedExtensionOriginError, match="must be absolute"):
            _validate_source_base_path("relative/path/to/ext")

    def test_empty_string_rejected(self) -> None:
        with pytest.raises(UntrustedExtensionOriginError, match="must be absolute"):
            _validate_source_base_path("")

    def test_bare_dot_rejected(self) -> None:
        with pytest.raises(UntrustedExtensionOriginError, match="must be absolute"):
            _validate_source_base_path(".")

    def test_malformed_supx_empty_id_rejected(self) -> None:
        with pytest.raises(UntrustedExtensionOriginError, match="Malformed supx://"):
            _validate_source_base_path("supx://")

    def test_malformed_supx_bad_chars_rejected(self) -> None:
        with pytest.raises(UntrustedExtensionOriginError, match="Malformed supx://"):
            _validate_source_base_path("supx://../../etc/passwd")

    def test_http_scheme_rejected(self) -> None:
        with pytest.raises(UntrustedExtensionOriginError, match="must be absolute"):
            _validate_source_base_path("http://evil.com/payload")

    def test_file_scheme_rejected(self) -> None:
        with pytest.raises(UntrustedExtensionOriginError, match="must be absolute"):
            _validate_source_base_path("file:///etc/passwd")


# ---------------------------------------------------------------------------
# install_in_memory_importer
# ---------------------------------------------------------------------------


class TestInstallInMemoryImporter:
    def test_rejects_relative_source_base_path(self) -> None:
        with pytest.raises(UntrustedExtensionOriginError):
            install_in_memory_importer({}, "relative/bad")

    def test_accepts_supx_scheme(self) -> None:
        install_in_memory_importer({}, "supx://good-ext")

    def test_accepts_absolute_path(self) -> None:
        install_in_memory_importer({}, "/opt/extensions/good-ext/dist")


# ---------------------------------------------------------------------------
# InMemoryLoader.exec_module – origin guard
# ---------------------------------------------------------------------------


class TestInMemoryLoaderOriginGuard:
    def test_exec_module_rejects_relative_origin(self) -> None:
        loader = InMemoryLoader(
            module_name="evil",
            source="x = 1",
            is_package=False,
            origin="relative/evil.py",
        )
        module = types.ModuleType("evil")
        with pytest.raises(UntrustedExtensionOriginError, match="untrusted origin"):
            loader.exec_module(module)

    def test_exec_module_accepts_supx_origin(self) -> None:
        loader = InMemoryLoader(
            module_name="ok_mod",
            source="x = 1",
            is_package=False,
            origin="supx://my-ext/backend/src/ok_mod.py",
        )
        module = types.ModuleType("ok_mod")
        loader.exec_module(module)
        assert module.x == 1

    def test_exec_module_accepts_absolute_origin(self) -> None:
        loader = InMemoryLoader(
            module_name="ok_mod",
            source="y = 42",
            is_package=False,
            origin="/opt/extensions/my-ext/dist/backend/src/ok_mod.py",
        )
        module = types.ModuleType("ok_mod")
        loader.exec_module(module)
        assert module.y == 42
