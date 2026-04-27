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
from collections import OrderedDict
from contextlib import nullcontext
from datetime import datetime, timedelta
from typing import Any

import pytest
from marshmallow import Schema

from superset.dashboards.permalink.schemas import DashboardPermalinkSchema
from superset.key_value.exceptions import (
    KeyValueCodecDecodeException,
    KeyValueCodecEncodeException,
)
from superset.key_value.types import (
    JsonKeyValueCodec,
    MarshmallowKeyValueCodec,
    PickleKeyValueCodec,
)


@pytest.mark.parametrize(
    "input_,expected_result",
    [
        (
            {"foo": "bar"},
            {"foo": "bar"},
        ),
        (
            {"foo": (1, 2, 3)},
            {"foo": [1, 2, 3]},
        ),
        (
            {1, 2, 3},
            KeyValueCodecEncodeException(),
        ),
        (
            object(),
            KeyValueCodecEncodeException(),
        ),
    ],
)
def test_json_codec(input_: Any, expected_result: Any):
    cm = (
        pytest.raises(type(expected_result))
        if isinstance(expected_result, Exception)
        else nullcontext()
    )
    with cm:
        codec = JsonKeyValueCodec()
        encoded_value = codec.encode(input_)
        assert expected_result == codec.decode(encoded_value)


@pytest.mark.parametrize(
    "schema,input_,expected_result",
    [
        (
            DashboardPermalinkSchema(),
            {
                "dashboardId": "1",
                "state": {
                    "urlParams": [["foo", "bar"], ["foo", "baz"]],
                },
            },
            {
                "dashboardId": "1",
                "state": {
                    "urlParams": [("foo", "bar"), ("foo", "baz")],
                },
            },
        ),
        (
            DashboardPermalinkSchema(),
            {"foo": "bar"},
            KeyValueCodecEncodeException(),
        ),
    ],
)
def test_marshmallow_codec(schema: Schema, input_: Any, expected_result: Any):
    cm = (
        pytest.raises(type(expected_result))
        if isinstance(expected_result, Exception)
        else nullcontext()
    )
    with cm:
        codec = MarshmallowKeyValueCodec(schema)
        encoded_value = codec.encode(input_)
        assert expected_result == codec.decode(encoded_value)


@pytest.mark.parametrize(
    "input_,expected_result",
    [
        (
            {1, 2, 3},
            {1, 2, 3},
        ),
        (
            {"foo": 1, "bar": {1: (1, 2, 3)}, "baz": {1, 2, 3}},
            {
                "foo": 1,
                "bar": {1: (1, 2, 3)},
                "baz": {1, 2, 3},
            },
        ),
    ],
)
def test_pickle_codec(input_: Any, expected_result: Any):
    codec = PickleKeyValueCodec()
    encoded_value = codec.encode(input_)
    assert expected_result == codec.decode(encoded_value)


@pytest.mark.parametrize(
    "input_,expected_result",
    [
        (
            OrderedDict([("a", 1), ("b", 2)]),
            OrderedDict([("a", 1), ("b", 2)]),
        ),
        (
            {"ts": datetime(2024, 1, 1), "delta": timedelta(seconds=30)},
            {"ts": datetime(2024, 1, 1), "delta": timedelta(seconds=30)},
        ),
    ],
)
def test_pickle_codec_allowed_types(input_: Any, expected_result: Any) -> None:
    codec = PickleKeyValueCodec()
    encoded_value = codec.encode(input_)
    assert expected_result == codec.decode(encoded_value)


def test_pickle_codec_rejects_os_system() -> None:
    """Crafted pickle payload referencing os.system must be rejected."""
    payload = (
        b"\x80\x04\x95\x1f\x00\x00\x00\x00\x00\x00\x00"
        b"\x8c\x05posix\x94\x8c\x06system\x94\x93\x94"
        b"\x8c\x04true\x94\x85\x94R\x94."
    )
    codec = PickleKeyValueCodec()
    with pytest.raises(KeyValueCodecDecodeException, match="forbidden"):
        codec.decode(payload)


def test_pickle_codec_rejects_eval() -> None:
    """Pickle payload referencing builtins.eval must be rejected."""
    payload = (
        b"\x80\x04\x95\x1d\x00\x00\x00\x00\x00\x00\x00"
        b"\x8c\x08builtins\x94\x8c\x04eval\x94\x93\x94"
        b"\x8c\x011\x94\x85\x94R\x94."
    )
    codec = PickleKeyValueCodec()
    with pytest.raises(KeyValueCodecDecodeException, match="forbidden"):
        codec.decode(payload)
