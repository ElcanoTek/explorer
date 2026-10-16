# SPDX-License-Identifier: BSD-3-Clause
#
# Vendored from python-dotenv 1.2.4 (https://github.com/theskumar/python-dotenv),
# upstream path: src/dotenv/variables.py. Trimmed to what Explorer uses and modified
# (typing modernized; unused code removed). See LICENSE in this directory.
# Copyright (c) 2014, Saurabh Kumar (python-dotenv), 2013, Ted Tieken
# (django-dotenv-rw), 2013, Jacob Kaplan-Moss (django-dotenv)

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from re import Pattern

_posix_variable: Pattern[str] = re.compile(
    r"""
    \$\{
        (?P<name>[^\}:]*)
        (?::-
            (?P<default>[^\}]*)
        )?
    \}
    """,
    re.VERBOSE,
)


class Literal:
    def __init__(self, value: str) -> None:
        self.value = value

    def resolve(self, env: Mapping[str, str | None]) -> str:
        return self.value


class Variable:
    def __init__(self, name: str, default: str | None) -> None:
        self.name = name
        self.default = default

    def resolve(self, env: Mapping[str, str | None]) -> str:
        default = self.default if self.default is not None else ""
        result = env.get(self.name, default)
        return result if result is not None else ""


def parse_variables(value: str) -> Iterator[Literal | Variable]:
    cursor = 0

    for match in _posix_variable.finditer(value):
        (start, end) = match.span()
        name = match["name"]
        default = match["default"]

        if start > cursor:
            yield Literal(value=value[cursor:start])

        yield Variable(name=name, default=default)
        cursor = end

    length = len(value)
    if cursor < length:
        yield Literal(value=value[cursor:length])
