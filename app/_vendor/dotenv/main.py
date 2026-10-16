# SPDX-License-Identifier: BSD-3-Clause
#
# Vendored from python-dotenv 1.2.4 (https://github.com/theskumar/python-dotenv),
# upstream path: src/dotenv/main.py. Trimmed to what Explorer uses and modified
# (typing modernized; unused code removed). See LICENSE in this directory.
# Copyright (c) 2014, Saurabh Kumar (python-dotenv), 2013, Ted Tieken
# (django-dotenv-rw), 2013, Jacob Kaplan-Moss (django-dotenv)

from __future__ import annotations

import io
import logging
import os
import stat
from collections.abc import Iterable, Iterator, Mapping
from typing import IO

from .parser import parse_stream
from .variables import parse_variables

StrPath = str | os.PathLike[str]

logger = logging.getLogger(__name__)


def _load_dotenv_disabled() -> bool:
    """Determine if dotenv loading has been disabled."""
    if "PYTHON_DOTENV_DISABLED" not in os.environ:
        return False
    value = os.environ["PYTHON_DOTENV_DISABLED"].casefold()
    return value in {"1", "true", "t", "yes", "y"}


def _is_file_or_fifo(path: StrPath) -> bool:
    """Return True if `path` exists and is either a regular file or a FIFO."""
    if os.path.isfile(path):
        return True

    try:
        st = os.stat(path)
    except OSError:
        return False

    return stat.S_ISFIFO(st.st_mode)


def _parse(stream: IO[str]) -> Iterator[tuple[str, str | None]]:
    for mapping in parse_stream(stream):
        if mapping.error:
            logger.warning(
                "python-dotenv could not parse statement starting at line %s",
                mapping.original.line,
            )
        if mapping.key is not None:
            yield mapping.key, mapping.value


def resolve_variables(
    values: Iterable[tuple[str, str | None]],
    override: bool,
) -> Mapping[str, str | None]:
    new_values: dict[str, str | None] = {}

    for name, value in values:
        if value is None:
            result = None
        else:
            atoms = parse_variables(value)
            env: dict[str, str | None] = {}
            if override:
                env.update(os.environ)
                env.update(new_values)
            else:
                env.update(new_values)
                env.update(os.environ)
            result = "".join(atom.resolve(env) for atom in atoms)

        new_values[name] = result

    return new_values


def dotenv_values(
    dotenv_path: StrPath,
    *,
    override: bool = True,
    interpolate: bool = True,
    encoding: str | None = "utf-8",
) -> Mapping[str, str | None]:
    """Parse a .env file into a dict; a missing file is an empty dict.

    ``override`` only decides which side wins while interpolating
    ``${VAR}`` references (the file's earlier values, or os.environ).
    """
    if _is_file_or_fifo(dotenv_path):
        with open(dotenv_path, encoding=encoding) as stream:
            raw_values = list(_parse(stream))
    else:
        raw_values = list(_parse(io.StringIO("")))
    if interpolate:
        return dict(resolve_variables(raw_values, override=override))
    return dict(raw_values)


def load_dotenv(
    dotenv_path: StrPath,
    override: bool = False,
    interpolate: bool = True,
    encoding: str | None = "utf-8",
) -> bool:
    """Parse a .env file and load its variables into os.environ.

    Returns True if at least one variable was found. With ``override`` false,
    a variable already in the environment keeps its value. Loading is
    skipped when ``PYTHON_DOTENV_DISABLED`` is set to a truthy value.
    """
    if _load_dotenv_disabled():
        logger.debug(
            "python-dotenv: .env loading disabled by PYTHON_DOTENV_DISABLED "
            "environment variable"
        )
        return False

    values = dotenv_values(
        dotenv_path, override=override, interpolate=interpolate, encoding=encoding
    )
    if not values:
        return False

    for k, v in values.items():
        if k in os.environ and not override:
            continue
        if v is not None:
            os.environ[k] = v

    return True
