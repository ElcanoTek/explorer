# SPDX-License-Identifier: BSD-3-Clause
#
# Vendored from python-dotenv 1.2.4 (https://github.com/theskumar/python-dotenv),
# upstream path: src/dotenv/__init__.py. Trimmed to what Explorer uses and modified
# (typing modernized; unused code removed). See LICENSE in this directory.
# Copyright (c) 2014, Saurabh Kumar (python-dotenv), 2013, Ted Tieken
# (django-dotenv-rw), 2013, Jacob Kaplan-Moss (django-dotenv)

"""Minimal python-dotenv: ``load_dotenv(path, override=...)`` only."""

from .main import dotenv_values, load_dotenv

__all__ = ["dotenv_values", "load_dotenv"]
