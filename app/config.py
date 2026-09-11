# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parents[1]
# Neither file is committed — see .env.example for the template. ".env.shared"
# is read first so a deployment can keep fleet-wide values there, and ".env"
# overrides it with per-host values.
load_dotenv(ROOT_DIR / ".env.shared")
load_dotenv(ROOT_DIR / ".env", override=True)


@dataclass(frozen=True)
class Settings:
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_region: str
    email_s3_bucket: str
    email_s3_prefix: str
    email_s3_date_prefix_format: str
    email_s3_max_date_prefix_days: int
    email_s3_max_body_search_days: int
    email_search_header_fetch_bytes: int
    email_search_job_max_seconds: int
    # Signs the SessionMiddleware cookie holding per-browser search ownership
    # and, in central mode, the short-lived state/nonce/PKCE transaction. The
    # actual app login remains the verified Elcano cookie or opaque Explorer
    # session handled in app/auth.py.
    session_secret: str

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", ""),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", ""),
            aws_region=os.getenv("AWS_REGION", "us-east-2"),
            email_s3_bucket=os.getenv("EMAIL_S3_BUCKET", ""),
            email_s3_prefix=os.getenv("EMAIL_S3_PREFIX", "emails/"),
            email_s3_date_prefix_format=os.getenv(
                "EMAIL_S3_DATE_PREFIX_FORMAT", "emails/%Y/%m/%d/"
            ),
            email_s3_max_date_prefix_days=int(
                os.getenv("EMAIL_S3_MAX_DATE_PREFIX_DAYS", "62")
            ),
            email_s3_max_body_search_days=int(
                os.getenv("EMAIL_S3_MAX_BODY_SEARCH_DAYS", "14")
            ),
            email_search_header_fetch_bytes=int(
                os.getenv("EMAIL_HEADER_FETCH_BYTES", "65536")
            ),
            email_search_job_max_seconds=int(
                os.getenv("EMAIL_SEARCH_JOB_MAX_SECONDS", "120")
            ),
            session_secret=os.getenv(
                "EXPLORER_SESSION_SECRET", "explorer-dev-session-secret"
            ),
        )


settings = Settings.from_env()
