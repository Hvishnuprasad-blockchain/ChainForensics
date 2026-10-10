from __future__ import annotations

import os
import secrets
from collections.abc import Generator

from dotenv import load_dotenv
from fastapi import Header, HTTPException, status
from sqlalchemy.orm import Session

from chainforensics.database.database import SessionLocal


# Load variables from .env
load_dotenv()


def get_db() -> Generator[Session, None, None]:
    """
    Provide one SQLAlchemy database session per API request.
    """

    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


def require_api_key(
    x_api_key: str | None = Header(
        default=None,
        alias="x-api-key",
    ),
) -> None:
    """
    Protect API endpoints using the CHAINFORENSIS_API_KEY
    environment variable.
    """

    expected_api_key = os.getenv(
        "CHAINFORENSIS_API_KEY"
    )

    if not expected_api_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API key is not configured.",
        )

    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key.",
        )

    if not secrets.compare_digest(
        x_api_key.strip(),
        expected_api_key.strip(),
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
        )