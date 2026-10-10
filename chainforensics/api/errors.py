from __future__ import annotations

import logging
import uuid

from fastapi import Request
from fastapi.responses import JSONResponse


logger = logging.getLogger("chainforensics.api")


def create_correlation_id() -> str:
    return str(uuid.uuid4())


def generic_error_response(
    *,
    status_code: int,
    correlation_id: str,
) -> JSONResponse:
    """
    Return the generic error structure exposed to callers.

    Detailed exception information must never be returned
    directly to the API caller.
    """

    return JSONResponse(
        status_code=status_code,
        content={
            "error": "Request could not be completed.",
            "correlation_id": correlation_id,
        },
    )


async def generic_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    """
    Catch unexpected server errors.

    Caller receives only a generic message + correlation ID.
    Full exception details are logged server-side.
    """

    correlation_id = create_correlation_id()

    logger.exception(
        "Unhandled API exception | correlation_id=%s | "
        "method=%s | path=%s",
        correlation_id,
        request.method,
        request.url.path,
    )

    return generic_error_response(
        status_code=500,
        correlation_id=correlation_id,
    )