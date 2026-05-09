from typing import Any, Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class ErrorDetail(BaseModel):
    message: str
    code: str | None = None
    field: str | None = None


class ResponseEnvelope(BaseModel, Generic[T]):
    success: bool = True
    message: str | None = None
    data: T | None = None
    errors: list[ErrorDetail] | None = None
    meta: dict[str, Any] | None = None
