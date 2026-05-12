import re
import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, field_validator


class ContactCreate(BaseModel):
    full_name: str
    email: EmailStr
    phone: str | None = None
    message: str

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v):
        if v is None:
            return v
        pattern = r"^\+?[0-9]\d{6,14}$"
        if not re.match(pattern, v.replace(" ", "").replace("-", "")):
            raise ValueError("Invalid phone number format.")
        return v

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v):
        if len(v.strip()) < 2:
            raise ValueError("Full name must be at least 2 characters.")
        return v.strip()

    @field_validator("message")
    @classmethod
    def validate_message(cls, v):
        if len(v.strip()) < 10:
            raise ValueError("Message must be at least 10 characters.")
        return v.strip()


class ContactResponse(BaseModel):
    id: uuid.UUID
    full_name: str
    email: str
    phone: Optional[str]
    message: str
    created_at: datetime

    model_config = {"from_attributes": True}
