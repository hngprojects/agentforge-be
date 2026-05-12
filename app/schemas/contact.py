from pydantic import BaseModel, EmailStr, Field


class ContactCreate(BaseModel):
    fullname: str = Field(min_length=2, max_length=255)
    email: EmailStr
    phone_number: str = Field(min_length=7, max_length=30)
    message: str = Field(min_length=10)


class ContactResponse(BaseModel):
    success: str
    message: str
