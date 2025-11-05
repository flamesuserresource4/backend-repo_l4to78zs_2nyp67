from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="BCrypt password hash")
    admin: bool = Field(False, description="Admin role flag")

class Post(BaseModel):
    title: str = Field(..., description="Post title")
    content: str = Field(..., description="Post content")
    status: Literal['Draft','Published'] = Field('Draft', description="Publication status")
    user_id: str = Field(..., description="Owner user id")
    author_name: Optional[str] = Field(None, description="Owner display name")
