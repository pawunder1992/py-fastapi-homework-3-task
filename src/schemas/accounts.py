from pydantic import BaseModel, EmailStr, ConfigDict


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str
    model_config = ConfigDict(from_attributes=True)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: str
    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(UserActivationRequestSchema):
    password: str


class UserLoginRequestSchema(UserRegistrationRequestSchema):
    pass


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str
