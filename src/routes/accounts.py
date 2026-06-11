import string
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession


from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)

from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()


def validate_password(password: str) -> str:
    if len(password) < 8:
        raise ValueError("Password must contain at least 8 characters.")
    if not any(char in string.ascii_lowercase for char in password):
        raise ValueError("Password must contain at least one lower letter.")
    if not any(char in string.ascii_uppercase for char in password):
        raise ValueError(
            "Password must contain at least one uppercase letter."
        )
    if not any(char in string.digits for char in password):
        raise ValueError("Password must contain at least one digit.")
    if not any(char in string.punctuation for char in password):
        raise ValueError(
            "Password must contain at least one special character: @, $, !, %, *, ?, #, &."
        )
    return password


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(
        select(UserModel).where(UserModel.email == email)
    )
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, id: int):
    result = await db.execute(select(UserModel).where(UserModel.id == id))
    return result.scalar_one_or_none()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=201,
)
async def register(
    user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    db_user = await get_user_by_email(db, user.email)
    group = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    group = group.scalar_one_or_none()

    if db_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user.email} already exists.",
        )
    try:
        valid_password = validate_password(user.password)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    try:

        new_user = UserModel.create(
            user.email, validate_password(valid_password), group.id
        )
        await db.flush()
        user_activate_token = ActivationTokenModel(user=new_user)
        db.add(new_user)
        db.add(user_activate_token)
        await db.commit()
        await db.refresh(new_user)
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )
    return new_user


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate(
    user: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    db_user = await get_user_by_email(db, user.email)
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if db_user.is_active:
        raise HTTPException(
            status_code=400, detail="User account is already active."
        )

    activation_token = await db.scalar(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == db_user.id
        )
    )

    if (
        not activation_token
        or user.token != activation_token.token
        or activation_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    db_user.is_active = True
    db.add(db_user)
    await db.delete(activation_token)
    await db.commit()
    await db.refresh(db_user)

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def reset_password_request(
    user: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):
    db_user = await get_user_by_email(db, user.email)
    if db_user and db_user.is_active:
        reset_token = await db.scalar(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == db_user.id
            )
        )
        if reset_token:
            await db.delete(reset_token)
        new_reset_token = PasswordResetTokenModel(user=db_user)
        db.add(new_reset_token)
        await db.commit()
        await db.refresh(new_reset_token)
    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def reset_password_complete(
    user: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    db_user = await get_user_by_email(db, user.email)
    if not db_user or not db_user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    reset_token = await db.scalar(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == db_user.id
        )
    )

    if not reset_token:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    if (
        user.token != reset_token.token
        or reset_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
    ):
        try:
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.id == reset_token.id
                )
            )
            await db.commit()
        except SQLAlchemyError:
            await db.rollback()
            raise HTTPException(
                status_code=500,
                detail="An error occurred while resetting the password.",
            )

        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        validate_password(user.password)
        db_user._hashed_password = hash_password(user.password)
        db.add(db_user)

        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.id == reset_token.id
            )
        )

        await db.commit()
        await db.refresh(db_user)

    except ValueError as ve:
        await db.rollback()
        raise HTTPException(status_code=400, detail=str(ve))
    except (SQLAlchemyError, Exception):
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password.",
        )

    return {"message": "Password reset successfully."}


@router.post("/login/", status_code=status.HTTP_201_CREATED)
async def login(
    user: UserLoginRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    db: AsyncSession = Depends(get_db),
    settings: BaseAppSettings = Depends(get_settings),
):
    db_user = await get_user_by_email(db, user.email)
    if not db_user or not db_user.verify_password(user.password):
        raise HTTPException(
            status_code=401, detail="Invalid email or password."
        )
    if not db_user.is_active:
        raise HTTPException(
            status_code=403, detail="User account is not activated."
        )

    token_payload = {"user_id": db_user.id}
    access_token = jwt_manager.create_access_token(data=token_payload)
    refresh_token = jwt_manager.create_refresh_token(data=token_payload)

    try:
        await db.execute(
            delete(RefreshTokenModel).where(
                RefreshTokenModel.user_id == db_user.id
            )
        )

        new_db_token = RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )
        db.add(new_db_token)

        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/refresh/", status_code=status.HTTP_200_OK)
async def refresh_access_token(
    user_token: TokenRefreshRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    db: AsyncSession = Depends(get_db),
):
    try:
        token_data = jwt_manager.decode_refresh_token(user_token.refresh_token)
    except Exception:
        refresh_token_in_db = await db.scalar(
            select(RefreshTokenModel).where(
                RefreshTokenModel.token == user_token.refresh_token
            )
        )
        if refresh_token_in_db:
            await db.execute(
                delete(RefreshTokenModel).where(
                    RefreshTokenModel.id == refresh_token_in_db.id
                )
            )
            await db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    refresh_token = await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == user_token.refresh_token
        )
    )

    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_id = token_data.get("user_id")

    db_user = await get_user_by_id(db, user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found.")

    if not db_user.is_active:
        raise HTTPException(status_code=401, detail="Invalid refresh token.")

    access_token = jwt_manager.create_access_token(
        data={"user_id": db_user.id}
    )
    return {"access_token": access_token}
