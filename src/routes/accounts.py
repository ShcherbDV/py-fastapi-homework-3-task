from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from jose import JWTError
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from config.settings import Settings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import BaseSecurityError, TokenExpiredError
from schemas import (
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
)
from schemas.accounts import (
    UserBase,
    PasswordResetCompleteRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password

router = APIRouter()


@router.post(
    "/register/", response_model=UserRegistrationResponseSchema, status_code=201
)
async def user_register(
    user: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
    auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    result = await db.execute(select(UserModel).where(UserModel.email == user.email))
    db_user = result.scalar_one_or_none()
    if db_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user.email} already exists.",
        )

    if len(user.password) < 8:
        raise HTTPException(
            status_code=422, detail="Password must contain at least 8 characters."
        )

    if not any(char.isupper() for char in user.password):
        raise HTTPException(
            status_code=422,
            detail="Password must contain at least one uppercase letter.",
        )

    if not any(char.isdigit() for char in user.password):
        raise HTTPException(
            status_code=422, detail="Password must contain at least one digit."
        )

    if not any(char.islower() for char in user.password):
        raise HTTPException(
            status_code=422, detail="Password must contain at least one lower letter."
        )

    if not any(
        char in ("@", "$", "!", "%", "*", "?", "#", "&") for char in user.password
    ):
        raise HTTPException(
            status_code=422,
            detail="Password must contain at least one special character: @, $, !, %, *, ?, #, &.",
        )

    try:
        hashed = hash_password(user.password)
        db_user = UserModel(
            email=user.email,
            _hashed_password=hashed,
            group_id=1,
        )
        jwt_token = auth_manager.create_access_token(
            {"user_id": db_user.id}, expires_delta=timedelta(days=1)
        )
        db_user.activation_token = ActivationTokenModel(
            user_id=db_user.id, token=jwt_token
        )
        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)
        return db_user
    except SQLAlchemyError:
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=MessageResponseSchema, status_code=200)
async def user_activate(
    user: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
    auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    result = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == user.email)
    )
    db_user = result.scalar_one_or_none()
    if db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    auth_manager.verify_access_token_or_raise(user.token)

    if (
        db_user.activation_token is None
        or user.token != db_user.activation_token.token
        or cast(datetime, db_user.activation_token.expires_at).replace(
            tzinfo=timezone.utc
        )
        < datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    db_user.is_active = True
    db_user.activation_token = None
    db_user.refresh_token = RefreshTokenModel()
    await db.commit()
    await db.refresh(db_user)
    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/", response_model=MessageResponseSchema, status_code=200
)
async def user_password_reset(user: UserBase, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == user.email))
    db_user = result.scalar_one_or_none()
    if not db_user or not db_user.is_active:
        return MessageResponseSchema(
            message="If you are registered, you will receive an email with instructions."
        )
    if db_user and db_user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == db_user.id
            )
        )

    new_token = PasswordResetTokenModel(user_id=cast(int, db_user.id))
    db.add(new_token)
    await db.commit()
    await db.refresh(new_token)

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/", response_model=MessageResponseSchema, status_code=200
)
async def user_password_reset_complete(
    user: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(UserModel).where(UserModel.email == user.email))
    db_user = result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    if not db_user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    result_token = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == db_user.id
        )
    )
    db_token = result_token.scalar_one_or_none()

    if not db_token:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    if db_token.token != user.token or db_token.expires_at.replace(
        tzinfo=timezone.utc
    ) < datetime.now(timezone.utc):
        await db.delete(db_token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        db_user.password = user.password
        await db.delete(db_token)
        await db.commit()
        await db.refresh(db_user)
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while resetting the password."
        )

    return MessageResponseSchema(message="Password reset successfully.")


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
async def login(
    user: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    result = await db.execute(select(UserModel).where(UserModel.email == user.email))
    db_user = result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not db_user.verify_password(user.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    access_token = jwt_manager.create_access_token(
        {"sub": str(db_user.id), "user_id": db_user.id}
    )
    refresh_token = jwt_manager.create_refresh_token(
        {"sub": str(db_user.id), "user_id": db_user.id}
    )

    try:
        refresh_token_record = RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )
        db.add(refresh_token_record)
        await db.commit()
        await db.refresh(refresh_token_record)
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while processing the request."
        )

    return UserLoginResponseSchema(
        access_token=access_token, refresh_token=refresh_token, token_type="bearer"
    )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=200)
async def refresh(
    payload: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    refresh_token = payload.refresh_token
    try:
        decoded_token = jwt_manager.decode_refresh_token(refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token.")

    user_id = decoded_token.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="Invalid token.")

    stmt = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == refresh_token)
    )
    token_db = stmt.scalars().first()

    if not token_db:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    stmt_user = await db.execute(select(UserModel).where(UserModel.id == user_id))
    db_user = stmt_user.scalars().first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token({"user_id": db_user.id})

    return TokenRefreshResponseSchema(access_token=access_token)
