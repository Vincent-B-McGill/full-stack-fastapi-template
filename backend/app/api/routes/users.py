import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, col, delete, func, select

from app import crud
from app.api.deps import (
    CurrentUser,
    SessionDep,
    get_current_active_superuser,
)
from app.core.config import settings
from app.core.security import get_password_hash, verify_password
from app.models import (
    Item,
    Message,
    UpdatePassword,
    User,
    UserCreate,
    UserPublic,
    UserRegister,
    UsersPublic,
    UserUpdate,
    UserUpdateMe,
)
from app.utils import generate_new_account_email, send_email

router = APIRouter(prefix="/users", tags=["users"])


def _get_user_or_404(*, session: Session, user_id: uuid.UUID) -> User:
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=404,
            detail="The user with this id does not exist in the system",
        )
    return user


def _is_last_active_superuser(*, session: Session, user: User) -> bool:
    if not user.is_superuser or not user.is_active:
        return False

    active_superusers_statement = select(func.count()).where(
        User.is_superuser,
        User.is_active,
    )
    active_superusers_count = session.exec(active_superusers_statement).one()
    return active_superusers_count == 1


def _ensure_user_can_change_active_status(
    *,
    session: Session,
    current_user: User,
    user: User,
    is_active: bool,
) -> None:
    if user == current_user and is_active is False:
        raise HTTPException(
            status_code=403,
            detail="Super users are not allowed to deactivate themselves",
        )
    if is_active is False and _is_last_active_superuser(session=session, user=user):
        raise HTTPException(
            status_code=403,
            detail="The last active superuser cannot be deactivated",
        )


def _set_user_active_status(
    *,
    session: Session,
    current_user: User,
    user: User,
    is_active: bool,
) -> User:
    _ensure_user_can_change_active_status(
        session=session,
        current_user=current_user,
        user=user,
        is_active=is_active,
    )

    if user.is_active == is_active:
        status_message = "active" if is_active else "inactive"
        raise HTTPException(
            status_code=409,
            detail=f"User is already {status_message}",
        )

    user_update = UserUpdate(is_active=is_active)
    return crud.update_user(session=session, db_user=user, user_in=user_update)


@router.get(
    "/",
    dependencies=[Depends(get_current_active_superuser)],
    response_model=UsersPublic,
)
def read_users(session: SessionDep, skip: int = 0, limit: int = 100) -> Any:
    """
    Retrieve users.
    """

    count_statement = select(func.count()).select_from(User)
    count = session.exec(count_statement).one()

    statement = (
        select(User).order_by(col(User.created_at).desc()).offset(skip).limit(limit)
    )
    users = session.exec(statement).all()

    users_public = [UserPublic.model_validate(user) for user in users]
    return UsersPublic(data=users_public, count=count)


@router.post(
    "/", dependencies=[Depends(get_current_active_superuser)], response_model=UserPublic
)
def create_user(*, session: SessionDep, user_in: UserCreate) -> Any:
    """
    Create new user.
    """
    user = crud.get_user_by_email(session=session, email=user_in.email)
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this email already exists in the system.",
        )

    user = crud.create_user(session=session, user_create=user_in)
    if settings.emails_enabled and user_in.email:
        email_data = generate_new_account_email(
            email_to=user_in.email, username=user_in.email, password=user_in.password
        )
        send_email(
            email_to=user_in.email,
            subject=email_data.subject,
            html_content=email_data.html_content,
        )
    return user


@router.patch("/me", response_model=UserPublic)
def update_user_me(
    *, session: SessionDep, user_in: UserUpdateMe, current_user: CurrentUser
) -> Any:
    """
    Update own user.
    """

    if user_in.email:
        existing_user = crud.get_user_by_email(session=session, email=user_in.email)
        if existing_user and existing_user.id != current_user.id:
            raise HTTPException(
                status_code=409, detail="User with this email already exists"
            )
    user_data = user_in.model_dump(exclude_unset=True)
    current_user.sqlmodel_update(user_data)
    session.add(current_user)
    session.commit()
    session.refresh(current_user)
    return current_user


@router.patch("/me/password", response_model=Message)
def update_password_me(
    *, session: SessionDep, body: UpdatePassword, current_user: CurrentUser
) -> Any:
    """
    Update own password.
    """
    verified, _ = verify_password(body.current_password, current_user.hashed_password)
    if not verified:
        raise HTTPException(status_code=400, detail="Incorrect password")
    if body.current_password == body.new_password:
        raise HTTPException(
            status_code=400, detail="New password cannot be the same as the current one"
        )
    hashed_password = get_password_hash(body.new_password)
    current_user.hashed_password = hashed_password
    session.add(current_user)
    session.commit()
    return Message(message="Password updated successfully")


@router.get("/me", response_model=UserPublic)
def read_user_me(current_user: CurrentUser) -> Any:
    """
    Get current user.
    """
    return current_user


@router.delete("/me", response_model=Message)
def delete_user_me(session: SessionDep, current_user: CurrentUser) -> Any:
    """
    Delete own user.
    """
    if current_user.is_superuser:
        raise HTTPException(
            status_code=403, detail="Super users are not allowed to delete themselves"
        )
    session.delete(current_user)
    session.commit()
    return Message(message="User deleted successfully")


@router.post("/signup", response_model=UserPublic)
def register_user(session: SessionDep, user_in: UserRegister) -> Any:
    """
    Create new user without the need to be logged in.
    """
    user = crud.get_user_by_email(session=session, email=user_in.email)
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this email already exists in the system",
        )
    user_create = UserCreate.model_validate(user_in)
    user = crud.create_user(session=session, user_create=user_create)
    return user


@router.get("/{user_id}", response_model=UserPublic)
def read_user_by_id(
    user_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> Any:
    """
    Get a specific user by id.
    """
    user = session.get(User, user_id)
    if user == current_user:
        return user
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=403,
            detail="The user doesn't have enough privileges",
        )
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.patch(
    "/{user_id}",
    dependencies=[Depends(get_current_active_superuser)],
    response_model=UserPublic,
)
def update_user(
    *,
    session: SessionDep,
    current_user: CurrentUser,
    user_id: uuid.UUID,
    user_in: UserUpdate,
) -> Any:
    """
    Update a user.
    """

    db_user = _get_user_or_404(session=session, user_id=user_id)
    is_deactivating_last_active_superuser = (
        user_in.is_active is False and _is_last_active_superuser(session=session, user=db_user)
    )
    is_demoting_last_active_superuser = (
        user_in.is_superuser is False
        and db_user.is_superuser
        and db_user.is_active
        and _is_last_active_superuser(session=session, user=db_user)
    )
    if user_in.is_active is False:
        _ensure_user_can_change_active_status(
            session=session,
            current_user=current_user,
            user=db_user,
            is_active=False,
        )
    if is_demoting_last_active_superuser:
        raise HTTPException(
            status_code=403,
            detail="The last active superuser cannot lose superuser privileges",
        )
    if user_in.email:
        existing_user = crud.get_user_by_email(session=session, email=user_in.email)
        if existing_user and existing_user.id != user_id:
            raise HTTPException(
                status_code=409, detail="User with this email already exists"
            )

    db_user = crud.update_user(session=session, db_user=db_user, user_in=user_in)
    return db_user


@router.post(
    "/{user_id}/deactivate",
    dependencies=[Depends(get_current_active_superuser)],
    response_model=UserPublic,
)
def deactivate_user(
    session: SessionDep, current_user: CurrentUser, user_id: uuid.UUID
) -> Any:
    """
    Deactivate a user.
    """
    user = _get_user_or_404(session=session, user_id=user_id)
    return _set_user_active_status(
        session=session,
        current_user=current_user,
        user=user,
        is_active=False,
    )


@router.post(
    "/{user_id}/activate",
    dependencies=[Depends(get_current_active_superuser)],
    response_model=UserPublic,
)
def activate_user(
    session: SessionDep, current_user: CurrentUser, user_id: uuid.UUID
) -> Any:
    """
    Reactivate a user.
    """
    user = _get_user_or_404(session=session, user_id=user_id)
    return _set_user_active_status(
        session=session,
        current_user=current_user,
        user=user,
        is_active=True,
    )


@router.delete("/{user_id}", dependencies=[Depends(get_current_active_superuser)])
def delete_user(
    session: SessionDep, current_user: CurrentUser, user_id: uuid.UUID
) -> Message:
    """
    Delete a user.
    """
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user == current_user:
        raise HTTPException(
            status_code=403, detail="Super users are not allowed to delete themselves"
        )
    if _is_last_active_superuser(session=session, user=user):
        raise HTTPException(
            status_code=403,
            detail="The last active superuser cannot be deleted",
        )
    statement = delete(Item).where(col(Item.owner_id) == user_id)
    session.exec(statement)
    session.delete(user)
    session.commit()
    return Message(message="User deleted successfully")
