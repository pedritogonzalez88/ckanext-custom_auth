import logging
from typing import Any, Dict

import ckan.lib.authenticator as authenticator
from ckan.common import _, config
from ckan.plugins import toolkit


log = logging.getLogger(__name__)


def user_login(context: Dict[str, Any], data_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Authenticate a CKAN user and optionally attach a frontend token."""

    def _generic_login_error() -> Dict[str, Any]:
        return {
            "errors": {"auth": [_("Username or password entered was incorrect")]},
            "error_summary": {_("auth"): _("Incorrect username or password")},
        }

    try:
        session = context["session"]
        model = context["model"]
    except KeyError as missing_key:
        log.error("Missing key %s in login context", missing_key)
        return _generic_login_error()

    identifier = (data_dict.get("id") or "").strip()
    password = data_dict.get("password")
    if not identifier or not password:
        return _generic_login_error()

    # Support login via username or email.
    user_obj = None
    if "@" in identifier:
        user_obj = (
            session.query(model.User).filter(model.User.email == identifier).first()
        )
    else:
        user_obj = model.User.get(identifier)

    if not user_obj:
        return _generic_login_error()

    user_dict = user_obj.as_dict()

    identity = {"login": user_dict["name"], "password": password}

    try:
        auth_user = authenticator.default_authenticate(identity)
    except Exception:
        log.exception(
            "Authentication backend failed for user %s", user_dict.get("name")
        )
        return _generic_login_error()

    if not auth_user:
        return _generic_login_error()

    resolved_user = model.User.get(auth_user.id)
    if not resolved_user or resolved_user.name != user_dict["name"]:
        return _generic_login_error()

    # Refresh user_dict with resolved_user to ensure we have the most recent data
    user_dict = resolved_user.as_dict()

    if config.get("ckanext.auth.include_frontend_login_token", False):
        log.info("Frontend token generation enabled for user %s", user_dict.get("name"))
        user_dict = generate_token(context, user_dict, user_obj=resolved_user)
    else:
        log.info("Frontend token generation disabled in config")

    return user_dict


def generate_token(
    context: Dict[str, Any], user: Dict[str, Any], *, user_obj: Any | None = None
) -> Dict[str, Any]:
    """Attach (and refresh) a frontend API token for the authenticated user."""

    user["frontend_token"] = None

    # Get fresh user object if not provided
    resolved_user_obj = user_obj
    if resolved_user_obj is None:
        model = context.get("model")
        if model is not None:
            resolved_user_obj = model.User.get(user.get("name"))
            if resolved_user_obj is None and user.get("id"):
                resolved_user_obj = model.User.get(user["id"])

    if resolved_user_obj is None:
        log.error(
            "Cannot generate token: user object not found for %s", user.get("name")
        )
        return user

    # Build a fresh context with explicit user authorization
    token_context = {
        "model": context.get("model"),
        "session": context.get("session"),
        "user": resolved_user_obj.name,
        "auth_user_obj": resolved_user_obj,
        "ignore_auth": True,
    }

    get_action = toolkit.get_action

    log.info("Starting frontend token generation for user %s", resolved_user_obj.name)

    try:
        # List existing tokens
        api_tokens = get_action("api_token_list")(
            token_context, {"user": resolved_user_obj.name}
        )

        log.info(
            "Found %d existing tokens for user %s",
            len(api_tokens),
            resolved_user_obj.name,
        )

        # Revoke any existing frontend_token
        for token in api_tokens:
            if token.get("name") == "frontend_token":
                log.info("Revoking existing frontend_token with id %s", token["id"])
                get_action("api_token_revoke")(token_context, {"jti": token["id"]})

        # Create new token
        log.info("Creating new frontend_token for user %s", resolved_user_obj.name)
        frontend_token = get_action("api_token_create")(
            token_context, {"user": resolved_user_obj.name, "name": "frontend_token"}
        )
        user["frontend_token"] = frontend_token.get("token")
        log.info(
            "Frontend token successfully created for user %s", resolved_user_obj.name
        )
    except Exception as e:
        log.exception(
            "Failed to refresh frontend token for user %s: %s",
            resolved_user_obj.name,
            str(e),
        )

    return user
