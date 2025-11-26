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

    token_context = dict(context)
    token_context["ignore_auth"] = True
    token_context["user"] = user.get("name")
    token_context["auth_user"] = user.get("name")

    resolved_user_obj = user_obj
    if resolved_user_obj is None:
        model = context.get("model")
        if model is not None:
            # CKAN's User.get accepts name or id; try name first to avoid UUID lookups when unnecessary.
            resolved_user_obj = model.User.get(user.get("name"))
            if resolved_user_obj is None and user.get("id"):
                resolved_user_obj = model.User.get(user["id"])

    if resolved_user_obj is not None:
        token_context["auth_user_obj"] = resolved_user_obj
        token_context["user_obj"] = resolved_user_obj
    user["frontend_token"] = None

    get_action = toolkit.get_action

    log.info("Starting frontend token generation for user %s", user.get("name"))

    try:
        api_tokens = get_action("api_token_list")(
            token_context, {"user_id": user["name"]}
        )

        log.info(
            "Found %d existing tokens for user %s", len(api_tokens), user.get("name")
        )

        for token in api_tokens:
            if token.get("name") == "frontend_token":
                log.info("Revoking existing frontend_token with id %s", token["id"])
                get_action("api_token_revoke")(token_context, {"jti": token["id"]})

        log.info("Creating new frontend_token for user %s", user.get("name"))
        frontend_token = get_action("api_token_create")(
            token_context, {"user": user["name"], "name": "frontend_token"}
        )
        user["frontend_token"] = frontend_token.get("token")
        log.info("Frontend token successfully created for user %s", user.get("name"))
    except Exception:
        log.exception("Failed to refresh frontend token for user %s", user.get("name"))

    return user
