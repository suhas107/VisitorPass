from functools import wraps
from flask import abort
from flask_login import current_user

permissions = {
    "RESIDENT": {
        "PASS": ["create", "read_own", "revoke_own"],
        "ENTRY_LOG": ["read_own"],
        "RESIDENT_DIRECTORY": ["read_self"],
    },
    "GUARD": {
        "PASS": ["validate", "read_minimal"],
        "ENTRY_LOG": ["create", "read_own"],
        "RESIDENT_DIRECTORY": ["read_all"],
    },
    "ADMIN": {
        "PASS": ["read_all", "revoke_all"],
        "ENTRY_LOG": ["read_all"],
        "RESIDENT_DIRECTORY": ["read_all"],
        "USER": ["manage"],
    },
}


def require_permission(object_type, action, owner_getter=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            allowed_actions = permissions.get(current_user.role, {}).get(object_type, [])
            if action not in allowed_actions:
                abort(403)
            if owner_getter:
                owner_id = owner_getter(*args, **kwargs)
                if owner_id is not None and owner_id != current_user.id and not action.endswith("_all"):
                    abort(403)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def can(current_role, object_type, action):
    return action in permissions.get(current_role, {}).get(object_type, [])
