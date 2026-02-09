from flask import Blueprint

rp_bp = Blueprint("rp", __name__)

from . import routes  # noqa: E402,F401
