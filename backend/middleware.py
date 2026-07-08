from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from config import ALLOWED_ORIGINS, ALLOWED_HOSTS, DEFAULT_RATE_LIMIT


def setup_middleware(app):
    limiter = Limiter(key_func=get_remote_address, default_limits=[DEFAULT_RATE_LIMIT])
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=False,
        allow_methods=["POST", "GET"],
        allow_headers=["Content-Type"],
    )

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

    return limiter
