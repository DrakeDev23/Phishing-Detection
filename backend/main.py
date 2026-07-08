from fastapi import FastAPI
from middleware import setup_middleware
from routes import setup_routes


def create_app():
    app = FastAPI(
        title="Link Checker API",
        description="Comprehensive phishing and malicious URL detection service",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
    )

    limiter = setup_middleware(app)
    setup_routes(app, limiter)
    return app


app = create_app()
