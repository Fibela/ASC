# Vercel ASGI entrypoint — imports the FastAPI app so Vercel can serve it.
# Vercel's @vercel/python runtime detects the `app` name and serves it as ASGI.
from app.main import app  # noqa: F401
