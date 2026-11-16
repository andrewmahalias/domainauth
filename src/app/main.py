from fastapi import FastAPI
from app.routers import router


def create_app() -> FastAPI:
    app = FastAPI(
        title="Domain Authentication API",
        version="0.1.0",
        description="Async SPF/DKIM/DMARC verification API",
    )
    app.include_router(router)
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)