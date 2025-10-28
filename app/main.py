from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from app.api.router import router
from app.ui.templates import home_html

app = FastAPI(title="Detector de Phishing (MVP)")
app.include_router(router)

@app.get("/", response_class=HTMLResponse)
async def home():
    return home_html()