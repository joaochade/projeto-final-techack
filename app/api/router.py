from fastapi import APIRouter
from pydantic import BaseModel, HttpUrl, ValidationError
from app.services.url_heuristics import normalize_url, url_features, heuristic_score
from app.core.scoring import label_from_score

router = APIRouter()

class AnalyzeRequest(BaseModel):
    url: str

@router.post("/analyze")
async def analyze(payload: AnalyzeRequest):
    url = normalize_url(payload.url)
    feat = url_features(url)
    base_score, ev = heuristic_score(feat)

    # MVP: sem chamadas externas ainda (blacklists/WHOIS/SSL) — entram depois
    result = {
        "normalized_url": url,
        "features": feat,
        "score": base_score,
        "label": label_from_score(base_score),
        "evidence": ev,
        "checks": ["heuristics:url"],
    }
    return result