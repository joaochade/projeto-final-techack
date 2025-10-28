from pydantic import BaseModel
from dotenv import load_dotenv
import os

load_dotenv()

class Settings(BaseModel):
    env: str = os.getenv("ENV", "dev")
    gsb_api_key: str | None = os.getenv("GSB_API_KEY")
    openphish_url: str = os.getenv("OPENPHISH_URL", "https://openphish.com/feed.txt")

settings = Settings()