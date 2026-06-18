import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "Browser Scam Detection API"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Database configuration
    DATABASE_URL: str = "sqlite:///./scam_detection.db"
    
    # Third-party APIs (Optional)
    VIRUSTOTAL_API_KEY: str = ""
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    
    # Model configs
    MODEL_PATH: str = "app/ml/model.joblib"
    VECTORIZER_PATH: str = "app/ml/vectorizer.joblib"
    
    # CORS
    BACKEND_CORS_ORIGINS: list[str] = ["*"]
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
