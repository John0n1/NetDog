from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Application
    app_name: str = "NetDog"
    version: str = "1.0.0"
    environment: str = "development"
    
    # Database
    database_url: str = "postgresql://netdog:netdog@localhost:5432/netdog"
    
    # Redis
    redis_url: str = "redis://localhost:6379/0"
    
    # Security
    secret_key: str = "dev-secret-key-change-in-production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # API Keys
    nvd_api_key: str | None = None
    vulners_api_key: str | None = None
    
    # Celery (will use redis_url if not explicitly set)
    celery_broker_url: str | None = None
    celery_result_backend: str | None = None
    
    # Cache TTL (seconds)
    cve_cache_ttl: int = 86400  # 24 hours
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Use redis_url for celery if not explicitly set
        if self.celery_broker_url is None:
            self.celery_broker_url = self.redis_url
        if self.celery_result_backend is None:
            self.celery_result_backend = self.redis_url
    
    # Rate limiting
    rate_limit_per_minute: int = 60
    
    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    return Settings()
