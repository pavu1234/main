from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_env: str = "development"
    database_url: str = "sqlite:///./webguard.db"
    max_scan_pages: int = 100
    default_scan_pages: int = 25
    max_crawl_depth: int = 4
    request_timeout: float = 10.0
    max_concurrent_requests: int = 5
    max_response_bytes: int = 5 * 1024 * 1024
    max_js_bytes: int = 2 * 1024 * 1024
    max_redirects: int = 5
    request_delay_ms: int = 250
    frontend_origin: str = "http://localhost:5173"
    demo_lab_url: str = "http://security-lab:9000"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
