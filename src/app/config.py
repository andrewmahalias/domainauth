from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Налаштування DNS-резолвера за замовчуванням
    dns_nameservers: list[str] = ["1.1.1.1", "8.8.8.8"]
    dns_timeout: float = 3.0

    model_config = SettingsConfigDict(
        env_prefix="DOMAINAUTH_",
        env_file=".env",
        extra="ignore",
    )


def get_settings() -> Settings:
    return Settings()