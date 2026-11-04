from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # Variables de OpenRouter
    openrouter_api_key: str = ""
    
    # Variable que faltaba: el modelo de IA a usar
    ai_model: str = "deepseek/deepseek-v4-flash" 
    
    # Proveedor por defecto
    default_ai_provider: str = "openrouter"

    # Configuración para leer el archivo .env
    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8",
        extra="ignore" # <-- OPCIONAL: Esto evita errores si añades variables extra al .env en el futuro
    )

settings = Settings()