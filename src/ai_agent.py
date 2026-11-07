import json
import logging
from typing import Dict, Any
from openai import OpenAI, APIError, APITimeoutError, RateLimitError

from src.config import settings

logger = logging.getLogger(__name__)

class ThreatIntelAgent:
    """
    Agente de IA encargado de redactar el informe técnico de seguridad.
    REGLA DE ORO: La IA NO analiza los logs crudos. Solo redacta sobre
    los hallazgos que el código Python ya ha identificado.
    """

    def __init__(self):
        # Cliente apuntando a OpenRouter
        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=settings.openrouter_api_key,
            default_headers={
                "HTTP-Referer": "https://siem-ai-analyzer.local",
                "X-Title": "SIEM AI Analyzer",
            },
        )
        self.model = settings.ai_model

        self.system_prompt = (
            "Eres un Analista Senior de SOC (Security Operations Center).\n"
            "Tu tarea es redactar un informe técnico basándote ÚNICAMENTE en los hallazgos JSON proporcionados.\n\n"
            "REGLAS:\n"
            "1. NO inventes datos. Usa solo la evidencia.\n"
            "2. Si detectas múltiples hallazgos (ej. Fuerza bruta + Comandos sospechosos + Exfiltración), "
            "conéctalos lógicamente en el resumen ejecutivo. Describe la cadena de ataque (Kill Chain).\n"
            "3. El plan de acción debe ser específico: bloquear IPs, aislar servidores comprometidos, "
            "revocar sesiones de usuarios comprometidos, etc.\n"
            "4. Devuelve un JSON estricto con las claves: executive_summary, technical_explanation, "
            "impact, action_plan, recommendations.\n"
        )

    def generate_report_content(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        if not parsed_data.get("is_compromised"):
            logger.info("No se detectaron hallazgos. Se omite la llamada a la IA.")
            return self._clean_report()

        user_prompt = self._build_user_prompt(parsed_data)

        # --- LÓGICA DE REINTENTO SENIOR ---
        max_retries = 2
        for attempt in range(max_retries):
            try:
                logger.info(f"Consultando IA (Intento {attempt + 1}/{max_retries}) con modelo: {self.model}")
                response = self.client.chat.completions.create(
                    model=self.model,
                    response_format={"type": "json_object"},
                    temperature=0.1,
                    max_tokens=2500,
                    messages=[
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                )
                
                # Validación contra respuestas nulas o vacías
                if not response.choices or not response.choices[0].message.content:
                    logger.warning(f"Intento {attempt + 1}: La IA devolvió contenido vacío. Reintentando...")
                    continue  # Fuerza el siguiente intento del bucle
                    
                raw_content = response.choices[0].message.content
                logger.info("Respuesta de la IA recibida correctamente.")
                return self._parse_and_validate(raw_content)

            except RateLimitError as e:
                logger.error(f"Límite de peticiones alcanzado en OpenRouter: {e}")
                if attempt == max_retries - 1:
                    return self._fallback_report("Se alcanzó el límite de peticiones de la IA. Inténtalo de nuevo en unos minutos.")
            except APITimeoutError as e:
                logger.error(f"Timeout al conectar con OpenRouter: {e}")
                if attempt == max_retries - 1:
                    return self._fallback_report("La IA no respondió a tiempo. Inténtalo de nuevo.")
            except APIError as e:
                logger.error(f"Error de API de OpenRouter: {e}")
                if attempt == max_retries - 1:
                    return self._fallback_report(f"Error en el proveedor de IA: {e}")
            except json.JSONDecodeError as e:
                logger.error(f"La IA no devolvió un JSON válido: {e}")
                if attempt == max_retries - 1:
                    return self._fallback_report("La IA devolvió un formato inválido. Inténtalo de nuevo.")
            except Exception as e:
                logger.exception(f"Error inesperado en el agente de IA: {e}")
                return self._fallback_report(f"Error inesperado: {e}")

        # Si el bucle termina sin éxito
        return self._fallback_report("La IA devolvió contenido vacío tras varios intentos. Prueba con otro modelo o revisa el prompt.")

    def _build_user_prompt(self, parsed_data: Dict[str, Any]) -> str:
        findings_for_prompt = []
        for f in parsed_data["findings"]:
            findings_for_prompt.append({
                "type": f["type"],
                "severity": f["severity"],
                "evidence": f["evidence"],
                "justification": f["justification"],
                "affected_records": f["affected_records"],
                "raw_data_sample": f["raw_data"][:5],
            })

        payload = {
            "total_logs_analyzed": parsed_data["total_logs_analyzed"],
            "summary": parsed_data["summary"],
            "findings": findings_for_prompt,
        }

        # --- PROMPT REFORZADO PARA DEEPSEEK ---
        return (
            "Analiza los siguientes hallazgos de seguridad y genera un informe técnico.\n\n"
            f"DATOS:\n{json.dumps(payload, indent=2, default=str)}\n\n"
            "INSTRUCCIÓN CRÍTICA: Devuelve ÚNICAMENTE un objeto JSON válido. "
            "No incluyas texto adicional, explicaciones, ni bloques de código markdown. "
            "El JSON debe tener EXACTAMENTE las siguientes claves (todas en español):\n"
            "- \"executive_summary\": Resumen ejecutivo para la dirección (2-4 frases).\n"
            "- \"technical_explanation\": Explicación técnica de cada hallazgo.\n"
            "- \"impact\": Posible impacto en la organización.\n"
            "- \"action_plan\": Plan de acción (investigar, contener y remediar).\n"
            "- \"recommendations\": Recomendaciones generales de seguridad.\n\n"
            "EJEMPLO DE FORMATO DE SALIDA:\n"
            "{\n"
            "  \"executive_summary\": \"Se detectaron...\",\n"
            "  \"technical_explanation\": \"Los logs muestran...\",\n"
            "  \"impact\": \"El impacto potencial es...\",\n"
            "  \"action_plan\": \"1. Investigar... 2. Contener... 3. Remediar...\",\n"
            "  \"recommendations\": \"Se recomienda implementar MFA...\"\n"
            "}"
        )

    def _parse_and_validate(self, raw_content: str) -> Dict[str, Any]:
        try:
            content = json.loads(raw_content)
        except json.JSONDecodeError:
            cleaned = raw_content.strip().strip("`").replace("json\n", "", 1)
            content = json.loads(cleaned)

        required_keys = [
            "executive_summary", "technical_explanation", "impact", "action_plan", "recommendations"
        ]
        for key in required_keys:
            if key not in content or not str(content[key]).strip():
                logger.warning(f"Falta la clave '{key}' en la respuesta de la IA. Usando valor por defecto.")
                content[key] = "No disponible."

        return content

    def _fallback_report(self, error_message: str) -> Dict[str, Any]:
        return {
            "executive_summary": f"No se pudo generar el resumen ejecutivo automáticamente. Motivo: {error_message}",
            "technical_explanation": "El análisis técnico no está disponible debido a un error en el motor de IA.",
            "impact": "Desconocido. Revisar los hallazgos manualmente.",
            "action_plan": "1. Revisar el Excel manualmente. 2. Reintentar la generación del informe. 3. Escalar al equipo de seguridad.",
            "recommendations": "Revisar la configuración de la API Key de OpenRouter y el estado del servicio.",
        }

    def _clean_report(self) -> Dict[str, Any]:
        return {
            "executive_summary": "No se detectaron indicadores de compromiso en los logs analizados. El sistema se encuentra en estado normal.",
            "technical_explanation": "Las reglas de detección no arrojaron coincidencias.",
            "impact": "Ninguno. No hay evidencia de actividad maliciosa.",
            "action_plan": "1. Mantener la monitorización continua. 2. Revisar periódicamente las reglas de detección. 3. Conservar los logs para auditorías futuras.",
            "recommendations": "Continuar con las buenas prácticas de seguridad: actualizaciones, MFA y segmentación de red.",
        }