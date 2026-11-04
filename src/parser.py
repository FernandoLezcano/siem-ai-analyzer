import pandas as pd
import re
from typing import Dict, Any, List
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)

class LogParser:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.df: pd.DataFrame = pd.DataFrame()
        
        # --- Reglas de detección (Configurables) ---
        self.suspicious_commands = re.compile(
            r'(mimikatz|nc\s+-e|powershell\s+-enc|vssadmin\s+delete|certutil\s+-urlcache|net\s+user\s+.*\s+/add)',
            re.IGNORECASE
        )
        self.brute_force_threshold = 5
        self.lateral_movement_window_min = 10
        self.lateral_movement_threshold = 3
        self.privilege_escalation_ids = [4672, 4728, 4732, 4756]  # Windows Event IDs
        self.failed_logon_id = 4625
        self.success_logon_id = 4624

    # ---------- Carga y normalización ----------
    def load_and_normalize(self) -> None:
        try:
            self.df = pd.read_excel(self.file_path)
            self.df.columns = [col.strip().lower() for col in self.df.columns]
            if 'timestamp' in self.df.columns:
                self.df['timestamp'] = pd.to_datetime(self.df['timestamp'], errors='coerce')
            logger.info(f"Datos cargados: {len(self.df)} registros.")
        except Exception as e:
            logger.error(f"Error cargando Excel: {e}")
            raise ValueError(f"Archivo inválido: {e}")

    # ---------- Utilidad interna ----------
    def _build_finding(self, tipo: str, severidad: str, evidencia: str, raw: pd.DataFrame, justificacion: str) -> Dict[str, Any]:
        return {
            "type": tipo,
            "severity": severidad,
            "evidence": evidencia,
            "justification": justificacion,
            "raw_data": raw.head(20).to_dict(orient='records'),
            "affected_records": len(raw)
        }

    # ---------- 1. Fuerza Bruta ----------
    def detect_brute_force(self) -> List[Dict[str, Any]]:
        findings = []
        if not {'source_ip', 'event_id'}.issubset(self.df.columns):
            return findings
        failed = self.df[self.df['event_id'] == self.failed_logon_id]
        grouped = failed.groupby('source_ip').size().reset_index(name='count')
        for _, row in grouped[grouped['count'] >= self.brute_force_threshold].iterrows():
            severity = "Crítico" if row['count'] >= 20 else "Alto"
            findings.append(self._build_finding(
                tipo="Fuerza Bruta",
                severidad=severity,
                evidencia=f"IP {row['source_ip']} con {row['count']} intentos fallidos.",
                raw=failed[failed['source_ip'] == row['source_ip']],
                justificacion=f"Se superó el umbral de {self.brute_force_threshold} intentos fallidos desde una única IP, patrón típico de ataque de diccionario."
            ))
        return findings

    # ---------- 2. Inicios Sospechosos (horario/patrón) ----------
    def detect_suspicious_logons(self) -> List[Dict[str, Any]]:
        findings = []
        if 'timestamp' not in self.df.columns:
            return findings
        successes = self.df[self.df.get('event_id') == self.success_logon_id].copy()
        if successes.empty:
            return findings
        successes['hour'] = successes['timestamp'].dt.hour
        # Fuera de horario laboral: antes de las 7 o después de las 20
        out_of_hours = successes[(successes['hour'] < 7) | (successes['hour'] > 20)]
        if not out_of_hours.empty:
            findings.append(self._build_finding(
                tipo="Inicios Sospechosos",
                severidad="Medio",
                evidencia=f"{len(out_of_hours)} inicios fuera del horario laboral.",
                raw=out_of_hours,
                justificacion="Logins exitosos registrados fuera del horario laboral habitual, lo que puede indicar uso indebido de credenciales."
            ))
        return findings

    # ---------- 3. Escalamiento de Privilegios ----------
    def detect_privilege_escalation(self) -> List[Dict[str, Any]]:
        findings = []
        if 'event_id' not in self.df.columns:
            return findings
        escalations = self.df[self.df['event_id'].isin(self.privilege_escalation_ids)]
        if not escalations.empty:
            findings.append(self._build_finding(
                tipo="Escalamiento de Privilegios",
                severidad="Crítico",
                evidencia=f"{len(escalations)} eventos de elevación de privilegios detectados.",
                raw=escalations,
                justificacion="Se identificaron eventos asociados a la asignación de privilegios elevados o creación de grupos administrativos."
            ))
        return findings

    # ---------- 4. Comandos y Procesos Sospechosos ----------
    def detect_suspicious_commands(self) -> List[Dict[str, Any]]:
        findings = []
        if 'command_line' not in self.df.columns:
            return findings
        matches = self.df[self.df['command_line'].astype(str).str.contains(self.suspicious_commands, na=False)]
        if not matches.empty:
            findings.append(self._build_finding(
                tipo="Comandos y Procesos Sospechosos",
                severidad="Crítico",
                evidencia=f"{len(matches)} ejecuciones de comandos maliciosos conocidos.",
                raw=matches,
                justificacion="Se detectó la ejecución de utilidades asociadas a exfiltración, persistencia o volcado de credenciales."
            ))
        return findings

    # ---------- 5. Movimiento Lateral ----------
    def detect_lateral_movement(self) -> List[Dict[str, Any]]:
        findings = []
        if not {'timestamp', 'user', 'destination_ip'}.issubset(self.df.columns):
            return findings
        df_sorted = self.df.sort_values('timestamp')
        for user, group in df_sorted.groupby('user'):
            if group['destination_ip'].nunique() < self.lateral_movement_threshold:
                continue
            time_span = group['timestamp'].max() - group['timestamp'].min()
            if time_span <= timedelta(minutes=self.lateral_movement_window_min):
                findings.append(self._build_finding(
                    tipo="Movimiento Lateral",
                    severidad="Alto",
                    evidencia=f"Usuario '{user}' accedió a {group['destination_ip'].nunique()} hosts en {time_span}.",
                    raw=group,
                    justificacion="Un usuario accediendo a múltiples sistemas en un corto periodo es un patrón típico de propagación lateral tras un compromiso."
                ))
        return findings

    # ---------- 6. Otras Anomalías ----------
    def detect_other_anomalies(self) -> List[Dict[str, Any]]:
        findings = []
        # Ejemplo: IPs fuera de rangos privados (posible conexión externa)
        if 'destination_ip' in self.df.columns:
            private_regex = re.compile(r'^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)')
            external = self.df[~self.df['destination_ip'].astype(str).str.match(private_regex) & self.df['destination_ip'].notna()]
            if not external.empty:
                findings.append(self._build_finding(
                    tipo="Conexiones Externas Anómalas",
                    severidad="Medio",
                    evidencia=f"{len(external)} conexiones a IPs externas detectadas.",
                    raw=external,
                    justificacion="Conexiones a rangos de red no corporativos que podrían indicar exfiltración de datos o C2."
                ))
        return findings

    # ---------- Orquestador ----------
    def analyze(self) -> Dict[str, Any]:
        self.load_and_normalize()
        all_findings: List[Dict[str, Any]] = []
        all_findings.extend(self.detect_brute_force())
        all_findings.extend(self.detect_suspicious_logons())
        all_findings.extend(self.detect_privilege_escalation())
        all_findings.extend(self.detect_suspicious_commands())
        all_findings.extend(self.detect_lateral_movement())
        all_findings.extend(self.detect_other_anomalies())

        # Ordenar por severidad
        order = {"Crítico": 0, "Alto": 1, "Medio": 2, "Bajo": 3}
        all_findings.sort(key=lambda x: order.get(x["severity"], 4))

        return {
            "total_logs_analyzed": len(self.df),
            "findings": all_findings,
            "is_compromised": len(all_findings) > 0,
            "summary": {
                "critical": sum(1 for f in all_findings if f["severity"] == "Crítico"),
                "high": sum(1 for f in all_findings if f["severity"] == "Alto"),
                "medium": sum(1 for f in all_findings if f["severity"] == "Medio"),
            }
        }