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
        
        # --- Configuración de Reglas ---
        self.brute_force_threshold = 5
        
        # Regex para comandos maliciosos (PowerShell ofuscado, exfiltración, reconocimiento)
        self.suspicious_cmd_regex = re.compile(
            r'(mimikatz|nc\s+-e|powershell.*-enc|vssadmin.*delete|net\s+view|7z\.exe\s+a|tar\.exe.*-c)',
            re.IGNORECASE
        )
        # Regex para detectar acceso a recursos sensibles (Finanzas, Legal)
        self.sensitive_access_regex = re.compile(r'(Finance|Legal|FY2026)', re.IGNORECASE)
        
        # Event IDs Windows Clave
        self.failed_logon_id = 4625
        self.success_logon_id = 4624
        self.privilege_escalation_id = 4672
        self.process_creation_id = 4688

    def load_and_normalize(self) -> None:
        try:
            self.df = pd.read_excel(self.file_path)
            self.df.columns = [col.strip().lower() for col in self.df.columns]
            
            # Normalización de tipos
            if 'timestamp' in self.df.columns:
                self.df['timestamp'] = pd.to_datetime(self.df['timestamp'], errors='coerce')
            if 'event_id' in self.df.columns:
                self.df['event_id'] = pd.to_numeric(self.df['event_id'], errors='coerce')
            if 'process_commandline' in self.df.columns:
                self.df['process_commandline'] = self.df['process_commandline'].fillna('').astype(str)
                
            logger.info(f"Datos cargados y normalizados: {len(self.df)} registros.")
        except Exception as e:
            logger.error(f"Error cargando Excel: {e}")
            raise ValueError(f"Archivo inválido: {e}")

    def _build_finding(self, tipo: str, severidad: str, evidencia: str, raw: pd.DataFrame, justificacion: str) -> Dict[str, Any]:
        return {
            "type": tipo,
            "severity": severidad,
            "evidence": evidencia,
            "justification": justificacion,
            "raw_data": raw.head(15).to_dict(orient='records'), # Límite para no saturar el PDF
            "affected_records": len(raw)
        }

    # --- 1. Fuerza Bruta ---
    def detect_brute_force(self) -> List[Dict[str, Any]]:
        findings = []
        if not {'source_ip', 'event_id'}.issubset(self.df.columns): return findings
        
        failed = self.df[self.df['event_id'] == self.failed_logon_id]
        grouped = failed.groupby('source_ip').size().reset_index(name='count')
        
        for _, row in grouped[grouped['count'] >= self.brute_force_threshold].iterrows():
            severity = "Crítico" if row['count'] >= 20 else "Alto"
            findings.append(self._build_finding(
                "Fuerza Bruta", severity,
                f"IP {row['source_ip']} con {row['count']} intentos fallidos.",
                failed[failed['source_ip'] == row['source_ip']],
                f"Superó el umbral de {self.brute_force_threshold} intentos. Indica ataque de diccionario o fuerza bruta."
            ))
        return findings

    # --- 2. Inicios Sospechosos (Horario y Origen) ---
    def detect_suspicious_logons(self) -> List[Dict[str, Any]]:
        findings = []
        if not {'timestamp', 'event_id'}.issubset(self.df.columns): return findings
        
        successes = self.df[self.df['event_id'] == self.success_logon_id].copy()
        if successes.empty: return findings
        
        # Fuera de horario (antes de 7am o después de 8pm)
        successes['hour'] = successes['timestamp'].dt.hour
        out_of_hours = successes[(successes['hour'] < 7) | (successes['hour'] > 20)]
        
        if not out_of_hours.empty:
            findings.append(self._build_finding(
                "Inicios Sospechosos", "Medio",
                f"{len(out_of_hours)} inicios de sesión fuera del horario laboral.",
                out_of_hours,
                "Accesos exitosos registrados fuera del horario habitual, posible uso indebido de credenciales."
            ))
        return findings

    # --- 3. Escalamiento de Privilegios ---
    def detect_privilege_escalation(self) -> List[Dict[str, Any]]:
        findings = []
        if 'event_id' not in self.df.columns: return findings
        
        escalations = self.df[self.df['event_id'] == self.privilege_escalation_id]
        if not escalations.empty:
            findings.append(self._build_finding(
                "Escalamiento de Privilegios", "Crítico",
                f"{len(escalations)} eventos de asignación de privilegios especiales.",
                escalations,
                "Event ID 4672 detectado. Indica que una cuenta obtuvo privilegios administrativos o de sistema."
            ))
        return findings

    # --- 4. Comandos y Procesos Sospechosos ---
    def detect_suspicious_commands(self) -> List[Dict[str, Any]]:
        findings = []
        if 'process_commandline' not in self.df.columns: return findings
        
        # Filtramos solo donde hay un comando real
        commands = self.df[self.df['process_commandline'] != '']
        matches = commands[commands['process_commandline'].str.contains(self.suspicious_cmd_regex, na=False)]
        
        if not matches.empty:
            findings.append(self._build_finding(
                "Comandos y Procesos Sospechosos", "Crítico",
                f"{len(matches)} ejecuciones de comandos maliciosos detectados.",
                matches,
                "Se identificaron ejecuciones de PowerShell ofuscado (-enc), volcado de credenciales, o herramientas de exfiltración (7z, tar)."
            ))
        return findings

    # --- 5. Movimiento Lateral ---
    def detect_lateral_movement(self) -> List[Dict[str, Any]]:
        findings = []
        if not {'timestamp', 'user', 'destination'}.issubset(self.df.columns): return findings
        
        # Buscamos logins exitosos desde una misma cuenta a múltiples destinos
        logins = self.df[self.df['event_id'] == self.success_logon_id]
        if logins.empty: return findings

        for user, group in logins.groupby('user'):
            if group['destination'].nunique() >= 3: # Umbral de 3 destinos distintos
                findings.append(self._build_finding(
                    "Movimiento Lateral", "Alto",
                    f"Usuario '{user}' accedió a {group['destination'].nunique()} sistemas distintos.",
                    group,
                    "Un mismo usuario autenticándose en múltiples servidores en un corto periodo sugiere propagación lateral."
                ))
        return findings

    # --- 6. Otras Anomalías (Exfiltración y Ataques Web) ---
    def detect_other_anomalies(self) -> List[Dict[str, Any]]:
        findings = []
        
        # Anomalía A: Acceso a Recursos Compartidos Sensibles
        if 'event_description' in self.df.columns:
            sensitive = self.df[self.df['event_description'].str.contains(self.sensitive_access_regex, na=False)]
            if not sensitive.empty:
                findings.append(self._build_finding(
                    "Acceso a Datos Sensibles", "Alto",
                    f"{len(sensitive)} accesos a carpetas críticas (Finance/Legal).",
                    sensitive,
                    "Se detectó acceso a directorios de alto valor. Verificar si el usuario tiene legitimidad para acceder."
                ))

        # Anomalía B: Exfiltración por Proxy
        if 'log_source' in self.df.columns and 'event_description' in self.df.columns:
            proxy_logs = self.df[self.df['log_source'].str.contains('Proxy', case=False, na=False)]
            exfil = proxy_logs[proxy_logs['event_description'].str.contains('bytes_out', case=False, na=False)]
            if not exfil.empty:
                findings.append(self._build_finding(
                    "Posible Exfiltración de Datos", "Crítico",
                    f"{len(exfil)} transferencias masivas de datos salientes.",
                    exfil,
                    "Múltiples conexiones POST HTTPS con gran volumen de bytes hacia IPs externas (ej. 198.51.100.88)."
                ))
                
        return findings

    # --- Orquestador Final ---
    def analyze(self) -> Dict[str, Any]:
        self.load_and_normalize()
        
        all_findings = []
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