import sys
import os
from pathlib import Path

# --- SOLUCIÓN SENIOR: Añadir la raíz del proyecto al sys.path ---
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
# ----------------------------------------------------------------

import tempfile
import logging
from datetime import datetime

import streamlit as st
import pandas as pd

from src.parser import LogParser
from src.ai_agent import ThreatIntelAgent
from src.pdf_generator import PDFReportGenerator

# ------------------------------------------------------------------
# Configuración de logging
# ------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Configuración de la página
# ------------------------------------------------------------------
st.set_page_config(
    page_title="SIEM AI Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ------------------------------------------------------------------
# Funciones con caché
# ------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def process_file(file_path: str) -> dict:
    """Parsea y analiza el Excel. Cacheado por ruta de archivo."""
    parser = LogParser(file_path)
    return parser.analyze()

@st.cache_data(show_spinner=False)
def generate_pdfs_bytes(parsed_results: dict, ai_content: dict) -> tuple[bytes, bytes]:
    """
    Genera AMBOS PDFs (Ejecutivo y Técnico) y devuelve sus bytes.
    Cacheado por contenido para no regenerar si no cambian los datos.
    """
    template_dir = str(PROJECT_ROOT / "templates")
    pdf_gen = PDFReportGenerator(template_dir=template_dir)
    
    tmp_exec = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    tmp_tech = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    tmp_exec.close()
    tmp_tech.close()
    
    try:
        # Generar Ejecutivo
        pdf_gen.generate_executive_pdf(parsed_results, ai_content, tmp_exec.name)
        # Generar Técnico
        pdf_gen.generate_technical_pdf(parsed_results, ai_content, tmp_tech.name)
        
        with open(tmp_exec.name, "rb") as f:
            exec_bytes = f.read()
        with open(tmp_tech.name, "rb") as f:
            tech_bytes = f.read()
            
        return exec_bytes, tech_bytes
    finally:
        if os.path.exists(tmp_exec.name): os.remove(tmp_exec.name)
        if os.path.exists(tmp_tech.name): os.remove(tmp_tech.name)

# ------------------------------------------------------------------
# Inicialización del estado de sesión
# ------------------------------------------------------------------
def init_session_state():
    """Inicializa las claves de session_state una sola vez."""
    if "parsed_results" not in st.session_state:
        st.session_state.parsed_results = None
    if "ai_content" not in st.session_state:
        st.session_state.ai_content = None
    if "pdf_exec_bytes" not in st.session_state:
        st.session_state.pdf_exec_bytes = None
    if "pdf_tech_bytes" not in st.session_state:
        st.session_state.pdf_tech_bytes = None
    if "uploaded_filename" not in st.session_state:
        st.session_state.uploaded_filename = None

# ------------------------------------------------------------------
# Componentes de UI
# ------------------------------------------------------------------
def render_metrics(parsed_results: dict):
    """Muestra las métricas principales en tarjetas."""
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("📊 Logs analizados", parsed_results["total_logs_analyzed"])
    col2.metric("🚨 Hallazgos totales", len(parsed_results["findings"]))
    col3.metric("🔴 Críticos", parsed_results["summary"]["critical"])
    col4.metric("🟠 Altos", parsed_results["summary"]["high"])

    if parsed_results["is_compromised"]:
        st.error("⚠️ **Estado: COMPROMETIDO** — Se han detectado indicadores de compromiso.")
    else:
        st.success("✅ **Estado: LIMPIO** — No se detectaron indicadores de compromiso.")

def render_findings(parsed_results: dict):
    """Muestra los hallazgos en expanders por severidad."""
    st.subheader("🚨 Hallazgos Detectados")
    for idx, finding in enumerate(parsed_results["findings"], start=1):
        icon = {
            "Crítico": "🔴",
            "Alto": "🟠",
            "Medio": "🟡",
            "Bajo": "🟢",
        }.get(finding["severity"], "⚪")

        with st.expander(f"{icon} {idx}. {finding['type']} — {finding['severity']}"):
            st.markdown(f"**Evidencia:** {finding['evidence']}")
            st.markdown(f"**Justificación:** {finding['justification']}")
            st.markdown(f"**Registros afectados:** {finding['affected_records']}")
            st.markdown("**Muestra de logs crudos:**")
            st.dataframe(
                pd.DataFrame(finding["raw_data"]).head(10),
                use_container_width=True,
            )

def render_ai_section(parsed_results: dict):
    """Renderiza la sección de generación del informe IA."""
    st.subheader("🤖 Informe Técnico con IA")

    if st.session_state.ai_content is None:
        if st.button("🧠 Generar Informe", type="primary", use_container_width=True):
            with st.spinner("Redactando informe con IA..."):
                try:
                    agent = ThreatIntelAgent()
                    ai_content = agent.generate_report_content(parsed_results)
                    st.session_state.ai_content = ai_content
                    st.rerun()
                except Exception as e:
                    logger.exception("Error generando el informe IA")
                    st.error(f"Error al generar el informe: {e}")
    else:
        ai = st.session_state.ai_content

        # Mostrar el contenido del informe
        with st.container(border=True):
            st.markdown("### 📄 Resumen Ejecutivo")
            st.write(ai["executive_summary"])

            st.markdown("### 🔍 Explicación Técnica")
            st.write(ai["technical_explanation"])

            st.markdown("### 💥 Impacto en la Organización")
            st.write(ai["impact"])

            st.markdown("### 🛠️ Plan de Acción")
            st.write(ai["action_plan"])

            st.markdown("### 🛡️ Recomendaciones Generales")
            st.write(ai["recommendations"])

        # Generar los PDFs (cacheado)
        if st.session_state.pdf_exec_bytes is None or st.session_state.pdf_tech_bytes is None:
            with st.spinner("Generando PDFs..."):
                try:
                    exec_bytes, tech_bytes = generate_pdfs_bytes(parsed_results, ai)
                    st.session_state.pdf_exec_bytes = exec_bytes
                    st.session_state.pdf_tech_bytes = tech_bytes
                except Exception as e:
                    logger.exception("Error generando los PDFs")
                    st.error(f"Error al generar los PDFs: {e}")

        # Botones de descarga (Dos columnas)
        if st.session_state.pdf_exec_bytes and st.session_state.pdf_tech_bytes:
            col1, col2 = st.columns(2)
            with col1:
                st.download_button(
                    label="📥 Descargar Informe Ejecutivo",
                    data=st.session_state.pdf_exec_bytes,
                    file_name=f"ejecutivo_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                    mime="application/pdf",
                    type="primary",
                    use_container_width=True,
                )
            with col2:
                st.download_button(
                    label="🛠️ Descargar Informe Técnico",
                    data=st.session_state.pdf_tech_bytes,
                    file_name=f"tecnico_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                    mime="application/pdf",
                    type="primary",
                    use_container_width=True,
                )

# ------------------------------------------------------------------
# Aplicación principal
# ------------------------------------------------------------------
def main():
    init_session_state()

    # --- Sidebar ---
    with st.sidebar:
        st.title("🛡️ SIEM AI Analyzer")
        st.caption("Análisis de logs y generación de informes SOC")
        st.divider()

        st.header("📁 Carga de Datos")
        uploaded_file = st.file_uploader(
            "Sube el archivo Excel (.xlsx)",
            type=["xlsx"],
            help="El Excel debe contener los logs exportados de tu SIEM.",
        )

        st.divider()
        st.header("ℹ️ Información")
        st.markdown(
            """
            **Modelo IA:** DeepSeek V4 Flash (OpenRouter)  
            **Detecciones:**
            - Fuerza bruta
            - Inicios sospechosos
            - Escalamiento de privilegios
            - Comandos sospechosos
            - Movimiento lateral
            - Otras anomalías
            """
        )

        if st.button("🔄 Reiniciar análisis", use_container_width=True):
            for key in ["parsed_results", "ai_content", "pdf_exec_bytes", "pdf_tech_bytes", "uploaded_filename"]:
                st.session_state[key] = None
            st.cache_data.clear()
            st.rerun()

    # --- Contenido principal ---
    if uploaded_file is None:
        st.title("Bienvenido al SIEM AI Analyzer")
        st.info(
            "👈 Sube un archivo Excel con los logs de tu SIEM en la barra lateral "
            "para comenzar el análisis."
        )
        return

    # Si cambia el archivo subido, limpiamos el estado anterior
    if st.session_state.uploaded_filename != uploaded_file.name:
        st.session_state.parsed_results = None
        st.session_state.ai_content = None
        st.session_state.pdf_exec_bytes = None
        st.session_state.pdf_tech_bytes = None
        st.session_state.uploaded_filename = uploaded_file.name

    # Guardar el Excel temporalmente y analizarlo
    if st.session_state.parsed_results is None:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx") as tmp:
            tmp.write(uploaded_file.getvalue())
            tmp_path = tmp.name
        try:
            with st.spinner("Analizando logs y correlacionando eventos..."):
                st.session_state.parsed_results = process_file(tmp_path)
        except Exception as e:
            logger.exception("Error procesando el Excel")
            st.error(f"Error al procesar el Excel: {e}")
            st.stop()
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    parsed_results = st.session_state.parsed_results

    # --- Renderizado ---
    st.title(f"📊 Análisis: `{uploaded_file.name}`")
    render_metrics(parsed_results)
    st.divider()

    if parsed_results["is_compromised"]:
        render_findings(parsed_results)
        st.divider()
        render_ai_section(parsed_results)
    else:
        st.success("No se han detectado hallazgos que requieran informe técnico.")
        with st.expander("Ver detalles del análisis"):
            st.write(parsed_results)

if __name__ == "__main__":
    main()