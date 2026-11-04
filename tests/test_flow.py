import os
import sys
from pathlib import Path

# Aseguramos que la raíz del proyecto esté en el PYTHONPATH
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.parser import LogParser
from src.ai_agent import ThreatIntelAgent
from src.pdf_generator import PDFReportGenerator

def main():
    excel_path = PROJECT_ROOT / "data" / "SIEM_Test_Logs_Sample.xlsx"
    output_pdf = PROJECT_ROOT / "data" / "test_report.pdf"

    if not excel_path.exists():
        print(f"❌ No existe el Excel de prueba: {excel_path}")
        return

    print("1. Analizando Excel...")
    parser = LogParser(str(excel_path))
    result = parser.analyze()
    print(f"   → {len(result['findings'])} hallazgos detectados")

    print("2. Generando informe IA (DeepSeek V4 Flash)...")
    agent = ThreatIntelAgent()
    ai = agent.generate_report_content(result)
    print(f"   → Resumen: {ai['executive_summary'][:100]}...")

    print("3. Generando PDF...")
    pdf = PDFReportGenerator(template_dir=str(PROJECT_ROOT / "templates"))
    pdf.generate_pdf(result, ai, str(output_pdf))
    print(f"   → PDF generado en: {output_pdf}")

if __name__ == "__main__":
    main()