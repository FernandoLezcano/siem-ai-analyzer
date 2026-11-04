from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
from datetime import datetime
from typing import Dict, Any
import pandas as pd
import os

class PDFReportGenerator:
    def __init__(self, template_dir: str = "templates"):
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def generate_executive_pdf(self, parsed_data: Dict[str, Any], ai_content: Dict[str, Any], output_path: str) -> str:
        """Genera el informe ejecutivo (sin logs crudos)."""
        template = self.env.get_template("report_executive.html")
        
        html_out = template.render(
            data=parsed_data,
            ai=ai_content,
            report_date=datetime.now().strftime("%d/%m/%Y %H:%M")
        )
        
        HTML(string=html_out).write_pdf(output_path)
        return output_path

    def generate_technical_pdf(self, parsed_data: Dict[str, Any], ai_content: Dict[str, Any], output_path: str) -> str:
        """Genera el informe técnico (con tablas de evidencias)."""
        template = self.env.get_template("report_technical.html")
        
        # Preparamos las tablas de evidencias
        for finding in parsed_data['findings']:
            df_raw = pd.DataFrame(finding['raw_data'])
            cols_to_show = [c for c in ['timestamp', 'user', 'source_ip', 'event_id', 'event_description', 'process'] if c in df_raw.columns]
            
            if cols_to_show:
                finding['evidence_html'] = df_raw[cols_to_show].head(5).to_html(
                    classes='styled-table', 
                    index=False,
                    escape=True
                )
            else:
                finding['evidence_html'] = "<p>No hay datos tabulares disponibles.</p>"

        html_out = template.render(
            data=parsed_data,
            ai=ai_content,
            report_date=datetime.now().strftime("%d/%m/%Y %H:%M")
        )
        
        HTML(string=html_out).write_pdf(output_path)
        return output_path