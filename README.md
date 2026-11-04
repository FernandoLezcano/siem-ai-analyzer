# 🛡️ SIEM AI Analyzer

**SIEM AI Analyzer** es una aplicación web de ciberseguridad diseñada para automatizar el triaje inicial de alertas en un SOC (Security Operations Center). Transforma logs crudos exportados de un SIEM en formato Excel en **dos informes profesionales en PDF** (Ejecutivo y Técnico), utilizando reglas heurísticas de detección y un Modelo de Lenguaje Grande (LLM) para la redacción del contexto.

Este proyecto fue construido siguiendo principios de **arquitectura limpia, separación de responsabilidades y rigor analítico** (cero alucinaciones de IA).

## 📑 Tabla de Contenidos

1. [Características Principales](#-características-principales)

2. [Arquitectura y Flujo de Datos](#-arquitectura-y-flujo-de-datos)

3. [Estructura del Proyecto](#-estructura-del-proyecto)

4. [Explicación Detallada de Módulos](#-explicación-detallada-de-módulos)

5. [Decisiones de Diseño](#-decisiones-de-diseño)

6. [Instalación y Configuración](#-instalación-y-configuración)

7. [Guía de Uso](#-guía-de-uso)

8. [Solución de Problemas Comunes](#-solución-de-problemas-comunes)

9. [Licencia](#-licencia)

## ✨ Características Principales

* **📥 Ingesta Robusta:** Carga y normalización automática de logs en Excel, manejando variaciones en los nombres de las columnas.

* **🔍 Motor de Detección Heurística:** Correlación de eventos para detectar 6 vectores de ataque críticos:

  * Fuerza Bruta (Intentos fallidos reiterados).

  * Movimiento Lateral (Múltiples conexiones en poco tiempo).

  * Escalamiento de Privilegios (EventIDs específicos de Windows).

  * Comandos Sospechosos (Regex sobre líneas de comandos).

  * Inicios Sospechosos (Logins fuera de horario).

  * Conexiones Externas (IPs fuera de rangos privados).

* **🤖 IA Anti-Alucinaciones:** Integración con OpenRouter (DeepSeek V4 Flash). La IA **solo** redacta el contexto basándose en los hallazgos pre-procesados por Python.

* **📊 Dashboard Interactivo:** Visualización en tiempo real de métricas, criticidad y muestras de logs crudos.

* **📄 Generación Dual de PDFs:**

  * **Informe Ejecutivo:** Resumen de impacto, plan de acción y recomendaciones (sin tecnicismos ni logs).

  * **Informe Técnico:** Explicación forense, justificación de hallazgos y tablas de evidencias detalladas.

* **⚡ Optimización:** Uso intensivo de caché en Streamlit para evitar reprocesar el Excel o regenerar la IA/PDFs en cada interacción.

## 🏗️ Arquitectura y Flujo de Datos

El proyecto sigue un flujo lineal y desacoplado:

```
[Excel Input] 
     │
     ▼
[Parser.py] ──► Normaliza datos y aplica 6 reglas de detección heurística.
     │
     ▼ (Devuelve un JSON con Hallazgos + Evidencias)
[AI_Agent.py] ──► Recibe SOLO los hallazgos, construye el prompt y llama a DeepSeek.
     │
     ▼ (Devuelve JSON con Resumen, Impacto, Plan de Acción)
[PDF_Generator.py] ──► Toma los datos + contenido IA y renderiza dos plantillas HTML.
     │
     ▼
[Jinja2 + WeasyPrint] ──► Convierte el HTML a PDF (Ejecutivo y Técnico).
     │
     ▼
[App.py (Streamlit)] ──► Muestra métricas y ofrece botones de descarga.

```

## 📂 Estructura del Proyecto

```
siem-ai-analyzer/
│
├── data/                           # Carpeta para los archivos Excel de prueba
│   └── sample_logs.xlsx
│
├── src/                            # Código fuente principal
│   ├── __init__.py
│   ├── app.py                      # Interfaz web (Streamlit)
│   ├── config.py                   # Gestión de variables de entorno (Pydantic)
│   ├── parser.py                   # Motor de Pandas y reglas de detección
│   ├── ai_agent.py                 # Conexión con OpenRouter y prompts estrictos
│   └── pdf_generator.py            # Lógica de generación de PDFs con Jinja2/WeasyPrint
│
├── templates/                      # Plantillas HTML para los informes
│   ├── report_executive.html       # Diseño del PDF Ejecutivo
│   └── report_technical.html       # Diseño del PDF Técnico (con tablas)
│
├── tests/                          # Pruebas de integración
│   ├── __init__.py
│   └── test_flow.py                # Script para probar el flujo completo sin UI
│
├── .env                            # Variables de entorno (API Keys) - NO SUBIR A GIT
├── .gitignore                      # Archivos ignorados por Git
├── requirements.txt                # Dependencias del proyecto
├── README.md                       # Este archivo
└── MANUAL.md                       # Manual técnico detallado (opcional)

```

## 🔬 Explicación Detallada de Módulos

### 1. `src/config.py`

Utiliza `pydantic-settings` para cargar y validar las variables de entorno. Si falta una API Key o el formato es incorrecto, la aplicación falla al inicio (*Fail-Fast*), evitando errores en tiempo de ejecución.

### 2. `src/parser.py`

* **Clase `LogParser`:** Recibe la ruta del Excel.

* **Normalización:** Convierte todas las columnas a minúsculas y asegura que `timestamp` sea un objeto datetime de Pandas.

* **Reglas de Detección:** Cada método (`detect_brute_force`, `detect_lateral_movement`, etc.) es independiente y devuelve un diccionario con: `type`, `severity`, `evidence`, `justification`, `affected_records` y `raw_data`.

* **Orquestador:** El método `analyze()` ejecuta todas las reglas, ordena los hallazgos por severidad (Crítico > Alto > Medio > Bajo) y devuelve un JSON estructurado.

### 3. `src/ai_agent.py`

* **Integración con OpenRouter:** Usa el SDK oficial de OpenAI pero apuntando a `https://openrouter.ai/api/v1`.

* **Rigor Analítico:** El `system_prompt` es extremadamente estricto. Prohíbe inventar IPs, usuarios o fechas. Si no está en el JSON de entrada, la IA no lo menciona.

* **Resiliencia:** Implementa un bucle de reintentos (`max_retries=2`). Si OpenRouter devuelve una respuesta vacía (común en modelos de razonamiento con `json_object`), el sistema reintenta automáticamente.

* **Fallback:** Si la IA falla definitivamente, devuelve un JSON con mensajes de error amigables para que la app no se rompa.

### 4. `src/pdf_generator.py`

* **Separación de Informes:** Tiene dos métodos: `generate_executive_pdf` y `generate_technical_pdf`.

* **Jinja2:** Renderiza los datos de Python en las plantillas HTML.

* **Preparación de Tablas:** Para el informe técnico, convierte el `raw_data` (lista de diccionarios) a DataFrames de Pandas, selecciona solo las columnas clave y genera el HTML de la tabla con la clase `styled-table`.

* **WeasyPrint:** Toma el HTML final y lo convierte a PDF respetando los estilos CSS (tamaño A4, márgenes, saltos de página).

### 5. `src/app.py`

* **Streamlit:** Construye la UI.

* **Manejo de Estado (`st.session_state`):** Almacena los resultados del parser, el contenido de la IA y los bytes de los PDFs. Esto evita que la app vuelva a llamar a la IA o regenere los PDFs cada vez que el usuario hace clic en un botón.

* **Caché (`@st.cache_data`):** Evita reprocesar el mismo Excel si el usuario interactúa con la UI.

## 🧠 Decisiones de Diseño

| Decisión | Justificación | 
| ----- | ----- | 
| **La IA no lee los logs crudos** | Enviar 700+ líneas de logs a un LLM consume muchos tokens y aumenta el riesgo de alucinaciones. Al enviar solo los hallazgos pre-procesados, el coste es mínimo y la precisión es máxima. | 
| **Uso de `response_format={"type": "json_object"}`** | Fuerza al LLM a devolver un JSON estructurado, eliminando la necesidad de parsear texto libre con expresiones regulares frágiles. | 
| **Separación de PDFs (Ejecutivo/Técnico)** | Un CEO no quiere ver tablas de logs, y un analista SOC no necesita leer resúmenes de negocio. Separar los informes mejora la comunicación y la utilidad del entregable. | 
| **`sys.path.insert` en `app.py`** | Streamlit cambia el directorio de trabajo al ejecutarse. Añadir la raíz del proyecto al `sys.path` garantiza que los imports de `src.*` funcionen siempre. | 
| **Instalación manual de GTK en Windows** | WeasyPrint requiere librerías gráficas del sistema en Windows. Se documenta claramente en la guía de instalación para evitar el error `OSError: cannot load library 'libgobject-2.0-0'`. | 

## 🚀 Instalación y Configuración

### Prerrequisitos

* Python 3.10 o superior.

* API Key de OpenRouter (puedes obtener una gratis en openrouter.ai).

* Windows (Obligatorio): Instalar el GTK3 Runtime. Durante la instalación, marca la casilla "Set up PATH environment variable". Reinicia tu terminal después.

### Pasos

1. Clonar el repositorio:

```
git clone https://github.com/tu-usuario/siem-ai-analyzer.git
cd siem-ai-analyzer

```

2. Crear y activar el entorno virtual:

```
python -m venv venv
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

```

3. Instalar dependencias:

```
pip install -r requirements.txt

```

4. Configurar variables de entorno:
   Crea un archivo `.env` en la raíz del proyecto con el siguiente contenido:

```
OPENROUTER_API_KEY=sk-or-v1-tu-clave-aqui
AI_MODEL=deepseek/deepseek-v4-flash

```

5. Verificar que todo funciona (Test de Integración):

```
python -m tests.test_flow

```

Esto generará un archivo `test_report.pdf` en la raíz si todo está correcto.

6. Iniciar la aplicación web:

```
streamlit run src/app.py

```

## 🖥️ Guía de Uso

1. Abre la aplicación en tu navegador (usualmente http://localhost:8501).

2. En la barra lateral izquierda, sube tu archivo Excel con los logs del SIEM.

3. La app analizará automáticamente los logs y mostrará:

   * Métricas generales (logs analizados, hallazgos, críticos).

   * Una lista de expanders con cada hallazgo detectado y su justificación técnica.

4. Haz clic en "Generar Informe". La IA de DeepSeek (vía OpenRouter) redactará el contexto.

5. Una vez generado el texto, la app creará los dos PDFs en segundo plano.

6. Aparecerán dos botones:

   * 📥 Descargar Informe Ejecutivo (para gerencia).

   * 🛠️ Descargar Informe Técnico (para el equipo SOC).

## 🛠️ Solución de Problemas Comunes

1. `ModuleNotFoundError: No module named 'src'`

   * **Causa:** Streamlit no encuentra la carpeta raíz.

   * **Solución:** Asegúrate de ejecutar `streamlit run src/app.py` desde la raíz del proyecto. El archivo `app.py` ya incluye la inyección en `sys.path` para solucionar esto.

2. `OSError: cannot load library 'libgobject-2.0-0'` (Windows)

   * **Causa:** Falta el runtime de GTK para WeasyPrint.

   * **Solución:** Instala el GTK3 Runtime y asegúrate de marcar la opción de añadir al PATH. Reinicia la terminal.

3. `La IA no devolvió ningún contenido`

   * **Causa:** DeepSeek V4 Flash a veces devuelve una respuesta vacía si el prompt es muy complejo.

   * **Solución:** El código ya incluye 2 reintentos automáticos. Si persiste, cambia el modelo en tu `.env` a `deepseek/deepseek-chat` (modelo estándar, más estable para JSON).

4. `Las tablas del PDF se salen de la hoja`

   * **Causa:** WeasyPrint no sabe cómo ajustar tablas muy anchas.

   * **Solución:** El `pdf_generator.py` ya recorta las columnas a las 6 más importantes y aplica `table-layout: fixed` en el CSS de la plantilla.

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Puedes usarlo, modificarlo y distribuirlo libremente, siempre que se mantenga la atribución original.

*Desarrollado como proyecto de portafolio para demostrar habilidades en Ciberseguridad (SOC), Análisis de Datos (Pandas) y Desarrollo Backend/Frontend con Python.*