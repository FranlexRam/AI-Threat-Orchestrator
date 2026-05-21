import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px
import os

# --- CONFIGURACIÓN DE LA PÁGINA ---
st.set_page_config(page_title="SaktiShield Analytics", page_icon="🛡️", layout="wide")

# --- ESTILOS CSS PERSONALIZADOS (LOOK PREMIUM EXPERTO) ---
st.markdown("""
    <style>
    /* Fondo general oscuro táctico */
    .main { background-color: #0B0D13; }
    
    /* Estilización de métricas */
    div[data-testid="stMetricValue"] { font-size: 38px; font-weight: 700; color: #00E575; }
    div[data-testid="stMetricLabel"] { font-size: 14px; color: #AEB0B7; letter-spacing: 0.5px; }
    
    /* Contenedor de la Tarjeta Forense */
    .forensic-card {
        background-color: #121622;
        border-left: 6px solid #9C27B0; /* Línea púrpura táctica */
        padding: 35px; /* Más espacio interno */
        border-radius: 10px;
        box-shadow: 0 6px 16px rgba(0,0,0,0.4);
        margin-top: 20px;
    }
    .forensic-header {
        font-size: 24px; /* Encabezado claro y grande */
        font-weight: 700;
        color: #FFFFFF;
        margin-bottom: 20px;
        letter-spacing: 0.5px;
    }
    .forensic-text {
        font-size: 20px; /* ¡Letra robusta! Se leerá perfecto a cualquier distancia */
        color: #F3F4F6; /* Blanco de alto contraste */
        line-height: 1.8; /* Excelente interlineado */
        text-align: justify;
    }
    /* Estilos para código o comandos resaltados por la IA */
    .forensic-text code {
        background-color: #1E2538;
        color: #00E575; /* Comandos en verde neón */
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 19px;
    }
    </style>
""", unsafe_allow_html=True)

# --- CABECERA BRANDING (LOGO Y TÍTULO) ---
col_logo, col_titulo = st.columns([1, 8])

with col_logo:
    logo_path = "logo_sakti.png"
    if os.path.exists(logo_path):
        st.image(logo_path, width=95)
    else:
        st.title("🛡️")

with col_titulo:
    st.markdown("<h1 style='margin-bottom: 0px; font-weight: 700;'>SaktiShield AI Threat Orchestrator</h1>", unsafe_allow_html=True)
    st.markdown("<p style='color: #AEB0B7; font-size: 15px; margin-top: 5px;'>Dashboard de Control Ejecutivo e Interfaz de Auditoría Forense en Tiempo Real.</p>", unsafe_allow_html=True)

# --- FUNCIÓN PARA LEER LA DB ---
def cargar_datos():
    conn = sqlite3.connect('security_vault.db')
    df = pd.read_sql_query("SELECT * FROM incidentes ORDER BY fecha DESC", conn)
    conn.close()
    return df

try:
    df = cargar_datos()

    # --- MÉTRICAS PRINCIPALES ---
    st.markdown("---")
    m1, m2, m3 = st.columns(3)
    with m1:
        st.metric("Total Incidentes", len(df))
    with m2:
        amenazas_criticas = len(df[df["nivel_riesgo"].str.upper().isin(["CRÍTICO", "CRITICO", "ALTO"])])
        st.metric("Amenazas Críticas Mitigadas", amenazas_criticas)
    with m3:
        st.metric("IPs Únicas Bloqueadas", df["ip_origen"].nunique())

    st.markdown("---")

    # --- CONFIGURACIÓN DE COLORES DINÁMICOS ---
    color_map = {
        "Tráfico Legítimo": "#00E575",
        "SQL Injection": "#FF003C",
        "XSS (Cross-Site Scripting)": "#FF5722",
        "Directory Traversal": "#FFB300",
        "Remote Code Execution (RCE)": "#9C27B0",
        "SSRF Attack": "#00BCD4",
        "Otras Amenazas": "#7C4DFF"
    }

    # --- GRÁFICOS INTERACTIVOS ---
    c1, c2 = st.columns([4, 5])

    with c1:
        st.subheader("📊 Distribución de Amenazas")
        fig_cat = px.pie(
            df, 
            names="categoria", 
            hole=0.55, 
            color="categoria",
            color_discrete_map=color_map
        )
        fig_cat.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#FFFFFF', size=12),
            legend=dict(orientation="h", yanchor="bottom", y=-0.25, xanchor="center", x=0.5),
            margin=dict(t=10, b=10, l=10, r=10)
        )
        st.plotly_chart(fig_cat, use_container_width=True)

    with c2:
        st.subheader("📋 Historial de Eventos Recientes")
        # Mostramos la tabla limpia para auditoría rápida
        st.dataframe(df[["fecha", "ip_origen", "categoria", "nivel_riesgo"]], use_container_width=True, height=230)

    # --- MOTOR DE SELECCIÓN DINÁMICA DE REPORTES ---
    st.markdown("---")
    st.subheader("🔍 Visor Interactivo de Auditoría SOC")
    
    # Creamos una lista ordenada para que el cliente elija qué incidente auditar
    df['selector_texto'] = df['fecha'] + " | " + df['categoria'] + " (" + df['ip_origen'] + ")"
    
    opciones_incidentes = df['selector_texto'].tolist()
    
    # El "Vínculo/Selector" para cargar cualquier reporte del historial
    incidente_seleccionado = st.selectbox(
        "Selecciona un incidente del historial para inspeccionar los detalles del reporte:",
        options=opciones_incidentes,
        index=0 # Por defecto carga el más reciente
    )
    
    # Extraemos los datos exactos del incidente seleccionado por el cliente
    fila_seleccionada = df[df['selector_texto'] == incidente_seleccionado].iloc[0]
    
    log_original_sel = fila_seleccionada["log_original"]
    ultimo_analisis = fila_seleccionada["analisis_ia"]
    categoria_sel = fila_seleccionada["categoria"]
    riesgo_sel = fila_seleccionada["nivel_riesgo"]
    ip_sel = fila_seleccionada["ip_origen"]
    fecha_sel = fila_seleccionada["fecha"]

    # Limpieza estética del texto de la IA
    if "Análisis Forense:" in ultimo_analisis:
        cuerpo_reporte = ultimo_analisis.split("Análisis Forense:", 1)[1].strip()
    elif "Motivo:" in ultimo_analisis:
        cuerpo_reporte = ultimo_analisis.split("Motivo:", 1)[1].strip()
    else:
        cuerpo_reporte = ultimo_analisis

    # Renderizado de la Tarjeta Forense Dinámica (Tamaño de letra optimizado a 17px)
    st.markdown(f"""
        <div class="forensic-card" style="border-left: 6px solid {color_map.get(categoria_sel, '#7C4DFF')};">
            <div class="forensic-header">
                🛡️ REPORTE DE AUDITORÍA: {categoria_sel.upper()}
            </div>
            <div class="forensic-text" style="font-size: 17px; color: #F3F4F6; line-height: 1.6;">
                <b>Fecha del Evento:</b> {fecha_sel} | <b>IP Origen:</b> {ip_sel} | <b>Riesgo:</b> {riesgo_sel}<br>
                <b>Payload Detectado:</b> <code>{log_original_sel}</code><br><br>
                <b>Análisis del Analista Virtual:</b> {cuerpo_reporte}
            </div>
        </div>
    """, unsafe_allow_html=True)

except Exception as e:
    st.error(f"Error al procesar la interfaz: {e}")