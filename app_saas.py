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
        border-left: 5px solid #9C27B0; /* Línea púrpura táctica de SaktiShield */
        padding: 30px; /* Más aire interno para legibilidad */
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        margin-top: 15px;
    }
    .forensic-header {
        font-size: 22px; /* Letra de encabezado más imponente */
        font-weight: 700;
        color: #FFFFFF;
        margin-bottom: 18px;
        letter-spacing: 0.5px;
    }
    .forensic-text {
        font-size: 18px; /* ¡Letra corregida! Ahora es perfectamente legible */
        color: #E2E4E9;
        line-height: 1.8; /* Mayor separación entre renglones para descanso visual */
        text-align: justify;
    }
    /* Estilos para subsecciones o negritas dentro del reporte */
    .forensic-text strong {
        color: #FF5722; 
        font-size: 19px;
        margin-top: 15px;
        display: inline-block;
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
        # Mostramos la tabla con un look limpio
        st.dataframe(df[["fecha", "ip_origen", "categoria", "nivel_riesgo"]], use_container_width=True, height=280)

    # --- DETALLE DEL ÚLTIMO ANÁLISIS SOC (UI/UX REDISEÑADA) ---
    st.markdown("---")
    st.subheader("🕵️ Reporte de Auditoría IA (Último Evento)")
    
    # Extraemos el log y limpiamos posibles problemas de formato de texto
    ultimo_analisis = df.iloc[0]["analisis_ia"]
    
    # Limpieza estética: Si el texto contiene la metadata del string, la separamos para dejar solo el cuerpo de la IA
    if "Análisis Forense:" in ultimo_analisis:
        partes = ultimo_analisis.split("Análisis Forense:", 1)
        cuerpo_reporte = partes[1].strip()
    else:
        cuerpo_reporte = ultimo_analisis

    # Renderizado elegante utilizando HTML inyectado de forma segura en la tarjeta custom
    st.markdown(f"""
        <div class="forensic-card">
            <div class="forensic-header">
                🔍 ANÁLISIS FORENSE PERICIAL EXPERTO - SOC NIVEL 3
            </div>
            <div class="forensic-text">
                {cuerpo_reporte}
            </div>
        </div>
    """, unsafe_allow_html=True)

except Exception as e:
    st.error(f"Aún no hay datos en la base de datos o hubo un error: {e}")
    st.info("Asegúrate de haber corrido brain.py y haber lanzado al menos un ataque desde Kali.")