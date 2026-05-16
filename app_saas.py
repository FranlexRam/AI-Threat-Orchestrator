import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px
import os

# --- CONFIGURACIÓN DE LA PÁGINA ---
st.set_page_config(page_title="SaktiShield Analytics", page_icon="🛡️", layout="wide")

# --- ESTILOS CSS PERSONALIZADOS ---
st.markdown("""
    <style>
    .main { background-color: #0F111A; }
    div[data-testid="stMetricValue"] { font-size: 36px; color: #00E575; }
    div[data-testid="stMetricLabel"] { font-size: 14px; color: #AEB0B7; }
    </style>
""", unsafe_allow_html=True)

# --- CABECERA BRANDING (LOGO Y TÍTULO) ---
col_logo, col_titulo = st.columns([1, 6])

with col_logo:
    # Intenta cargar el logotipo de Sakti, si no existe muestra un placeholder
    logo_path = "logo_sakti.png"
    if os.path.exists(logo_path):
        st.image(logo_path, width=100)
    else:
        st.title("🛡️") # Placeholder visual si el archivo no está en la raíz

with col_titulo:
    st.markdown("<h1 style='margin-bottom: 0px;'>SaktiShield AI Threat Orchestrator</h1>", unsafe_allow_html=True)
    st.markdown("<p style='color: #AEB0B7; font-size: 16px;'>Dashboard Ejecutivo e interfaz profesional en tiempo real para el análisis de amenazas.</p>", unsafe_allow_html=True)

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
        # Contamos tanto "CRÍTICO" como "ALTO" de manera estricta
        amenazas_criticas = len(df[df["nivel_riesgo"].str.upper().isin(["CRÍTICO", "CRITICO", "ALTO"])])
        st.metric("Amenazas Críticas", amenazas_criticas)
    with m3:
        st.metric("IPs Únicas", df["ip_origen"].nunique())

    st.markdown("---")

    # --- CONFIGURACIÓN DE COLORES DINÁMICOS PARA LA DONA ---
    # Mapeo exacto de las categorías almacenadas con los colores cyberpunk profesionales
    color_map = {
        "Tráfico Legítimo": "#00E575",
        "SQL Injection": "#FF003C",
        "XSS (Cross-Site Scripting)": "#FF5722",
        "Directory Traversal": "#FFB300",
        "Otras Amenazas": "#7C4DFF"
    }

    # --- GRÁFICOS INTERACTIVOS ---
    c1, c2 = st.columns([4, 5])

    with c1:
        st.subheader("📊 Distribución de Ataques")
        
        # Construimos el gráfico de dona forzando nuestro mapa de color discreto
        fig_cat = px.pie(
            df, 
            names="categoria", 
            hole=0.5, 
            color="categoria",
            color_discrete_map=color_map
        )
        
        # Ajustes de diseño estético para el fondo oscuro
        fig_cat.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#FFFFFF'),
            legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
        )
        st.plotly_chart(fig_cat, use_container_width=True)

    with c2:
        st.subheader("📋 Historial Reciente de Logs")
        # Visualización limpia de la tabla de eventos
        st.dataframe(df[["fecha", "ip_origen", "categoria", "nivel_riesgo"]], use_container_width=True)

    # --- DETALLE DEL ÚLTIMO ANÁLISIS SOC ---
    st.markdown("---")
    st.subheader("🕵️ Análisis SOC de la IA (Último Evento)")
    
    # Caja informativa que resalta dinámicamente el reporte extendido de Llama 3.2
    st.text_area(
        label="Reporte Técnico Desplegado:",
        value=df.iloc[0]["analisis_ia"],
        height=180,
        disabled=True
    )

except Exception as e:
    st.error(f"Aún no hay datos en la base de datos o hubo un error: {e}")
    st.info("Asegúrate de haber corrido brain.py y haber lanzado al menos un ataque desde Kali.")