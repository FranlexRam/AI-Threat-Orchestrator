import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px
from datetime import datetime

# --- CONFIGURACIÓN DE LA PÁGINA ---
st.set_page_config(page_title="AI Threat Orchestrator", page_icon="🛡️", layout="wide")

st.title("🛡️ AI Threat Orchestrator - Dashboard Ejecutivo")
st.markdown("Esta interfaz muestra en tiempo real los ataques analizados por la IA.")

# --- FUNCIÓN PARA LEER LA DB ---
def cargar_datos():
    conn = sqlite3.connect('security_vault.db')
    # Leemos la tabla de incidentes que creamos en brain.py
    df = pd.read_sql_query("SELECT * FROM incidentes ORDER BY fecha DESC", conn)
    conn.close()
    return df

try:
    df = cargar_datos()

    # --- MÉTRICAS PRINCIPALES ---
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Incidentes", len(df))
    with col2:
        amenazas_altas = len(df[df["nivel_riesgo"].str.upper() == "ALTO"])
        st.metric("Amenazas Críticas", amenazas_altas)
    with col3:
        st.metric("IPs Únicas", df["ip_origen"].nunique())

    st.markdown("---")

    # --- GRÁFICOS INTERACTIVOS ---
    c1, c2 = st.columns(2)

    with c1:
        st.subheader("Distribución de Ataques")
        fig_cat = px.pie(df, names="categoria", hole=0.4, color_discrete_sequence=px.colors.sequential.RdBu)
        st.plotly_chart(fig_cat, use_container_width=True)

    with c2:
        st.subheader("Historial Reciente")
        st.dataframe(df[["fecha", "ip_origen", "categoria", "nivel_riesgo"]], use_container_width=True)

    # --- DETALLE DEL ÚLTIMO ANÁLISIS ---
    st.subheader("🕵️ Análisis de la IA (Último Evento)")
    st.info(df.iloc[0]["analisis_ia"])

except Exception as e:
    st.error(f"Aún no hay datos en la base de datos o hubo un error: {e}")
    st.info("Asegúrate de haber corrido brain.py y haber lanzado al menos un ataque desde Kali.")