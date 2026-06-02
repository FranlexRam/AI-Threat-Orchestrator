import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px
import os
import time  # 🚀 Control del ciclo de vida

# --- CONFIGURACIÓN DE LA PÁGINA RESPONSIVE ---
st.set_page_config(
    page_title="SaktiShield AI Threat Orchestrator", 
    page_icon="🛡️", 
    layout="wide", 
    initial_sidebar_state="collapsed"
)

# --- 🌓 SISTEMA DE CONTROL DE TEMA (MODO CLARO / OSCURO) ---
if "tema_claro" not in st.session_state:
    st.session_state.tema_claro = False

# Fila superior minimalista para el switch de tema
col_header_left, col_header_right = st.columns([8, 2])
with col_header_right:
    mode_toggle = st.toggle("☀️ Modo Claro", value=st.session_state.tema_claro)
    st.session_state.tema_claro = mode_toggle

# --- INYECCIÓN DINÁMICA DE CSS CORREGIDA Y OPTIMIZADA ---
if st.session_state.tema_claro:
    # ☀️ MODO CLARO ENTERPRISE
    bg_app = "#F4F4F5"
    bg_card = "#FFFFFF"
    border_color = "#E4E4E7"
    text_main = "#18181B"
    text_muted = "#52525B"  
    plotly_text = "#18181B"
    code_bg = "#E4E4E7"
    badge_medio = "#18181B"
else:
    # 🌙 MODO OSCURO OLED
    bg_app = "#080809"
    bg_card = "#101012"
    border_color = "#1F1F23"
    text_main = "#FFFFFF"
    text_muted = "#A1A1AA"
    plotly_text = "#FFFFFF"
    code_bg = "#18181B"
    badge_medio = "#FFFFFF"

st.markdown(f"""
    <style>
    .stApp {{ background-color: {bg_app} !important; color: {text_main} !important; }}
    .main {{ background-color: {bg_app} !important; }}
    hr {{ border-top: 1px solid #FF0033 !important; opacity: 0.3; }}

    /* Selector de Streamlit Adaptable */
    div[data-baseweb="select"] {{
        background-color: {bg_card} !important;
        color: {text_main} !important;
    }}
    
    /* Tabla SOC HTML Adaptable */
    .tabla-soc-container {{
        max-height: 410px; 
        overflow-y: auto; 
        border: 1px solid {border_color}; 
        border-radius: 6px;
        background-color: {bg_card};
    }}
    .tabla-soc {{
        width: 100%; 
        border-collapse: collapse; 
        font-family: -apple-system, BlinkMacSystemFont, sans-serif; 
        color: {text_main}; 
        text-align: left;
    }}
    .tabla-soc thead tr {{
        background-color: {"#E4E4E7" if st.session_state.tema_claro else "#18181B"}; 
        border-bottom: 2px solid {border_color}; 
        position: sticky; 
        top: 0; 
        z-index: 10;
    }}
    .tabla-soc th {{
        padding: 14px; 
        font-size: 13px; 
        font-weight: 700; 
        color: {text_muted};
        text-transform: uppercase;
    }}
    .tabla-soc tbody tr {{ border-bottom: 1px solid {border_color}; font-size: 15px; }}
    .tabla-soc tbody tr:hover {{ background-color: {"#FAFAFA" if st.session_state.tema_claro else "#141416"}; }}
    .tabla-soc td {{ padding: 14px; color: {text_main}; }}
    
    /* Badges de Severidad */
    .badge-critico {{ color: #FF0033; font-weight: 700; }}
    .badge-medio {{ color: {badge_medio}; font-weight: 700; opacity: 0.8; }}
    .badge-bajo {{ color: {text_muted}; font-weight: 500; }}
    
    /* Tarjeta Forense */
    .forensic-card {{
        background-color: {bg_card};
        border-left: 6px solid #FF0033; 
        padding: 35px;
        border-radius: 6px;
        border-top: 1px solid {border_color};
        border-right: 1px solid {border_color};
        border-bottom: 1px solid {border_color};
        margin-top: 25px;
    }}
    .forensic-header {{ font-size: 24px; font-weight: 800; color: {text_main}; margin-bottom: 20px; }}
    .forensic-text {{ font-size: 17px; color: {text_main}; line-height: 1.7; }}
    .forensic-text code {{
        background-color: {code_bg};
        color: #FF0033; 
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 15px;
        font-family: monospace;
    }}
    </style>
""", unsafe_allow_html=True)

# --- CABECERA BRANDING ---
with col_header_left:
    col_logo, col_titulo = st.columns([1, 11])
    with col_logo:
        logo_path = "logo_sakti.png"
        if os.path.exists(logo_path):
            st.image(logo_path, width=80)
        else:
            st.title("🛡️")
    with col_titulo:
        st.markdown(f"<h1 style='margin-bottom: 0px; font-weight: 800; color:{text_main};'>SaktiShield AI Threat Orchestrator</h1>", unsafe_allow_html=True)
        st.markdown(f"<p style='color: {text_muted}; font-size: 15px; margin-top: 5px;'>Dashboard de Control Ejecutivo e Interfaz de Auditoría Forense en Tiempo Real.</p>", unsafe_allow_html=True)

# --- FUNCIÓN PARA LEER LA DB ---
def cargar_datos():
    conn = sqlite3.connect('security_vault.db')
    query = """
        SELECT id, fecha, ip_origen, analisis_ia, categoria, nivel_riesgo, estatus, log_original, accion_mitigacion 
        FROM incidentes 
        WHERE categoria != 'Tráfico Legítimo'
        ORDER BY fecha DESC
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    
    if not df.empty:
        df['categoria'] = df['categoria'].replace({
            'SSRF Attack (Server-Side Request Forgery)': 'SSRF Attack'
        })
    return df

try:
    df = cargar_datos()
    
    # --- CÁLCULO DE MÉTRICAS VALORES ---
    total_incidentes = len(df)
    amenazas_criticas = len(df[df["nivel_riesgo"].str.upper().isin(["CRÍTICO", "CRITICO", "ALTO"])]) if not df.empty else 0
    ips_bloqueadas = df["ip_origen"].nunique() if not df.empty else 0

    # --- TARJETAS DE MÉTRICAS HTML ---
    st.markdown("<br>", unsafe_allow_html=True)
    m1, m2, m3 = st.columns(3)
    
    with m1:
        st.markdown(f"""
            <div style="background-color: {bg_card}; padding: 20px; border-radius: 6px; border: 1px solid {border_color}; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                <div style="font-size: 13px; color: {text_muted}; letter-spacing: 0.1em; text-transform: uppercase; font-weight: 700;">Total Incidentes</div>
                <div style="font-size: 40px; font-weight: 800; color: #FF0033; margin-top: 5px; letter-spacing: -1px;">{total_incidentes}</div>
            </div>
        """, unsafe_allow_html=True)
        
    with m2:
        st.markdown(f"""
            <div style="background-color: {bg_card}; padding: 20px; border-radius: 6px; border: 1px solid {border_color}; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                <div style="font-size: 13px; color: {text_muted}; letter-spacing: 0.1em; text-transform: uppercase; font-weight: 700;">Amenazas Críticas Mitigadas</div>
                <div style="font-size: 40px; font-weight: 800; color: #FF0033; margin-top: 5px; letter-spacing: -1px;">{amenazas_criticas}</div>
            </div>
        """, unsafe_allow_html=True)
        
    with m3:
        st.markdown(f"""
            <div style="background-color: {bg_card}; padding: 20px; border-radius: 6px; border: 1px solid {border_color}; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                <div style="font-size: 13px; color: {text_muted}; letter-spacing: 0.1em; text-transform: uppercase; font-weight: 700;">IPs Únicas Bloqueadas</div>
                <div style="font-size: 40px; font-weight: 800; color: #FF0033; margin-top: 5px; letter-spacing: -1px;">{ips_bloqueadas}</div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # --- 🟨 MAPA DE COLORES PREMIUM (Directory Traversal forzado a Amarillo en ambos temas) ---
    color_map = {
        "Brute Force": "#FF0033",
        "SQL Injection": "#80001A",
        "XSS (Cross-Site Scripting)": "#0066FF",
        "Directory Traversal": "#EAB308",  # Amarillo Cyber permanente para mayor impacto visual
        "Remote Code Execution (RCE)": "#FF6600",
        "SSRF Attack": "#71717A",
        "Otras Amenazas": "#444444"
    }

    if df.empty:
        st.info("📡 Monitoreo SOC activo: Esperando que ingresen eventos...")
    else:
        # --- COLUMNAS RESPONSIVE OPTIMIZADAS ---
        c1, c2 = st.columns([1, 1.2])

        with c1:
            st.markdown(f"<h3 style='color:{text_main}; font-weight:700;'>📊 Distribución de Amenazas</h3>", unsafe_allow_html=True)
            fig_cat = px.pie(
                df, 
                names="categoria", 
                hole=0.6, 
                color="categoria",
                color_discrete_map=color_map
            )
            
            # LEYENDA HORIZONTAL COMPACTA INFERIOR
            fig_cat.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color=plotly_text, size=12),
                legend=dict(
                    orientation="h",        
                    yanchor="top", 
                    y=-0.08,                
                    xanchor="center", 
                    x=0.5,
                    font=dict(color=plotly_text, size=11)
                ),
                margin=dict(t=10, b=10, l=10, r=10)
            )
            fig_cat.update_traces(
                textposition='inside', 
                textinfo='percent', 
                marker=dict(line=dict(color=bg_app, width=2))
            )
            st.plotly_chart(fig_cat, theme="streamlit", use_container_width=True)

        with c2:
            st.markdown(f"<h3 style='color:{text_main}; font-weight:700;'>📋 Historial de Eventos Recientes</h3>", unsafe_allow_html=True)
            
            df_vista = df[["fecha", "ip_origen", "categoria", "nivel_riesgo", "accion_mitigacion"]].copy()
            
            def parsear_fila_html(row):
                sev = str(row["nivel_riesgo"]).upper()
                clase = "badge-critico" if any(x in sev for x in ["CRÍT", "CRIT", "ALT"]) else ("badge-medio" if "MED" in sev else "badge-bajo")
                
                row["nivel_riesgo"] = f'<span class="{clase}">{row["nivel_riesgo"]}</span>'
                row["ip_origen"] = f'<code style="color: #FF0033; font-family: monospace; background:{code_bg}; padding:2px 6px; border-radius:4px;">{row["ip_origen"]}</code>'
                row["accion_mitigacion"] = f'<span style="color: {text_muted}; font-style: italic;">{row["accion_mitigacion"]}</span>'
                return row

            df_vista = df_vista.apply(parsear_fila_html, axis=1)
            df_vista.columns = ["Fecha y Hora", "Dirección IP", "Vector de Ataque", "Severidad", "Acción Defensiva (SOAR)"]
            
            html_puro = df_vista.to_html(index=False, escape=False, classes="tabla-soc")
            st.markdown(f'<div class="tabla-soc-container">{html_puro}</div>', unsafe_allow_html=True)

        # --- VISOR INTERACTIVO ---
        st.markdown("<br><hr>", unsafe_allow_html=True)
        st.markdown(f"<h3 style='color:{text_main}; font-weight:700;'>🔍 Visor Interactivo de Auditoría SOC</h3>", unsafe_allow_html=True)
        
        df['selector_texto'] = df['fecha'] + " | " + df['categoria'] + " (" + df['ip_origen'] + ")"
        opciones_incidentes = df['selector_texto'].tolist()
        
        incidente_seleccionado = st.selectbox(
            "Selecciona un incidente del historial para inspeccionar:",
            options=opciones_incidentes,
            index=0 
        )
        
        fila_seleccionada = df[df['selector_texto'] == incidente_seleccionado].iloc[0]
        
        st.markdown(f"""
            <div class="forensic-card" style="border-left: 6px solid {color_map.get(fila_seleccionada['categoria'], '#FF0033')};">
                <div class="forensic-header">
                    🛡️ REPORTE DE AUDITORÍA: {fila_seleccionada['categoria'].upper()}
                </div>
                <div class="forensic-text">
                    <b>Fecha del Evento:</b> {fila_seleccionada['fecha']} &nbsp;|&nbsp; <b>IP Origen:</b> <code>{fila_seleccionada['ip_origen']}</code> &nbsp;|&nbsp; <b>Riesgo:</b> {fila_seleccionada['nivel_riesgo']}<br>
                    <b>Mitigación Ejecutada:</b> <span style="font-weight: 700;">{fila_seleccionada['accion_mitigacion']}</span><br>
                    <b>Payload Detectado:</b> <code>{fila_seleccionada['log_original']}</code><br><br>
                    <div style="margin-top:15px; border-top:1px solid {border_color}; padding-top:15px;">
                        <b>Análisis Forense Virtual:</b><br>
                        <span style="color: {text_main}; font-size:18px;">{fila_seleccionada['analisis_ia']}</span>
                    </div>
                </div>
            </div>
        """, unsafe_allow_html=True)

    # 📡 Sincronización en caliente
    time.sleep(2)
    st.rerun()

except Exception as e:
    st.error(f"Error al procesar la interfaz: {e}")