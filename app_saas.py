import streamlit as st
import pandas as pd
import psycopg2  # 🐘 Driver oficial de PostgreSQL
import plotly.express as px
import os
import time  # 🚀 Control del ciclo de vida

# --- CONFIGURACIÓN DE LA PÁGINA RESPONSIVE ---
st.set_page_config(
    page_title="SaktiShield AI Threat Orchestrator", 
    page_icon="🛡️", 
    layout="wide", 
    initial_sidebar_state="expanded"
)

# --- 🔒 INICIALIZACIÓN DEL SISTEMA DE AUTENTICACIÓN ---
if "autenticado" not in st.session_state:
    st.session_state.autenticado = False
if "user_rol" not in st.session_state:
    st.session_state.user_rol = None
if "user_empresa" not in st.session_state:
    st.session_state.user_empresa = None
if "tema_claro" not in st.session_state:
    st.session_state.tema_claro = False

# --- CONEXIÓN A POSTGRESQL ---
def obtener_conexion_pg():
    """🛡️ Obtiene conexión limpia a PostgreSQL leyendo variables de entorno"""
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "saktishield-db"),  # 🖥️ Cambiado por defecto al nombre del servicio Docker
        database=os.getenv("DB_NAME", "saktishield_production"),
        user=os.getenv("DB_USER", "sakti_admin"),
        password=os.getenv("DB_PASSWORD", "SaktiSecurePassword2026!"),
        port=os.getenv("DB_PORT", "5432")
    )

# --- 🛠️ INICIALIZAR TABLA DE USUARIOS Y SEMILLA MASTER ---
def inicializar_base_datos():
    """Crea la tabla de credenciales RBAC si no existe y siembra el acceso inicial"""
    try:
        conn = obtener_conexion_pg()
        cursor = conn.cursor()
        
        # Crear tabla de usuarios
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sakti_users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(100) NOT NULL,
                rol VARCHAR(20) NOT NULL, -- SUPERADMIN o CLIENT_ADMIN
                empresa_name VARCHAR(100), -- NULL para SUPERADMIN, nombre exacto para clientes
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Sembrar tu cuenta SuperAdmin global si está vacío el entorno
        cursor.execute("SELECT id FROM sakti_users WHERE username = 'sakti_root';")
        if not cursor.fetchone():
            cursor.execute("""
                INSERT INTO sakti_users (username, password, rol, empresa_name)
                VALUES ('sakti_root', 'sakti123', 'SUPERADMIN', 'GLOBAL');
            """)
            
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        # Lo mostramos como advertencia por si Postgres tarda unos segundos extras en iniciar
        st.warning(f"Esperando sincronización con el clúster Postgres...")

# Disparamos la verificación de tablas de seguridad de forma silenciosa
inicializar_base_datos()


# ==============================================================================
# 🚪 FLUJO EXCLUSIVO DE PANTALLA DE LOGIN
# ==============================================================================
if not st.session_state.autenticado:
    # Paleta de diseño temporal minimalista solo para la caja de Login
    st.markdown("""
        <style>
        .stApp { background-color: #080809 !important; color: #FFFFFF !important; }
        </style>
    """, unsafe_allow_html=True)
    
    st.markdown("<br><br><br>", unsafe_allow_html=True)
    col_l1, col_l2, col_l3 = st.columns([1, 1.4, 1])
    
    with col_l2:
        st.markdown("""
            <div style="background-color: #101012; padding: 35px; border-radius: 8px; border: 1px solid #1F1F23; text-align: center;">
                <h2 style='color: #FFFFFF; font-weight: 800; margin-bottom: 5px; letter-spacing: 0.5px;'>🛡️ SAKTI SHIELD</h2>
                <p style='color: #A1A1AA; font-size: 14px;'>Identificación Perimetral Centralizada SaaS</p>
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown("<br>", unsafe_allow_html=True)
        with st.form("formulario_login"):
            input_user = st.text_input("Usuario Corporativo", placeholder="ej. alfa_admin")
            input_pass = st.text_input("Firma Digital / Contraseña", type="password", placeholder="••••••••")
            boton_enviar = st.form_submit_button("Ingresar al Centro de Operaciones", use_container_width=True)
            
            if boton_enviar:
                # 🧼 Limpiamos espacios en blanco accidentales de los inputs
                user_limpio = input_user.strip()
                pass_limpio = input_pass.strip()
                
                # 🔒 BYPASS HARDCODED ABSOLUTO (Se evalúa primero, ignorando fallas de la base de datos)
                if user_limpio == "sakti_root" and pass_limpio == "sakti123":
                    st.session_state.autenticado = True
                    st.session_state.user_rol = "SUPERADMIN"
                    st.session_state.user_empresa = "GLOBAL"
                    st.success("🔒 Acceso máster verificado. Conectando...")
                    time.sleep(0.4)
                    st.rerun()
                elif user_limpio == "alfa_admin" and pass_limpio == "alfa123":
                    st.session_state.autenticado = True
                    st.session_state.user_rol = "CLIENT_ADMIN"
                    st.session_state.user_empresa = "Empresa Alfa C.A."
                    st.success("🔒 Entorno protegido verificado. Conectando...")
                    time.sleep(0.4)
                    st.rerun()
                else:
                    # Solo si NO coincide con las maestras de desarrollo, intentamos autenticar por DB
                    try:
                        conn = obtener_conexion_pg()
                        cursor = conn.cursor()
                        cursor.execute(
                            "SELECT rol, empresa_name FROM sakti_users WHERE username = %s AND password = %s;",
                            (user_limpio, pass_limpio)
                        )
                        usuario_encontrado = cursor.fetchone()
                        cursor.close()
                        conn.close()
                        
                        if usuario_encontrado:
                            st.session_state.autenticado = True
                            st.session_state.user_rol = usuario_encontrado[0]
                            st.session_state.user_empresa = usuario_encontrado[1]
                            st.rerun()
                        else:
                            st.error("❌ Credenciales inválidas.")
                    except Exception as db_error:
                        st.error(f"❌ Error de comunicación con el clúster: {db_error}")
    st.stop()  # 🚫 DETIENE POR COMPLETO LA RENDERIZACIÓN SI NO ESTÁ LOGUEADO


# ==============================================================================
# 📊 DISEÑO DEL DASHBOARD CENTRAL (SÓLO SI PASÓ EL LOGIN)
# ==============================================================================

# Fila superior minimalista para el switch de tema y botón de logout
col_header_left, col_header_right = st.columns([8, 2])
with col_header_right:
    mode_toggle = st.toggle("☀️ Modo Claro", value=st.session_state.tema_claro)
    st.session_state.tema_claro = mode_toggle
    if st.button("🚪 Cerrar Sesión", use_container_width=True):
        st.session_state.autenticado = False
        st.session_state.user_rol = None
        st.session_state.user_empresa = None
        st.rerun()

# --- DETERMINACIÓN DINÁMICA DE ESTILOS ASOCIADOS AL TEMA ---
if st.session_state.tema_claro:
    bg_app = "#F4F4F5"
    bg_card = "#FFFFFF"
    border_color = "#E4E4E7"
    text_main = "#18181B"
    text_muted = "#52525B"  
    plotly_text = "#18181B"
    code_bg = "#E4E4E7"
    badge_medio = "#18181B"
else:
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
        if st.session_state.user_rol == "SUPERADMIN":
            st.markdown(f"<p style='color: #FF0033; font-size: 15px; margin-top: 5px; font-weight:700;'>PANEL MASTER GLOBAL — Monitoreando todo el ecosistema SaaS.</p>", unsafe_allow_html=True)
        else:
            st.markdown(f"<p style='color: {text_muted}; font-size: 15px; margin-top: 5px;'>Entorno Protegido para: <b>{st.session_state.user_empresa}</b></p>", unsafe_allow_html=True)

# --- CONFIGURACIÓN BARRA LATERAL (CONTROL MULTI-TENANT) ---
empresa_a_consultar = st.session_state.user_empresa

if st.session_state.user_rol == "SUPERADMIN":
    st.sidebar.markdown(f"<h3 style='color:{text_main};'>⚙️ Consola Global</h3>", unsafe_allow_html=True)
    
    try:
        conn = obtener_conexion_pg()
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT empresa_name FROM sakti_users WHERE empresa_name != 'GLOBAL';")
        lista_empresas = [fila[0] for fila in cursor.fetchall() if fila[0]]
        cursor.close()
        conn.close()
    except:
        lista_empresas = []
        
    if "Empresa Alfa C.A." not in lista_empresas:
        lista_empresas.append("Empresa Alfa C.A.")
        
    opciones_filtro = ["TODOS LOS CLIENTES"] + lista_empresas
    seleccion_sidebar = st.sidebar.selectbox("Filtrar Vista Operativa:", opciones_filtro)
    empresa_a_consultar = seleccion_sidebar

# --- FUNCIÓN PARA LEER LA DB (POSTGRESQL - TENANT ISOLATION) ---
def cargar_datos_pg(target_tenant, rol):
    try:
        conn = obtener_conexion_pg()
        if rol == "SUPERADMIN" and target_tenant == "TODOS LOS CLIENTES":
            query = """
                SELECT id, fecha, ip_origen, analisis_ia, categoria, nivel_riesgo, estatus, log_original, accion_mitigacion, empresa_name 
                FROM "incidentes" 
                WHERE categoria != 'Tráfico Legítimo'
                ORDER BY fecha DESC
            """
            df = pd.read_sql_query(query, conn)
        else:
            query = """
                SELECT id, fecha, ip_origen, analisis_ia, categoria, nivel_riesgo, estatus, log_original, accion_mitigacion, empresa_name 
                FROM "incidentes" 
                WHERE categoria != 'Tráfico Legítimo' AND empresa_name = %s
                ORDER BY fecha DESC
            """
            df = pd.read_sql_query(query, conn, params=(target_tenant,))
            
        conn.close()
        
        if not df.empty:
            df['categoria'] = df['categoria'].replace({
                'SSRF Attack (Server-Side Request Forgery)': 'SSRF Attack'
            })
        return df
    except:
        return pd.DataFrame(columns=["id", "fecha", "ip_origen", "analisis_ia", "categoria", "nivel_riesgo", "estatus", "log_original", "accion_mitigacion", "empresa_name"])

# --- RENDERIZACIÓN OPERATIVA DEL PANEL SOC ---
df = cargar_datos_pg(empresa_a_consultar, st.session_state.user_rol)

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

color_map = {
    "Brute Force": "#FF0033",
    "SQL Injection": "#80001A",
    "XSS (Cross-Site Scripting)": "#0066FF",
    "Directory Traversal": "#EAB308",  
    "Remote Code Execution (RCE)": "#FF6600",
    "SSRF Attack": "#71717A",
    "Otras Amenazas": "#444444"
}

if df.empty:
    st.markdown(f"""
        <div style="padding: 30px; background-color: {bg_card}; border: 1px dashed #FF0033; border-radius: 6px; text-align: center;">
            <p style="color: {text_main}; font-size: 16px; margin: 0; font-weight: 600;">
                📡 Centro de Operaciones de Seguridad (SOC) Activo para: <span style="color:#FF0033;">{empresa_a_consultar}</span>
            </p>
            <p style="color: {text_muted}; font-size: 14px; margin: 5px 0 0 0;">
                Escuchando transmisiones en tiempo real en PostgreSQL. Esperando la inyección de las primeras telemetrías de ataque...
            </p>
        </div>
    """, unsafe_allow_html=True)
else:
    # --- COLUMNAS RESPONSIVE OPTIMIZADAS ---
    c1, c2 = st.columns([1, 1.2])

    with c1:
        st.markdown(f"<h3 style='color:{text_main}; font-weight:700;'>📊 Distribución de Vector de Ataques</h3>", unsafe_allow_html=True)
        
        fig_cat = px.pie(df, names="categoria", hole=0.6, color="categoria", color_discrete_map=color_map)
        fig_cat.update_layout(
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color=plotly_text, size=12),
            legend=dict(orientation="h", yanchor="top", y=-0.08, xanchor="center", x=0.5, font=dict(color=plotly_text, size=11)),
            margin=dict(t=10, b=10, l=10, r=10)
        )
        fig_cat.update_traces(textposition='inside', textinfo='percent', marker=dict(line=dict(color=bg_app, width=2)))
        st.plotly_chart(fig_cat, theme="streamlit", use_container_width=True)

    with c2:
        st.markdown(f"<h3 style='color:{text_main}; font-weight:700;'>📋 Historial de Eventos Recientes</h3>", unsafe_allow_html=True)
        
        columnas_vista = ["fecha", "ip_origen", "categoria", "nivel_riesgo", "accion_mitigacion"]
        if st.session_state.user_rol == "SUPERADMIN" and empresa_a_consultar == "TODOS LOS CLIENTES":
            columnas_vista.append("empresa_name")
            
        df_vista = df[columnas_vista].copy()
        
        def parsear_fila_html(row):
            sev = str(row["nivel_riesgo"]).upper()
            clase = "badge-critico" if any(x in sev for x in ["CRÍT", "CRIT", "ALT"]) else ("badge-medio" if "MED" in sev else "badge-bajo")
            row["nivel_riesgo"] = f'<span class="{clase}">{row["nivel_riesgo"]}</span>'
            row["ip_origen"] = f'<code style="color: #FF0033; font-family: monospace; background:{code_bg}; padding:2px 6px; border-radius:4px;">{row["ip_origen"]}</code>'
            row["accion_mitigacion"] = f'<span style="color: {text_muted}; font-style: italic;">{row["accion_mitigacion"]}</span>'
            if "empresa_name" in row:
                row["empresa_name"] = f'<b style="color: {text_main}; font-size:13px;">{row["empresa_name"]}</b>'
            return row

        df_vista = df_vista.apply(parsear_fila_html, axis=1)
        cabeceras_tabla = ["Fecha y Hora", "Dirección IP", "Vector de Ataque", "Severidad", "Acción Defensiva (SOAR)"]
        if "empresa_name" in df_vista.columns:
            cabeceras_tabla.append("Cliente Afectado")
            
        df_vista.columns = cabeceras_tabla
        html_puro = df_vista.to_html(index=False, escape=False, classes="tabla-soc")
        st.markdown(f'<div class="tabla-soc-container">{html_puro}</div>', unsafe_allow_html=True)

    # --- VISOR INTERACTIVO ---
    st.markdown("<br><hr>", unsafe_allow_html=True)
    st.markdown(f"<h3 style='color:{text_main}; font-weight:700;'>🔍 Visor Interactivo de Auditoría SOC</h3>", unsafe_allow_html=True)
    
    df['selector_texto'] = df['fecha'] + " | " + df['categoria'] + " (" + df['ip_origen'] + ")"
    opciones_incidentes = df['selector_texto'].tolist()
    
    incidente_seleccionado = st.selectbox("Selecciona un incidente para inspeccionar:", options=opciones_incidentes, index=0)
    fila_seleccionada = df[df['selector_texto'] == incidente_seleccionado].iloc[0]
    
    st.markdown(f"""
        <div class="forensic-card" style="border-left: 6px solid {color_map.get(fila_seleccionada['categoria'], '#FF0033')};">
            <div class="forensic-header">🛡️ REPORTE DE AUDITORÍA: {fila_seleccionada['categoria'].upper()}</div>
            <div class="forensic-text">
                <b>Fecha:</b> {fila_seleccionada['fecha']} &nbsp;|&nbsp; <b>IP:</b> <code>{fila_seleccionada['ip_origen']}</code> &nbsp;|&nbsp; <b>Riesgo:</b> {fila_seleccionada['nivel_riesgo']}<br>
                <b>Cliente Protegido:</b> <span style="color:#FF0033; font-weight:700;">{fila_seleccionada['empresa_name']}</span><br>
                <b>Mitigación SOAR:</b> <span style="font-weight: 700;">{fila_seleccionada['accion_mitigacion']}</span><br>
                <b>Payload Detectado:</b> <code>{fila_seleccionada['log_original']}</code><br><br>
                <div style="margin-top:15px; border-top:1px solid {border_color}; padding-top:15px;">
                    <b>Análisis Forense Virtual AI:</b><br>
                    <span style="color: {text_main}; font-size:18px;">{fila_seleccionada['analisis_ia']}</span>
                </div>
            </div>
        </div>
    """, unsafe_allow_html=True)

# 📡 Sincronización en caliente activa cada 3 segundos
time.sleep(3)
st.rerun()