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

# --- 🔒 INICIALIZACIÓN COMPLETA DEL SISTEMA DE AUTENTICACIÓN ---
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
        host=os.getenv("DB_HOST", "saktishield-db"),  # 🖥️ Nombre del servicio Docker
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
                empresa_name VARCHAR(100), -- NULL para SUPERADMIN o 'GLOBAL'
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
        st.warning(f"Esperando sincronización con el clúster Postgres...")

# Disparamos la verificación de tablas de seguridad de forma silenciosa
inicializar_base_datos()


# ==============================================================================
# 🚪 FLUJO EXCLUSIVO DE PANTALLA DE LOGIN (DINÁMICO Y CENTRALIZADO)
# ==============================================================================
if not st.session_state.autenticado:
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
                user_limpio = input_user.strip()
                pass_limpio = input_pass.strip()
                
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
                        rol_detectado = usuario_encontrado[0]
                        empresa_detectada = usuario_encontrado[1]
                        
                        st.session_state.autenticado = True
                        st.session_state.user_rol = rol_detectado
                        st.session_state.user_empresa = empresa_detectada
                        
                        st.success(f"🔒 Acceso verificado con éxito [{empresa_detectada}]. Conectando...")
                        time.sleep(0.5)
                        st.rerun()
                    else:
                        st.error("❌ Credenciales inválidas.")
                except Exception as db_error:
                    st.error(f"❌ Error de comunicación con el clúster: {db_error}")
    st.stop()


# ==============================================================================
# 📊 DISEÑO DEL DASHBOARD CENTRAL (SÓLO SI PASÓ EL LOGIN)
# ==============================================================================

# Fila superior minimalista para el switch de tema y botón de logout
col_header_left, col_header_right = st.columns([8, 2])
with col_header_right:
    # 🛡️ Vinculación nativa y persistente usando key sin sobreescritura manual redundante
    st.toggle("☀️ Modo Claro", key="tema_claro")
    
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
    div[data-baseweb="select"] {{ background-color: {bg_card} !important; color: {text_main} !important; }}
    
    .tabla-soc-container {{
        max-height: 410px; 
        overflow-y: auto; 
        border: 1px solid {border_color}; 
        border-radius: 6px;
        background-color: {bg_card};
    }}
    .tabla-soc {{ width: 100%; border-collapse: collapse; font-family: -apple-system, BlinkMacSystemFont, sans-serif; color: {text_main}; text-align: left; }}
    .tabla-soc thead tr {{ background-color: {"#E4E4E7" if st.session_state.tema_claro else "#18181B"}; border-bottom: 2px solid {border_color}; position: sticky; top: 0; z-index: 10; }}
    .tabla-soc th {{ padding: 14px; font-size: 13px; font-weight: 700; color: {text_muted}; text-transform: uppercase; }}
    .tabla-soc tbody tr {{ border-bottom: 1px solid {border_color}; font-size: 15px; }}
    .tabla-soc tbody tr:hover {{ background-color: {"#FAFAFA" if st.session_state.tema_claro else "#141416"}; }}
    .tabla-soc td {{ padding: 14px; color: {text_main}; }}
    
    .badge-critico {{ color: #EF4444; font-weight: 700; }}
    .badge-alto {{ color: #F97316; font-weight: 700; }}
    .badge-medio {{ color: #F59E0B; font-weight: 700; }}
    .badge-bajo {{ color: #10B981; font-weight: 500; }}
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

# --- 🎛️ CONFIGURACIÓN BARRA LATERAL ---
empresa_a_consultar = st.session_state.user_empresa

if st.session_state.user_rol == "SUPERADMIN":
    st.sidebar.markdown(f"<h3 style='color:{text_main};'>⚙️ Consola Global</h3>", unsafe_allow_html=True)
    
    try:
        conn = obtener_conexion_pg()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT empresa_name 
            FROM sakti_users 
            WHERE rol = 'CLIENT_ADMIN' AND empresa_name IS NOT NULL AND empresa_name != 'GLOBAL'
            ORDER BY empresa_name;
        """)
        lista_empresas = [fila[0] for fila in cursor.fetchall() if fila[0]]
        cursor.close()
        conn.close()
    except Exception:
        lista_empresas = []
        
    opciones_filtro = ["TODOS LOS CLIENTES"] + lista_empresas
    seleccion_sidebar = st.sidebar.selectbox("Filtrar Vista Operativa:", opciones_filtro)
    empresa_a_consultar = seleccion_sidebar

# --- FUNCIÓN PARA LEER LA DB ---
def cargar_datos_pg(target_tenant, rol):
    try:
        conn = obtener_conexion_pg()
        
        # 🛡️ SOLUCIÓN AL BUG FANTASMA: Ampliamos las exclusiones de strings exactos para purgar todo el tráfico benigno
        lista_exclusiones = ('Tráfico Legítimo', 'Tráfico Rutinario', 'Tráfico Legítimo (Rutinario)', 'Tráfico legítimo')
        
        if rol == "SUPERADMIN" and target_tenant == "TODOS LOS CLIENTES":
            query = """
                SELECT id, created_at AS fecha, client_ip AS ip_origen, resultado_ia AS analisis_ia, 
                       alerta_status AS estado_perimetral, nivel_riesgo, tipo_ataque AS categoria, 
                       log_entry AS log_original, soar_active, empresa_name 
                FROM sakti_incidents 
                WHERE tipo_ataque NOT IN %s
                ORDER BY created_at DESC
            """
            df = pd.read_sql_query(query, conn, params=(lista_exclusiones,))
        else:
            query = """
                SELECT id, created_at AS fecha, client_ip AS ip_origen, resultado_ia AS analisis_ia, 
                       alerta_status AS estado_perimetral, nivel_riesgo, tipo_ataque AS categoria, 
                       log_entry AS log_original, soar_active, empresa_name 
                FROM sakti_incidents 
                WHERE empresa_name = %s AND tipo_ataque NOT IN %s
                ORDER BY created_at DESC
            """
            df = pd.read_sql_query(query, conn, params=(target_tenant, lista_exclusiones))
            
        conn.close()
        
        if not df.empty:
            df['fecha'] = df['fecha'].astype(str)
            df['categoria'] = df['categoria'].astype(str).str.strip()
            
            # 🛡️ SOLUCIÓN AL BUG DE CLASIFICACIÓN BAJA (Capa de Seguridad Inmutable):
            # Analizamos la categoría real y si es un ataque flagrante, forzamos el escalado de severidad
            def forzar_severidad_minima(row):
                cat = row['categoria'].upper()
                if "BRUTE" in cat or "FORCE" in cat or "XSS" in cat or "SCRIPT" in cat or "SQL" in cat or "INJECTION" in cat or "TRAVERSAL" in cat or "RCE" in cat:
                    if "SQL" in cat or "RCE" in cat or "EXECUTION" in cat:
                        return "CRÍTICO"
                    return "ALTO"
                return row['nivel_riesgo']
                
            df['nivel_riesgo'] = df.apply(forzar_severidad_minima, axis=1)
            
        return df
    except Exception as e:
        return pd.DataFrame(columns=["id", "fecha", "ip_origen", "analisis_ia", "estado_perimetral", "nivel_riesgo", "categoria", "log_original", "soar_active", "empresa_name"])

# --- RENDERIZACIÓN OPERATIVA DEL PANEL SOC ---
df = cargar_datos_pg(empresa_a_consultar, st.session_state.user_rol)

total_incidentes = len(df)
amenazas_criticas = len(df[df["nivel_riesgo"].str.upper().isin(["CRÍTICO", "CRITICO", "ALTO"])]) if not df.empty else 0
ips_bloqueadas = df[df["estado_perimetral"] == "BLOQUEADO"]["ip_origen"].nunique() if not df.empty else 0

# --- TARJETAS DE MÉTRICAS HTML ---
st.markdown("<br>", unsafe_allow_html=True)
m1, m2, m3 = st.columns(3)

with m1:
    st.markdown(f"""
        <div style="background-color: {bg_card}; padding: 20px; border-radius: 6px; border: 1px solid {border_color};">
            <div style="font-size: 13px; color: {text_muted}; letter-spacing: 0.1em; text-transform: uppercase; font-weight: 700;">Total Incidentes Reales</div>
            <div style="font-size: 40px; font-weight: 800; color: #FF0033; margin-top: 5px; letter-spacing: -1px;">{total_incidentes}</div>
        </div>
    """, unsafe_allow_html=True)
    
with m2:
    st.markdown(f"""
        <div style="background-color: {bg_card}; padding: 20px; border-radius: 6px; border: 1px solid {border_color};">
            <div style="font-size: 13px; color: {text_muted}; letter-spacing: 0.1em; text-transform: uppercase; font-weight: 700;">Amenazas Críticas / Altas</div>
            <div style="font-size: 40px; font-weight: 800; color: #FF0033; margin-top: 5px; letter-spacing: -1px;">{amenazas_criticas}</div>
        </div>
    """, unsafe_allow_html=True)
    
with m3:
    st.markdown(f"""
        <div style="background-color: {bg_card}; padding: 20px; border-radius: 6px; border: 1px solid {border_color};">
            <div style="font-size: 13px; color: {text_muted}; letter-spacing: 0.1em; text-transform: uppercase; font-weight: 700;">IPs Únicas Mitigadas</div>
            <div style="font-size: 40px; font-weight: 800; color: #FF0033; margin-top: 5px; letter-spacing: -1px;">{ips_bloqueadas}</div>
        </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# 🎯 CONFIGURACIÓN DE COLORES ALINEADA EXACTAMENTE CON BRAIN.PY (Mapeo estricto de Strings)
color_map = {
    "Brute Force": "#FF0033",
    "SQL Injection": "#80001A",
    "Cross-Site Scripting (XSS)": "#0066FF",
    "Directory Traversal": "#EAB308",  
    "Remote Code Execution (RCE)": "#FF6600",
    "SSRF Attack": "#71717A",
    "Anomalía de Red detectada por IA": "#444444"
}

# --- CONTROL MULTI-TENANT DE RENDERIZADO VISUAL EN BASE A DATA ---
if df.empty:
    st.markdown(f"""
        <div style="padding: 30px; background-color: {bg_card}; border: 1px dashed #FF0033; border-radius: 6px; text-align: center;">
            <p style="color: {text_main}; font-size: 16px; margin: 0; font-weight: 600;">
                📡 Centro de Operaciones de Seguridad (SOC) Activo para: <span style="color:#FF0033;">{empresa_a_consultar}</span>
            </p>
            <p style="color: {text_muted}; font-size: 14px; margin: 5px 0 0 0;">
                No se registran telemetrías anómalas ni eventos perimetrales para este tenant en PostgreSQL.
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
        
        columnas_vista = ["fecha", "ip_origen", "categoria", "nivel_riesgo"]
        if st.session_state.user_rol == "SUPERADMIN" and empresa_a_consultar == "TODOS LOS CLIENTES":
            columnas_vista.append("empresa_name")
            
        df_vista = df[columnas_vista].copy()
        
        def parsear_fila_html(row):
            riesgo = str(row["nivel_riesgo"]).upper()
            if "CRÍT" in riesgo or "CRIT" in riesgo:
                clase = "badge-critico"
            elif "ALT" in riesgo:
                clase = "badge-alto"
            elif "MED" in riesgo:
                clase = "badge-medio"
            else:
                clase = "badge-bajo"
                
            row["nivel_riesgo"] = f'<span class="{clase}">🚨 {row["nivel_riesgo"]}</span>'
            row["ip_origen"] = f'<code style="color: #FF0033; font-family: monospace; background:{code_bg}; padding:2px 6px; border-radius:4px;">{row["ip_origen"]}</code>'
            if "empresa_name" in row:
                row["empresa_name"] = f'<b style="color: {text_main}; font-size:13px;">{row["empresa_name"]}</b>'
            return row

        df_vista = df_vista.apply(parsear_fila_html, axis=1)
        cabeceras_tabla = ["Fecha", "Dirección IP", "Vector Detectado", "Nivel Riesgo"]
        if "empresa_name" in df_vista.columns:
            cabeceras_tabla.append("Cliente Afectado")
            
        df_vista.columns = cabeceras_tabla
        html_puro = df_vista.to_html(index=False, escape=False, classes="tabla-soc")
        st.markdown(f'<div class="tabla-soc-container">{html_puro}</div>', unsafe_allow_html=True)

    # --- 🔒 VISOR INTERACTIVO ENCAPSULADO ESTRICTAMENTE DENTRO DEL ELSE ---
    st.markdown("<br><hr>", unsafe_allow_html=True)
    st.markdown(f"<h3 style='color:{text_main}; font-weight:700;'>🔍 Visor Interactivo de Auditoría SOC</h3>", unsafe_allow_html=True)
    
    df['selector_texto'] = df['fecha'] + " | " + df['categoria'] + " (" + df['ip_origen'] + ")"
    opciones_incidentes = df['selector_texto'].tolist()
    
    incidente_seleccionado = st.selectbox("Selecciona un incidente para inspeccionar de manera aislada:", options=opciones_incidentes, index=0)
    
    # Verificación defensiva antes de renderizar la tarjeta detallada inferior
    if incidente_seleccionado in df['selector_texto'].values:
        fila_seleccionada = df[df['selector_texto'] == incidente_seleccionado].iloc[0]
        
        db_riesgo = str(fila_seleccionada['nivel_riesgo']).upper()
        color_badge = "#EF4444" if "CRÍT" in db_riesgo or "CRIT" in db_riesgo or "ALT" in db_riesgo else ("#F59E0B" if "MED" in db_riesgo else "#10B981")
        
        st.markdown(f"""
            <div style="background-color: {bg_card}; padding: 25px; border-radius: 6px; border-left: 5px solid {color_badge}; border-top: 1px solid {border_color}; border-right: 1px solid {border_color}; border-bottom: 1px solid {border_color}; margin-top: 15px;">
                <h4 style="color: {text_main}; margin-top:0; font-weight:800; letter-spacing:0.5px;">🛡️ REPORTE DE AUDITORÍA: {fila_seleccionada['categoria'].upper()}</h4>
                <p style="color: {text_muted}; font-size:14px; margin-bottom:15px;">Tenant Auditado: <b>{fila_seleccionada['empresa_name']}</b></p>
                <table style="width:100%; color:{text_main}; font-size:14px; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 6px 0; color:{text_muted}; width:25%;"><b>Fecha y Hora:</b></td>
                        <td>{fila_seleccionada['fecha']}</td>
                    </tr>
                    <tr>
                        <td style="padding: 6px 0; color:{text_muted};"><b>IP de Origen:</b></td>
                        <td style="color:#EF4444; font-family:monospace; font-weight:700;">{fila_seleccionada['ip_origen']}</td>
                    </tr>
                    <tr>
                        <td style="padding: 6px 0; color:{text_muted};"><b>Estado Perimetral:</b></td>
                        <td><span style="background-color:{"#E4E4E7" if st.session_state.tema_claro else "#18181B"}; padding: 2px 8px; border-radius:4px; font-weight:bold;">{fila_seleccionada['estado_perimetral']}</span></td>
                    </tr>
                    <tr>
                        <td style="padding: 6px 0; color:{text_muted};"><b>Nivel de Riesgo:</b></td>
                        <td><span style="color:{color_badge}; font-weight:bold;">🚨 {fila_seleccionada['nivel_riesgo']}</span></td>
                    </tr>
                    <tr>
                        <td style="padding: 6px 0; color:{text_muted};"><b>Orquestación SOAR:</b></td>
                        <td style="color:#60A5FA; font-weight:bold;">{fila_seleccionada['soar_active']}</td>
                    </tr>
                </table>
                <br>
                <div style="background-color: {code_bg}; padding: 15px; border-radius: 4px; border: 1px solid {border_color};">
                    <span style="color: {text_muted}; font-size: 12px; display:block; margin-bottom:5px;">LOG DE TELEMETRÍA CRUDO RECOLECTADO:</span>
                    <code style="color: #F43F5E; font-size:13px; word-break: break-all; font-family:monospace;">{fila_seleccionada['log_original']}</code>
                </div>
                <br>
                <div style="background-color: {"#E0E7FF" if st.session_state.tema_claro else "#1E1B4B"}; padding: 15px; border-radius: 4px; border: 1px solid {"#C7D2FE" if st.session_state.tema_claro else "#312E81"};">
                    <span style="color: {"#4338CA" if st.session_state.tema_claro else "#C7D2FE"}; font-size: 12px; display:block; margin-bottom:5px;">DICTAMEN DEL MOTOR DE INTELIGENCIA ARTIFICIAL SAKTISHIELD AI (brain.py):</span>
                    <p style="color: {"#1E1B4B" if st.session_state.tema_claro else "#E0E7FF"}; font-size:14px; margin:0; line-height:1.5;">{fila_seleccionada['analisis_ia']}</p>
                </div>
            </div>
        """, unsafe_allow_html=True)

# 📡 Sincronización en caliente activa cada 3 segundos
time.sleep(3)
st.rerun()