import re
import socket
import ollama
import datetime
import os
import json
import requests
import urllib.parse
import psycopg2 # Conector oficial PostgreSQL en Docker
from dotenv import load_dotenv
from orchestrator_core import SaktiSOAR

# Cargar las variables del archivo .env
load_dotenv()

def get_pg_connection():
    """Conexión centralizada a la base de datos PostgreSQL de producción."""
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "saktishield-db"),
        database=os.getenv("DB_NAME", "saktishield_production"),
        user=os.getenv("DB_USER", "sakti_admin"),
        password=os.getenv("DB_PASSWORD", "SaktiSecurePassword2026!"),
        port=os.getenv("DB_PORT", "5432")
    )

def obtener_historial_reciente(client_ip, minutos=5):
    """Consulta PostgreSQL para evaluar ráfagas de ataques en ventanas de tiempo reales."""
    conn = get_pg_connection()
    cursor = conn.cursor()
    
    query = """
        SELECT tipo_ataque FROM sakti_incidents 
        WHERE client_ip = %s 
        AND tipo_ataque NOT IN ('Tráfico Legítimo', 'Tráfico Rutinario')
        AND created_at >= NOW() - INTERVAL '%s minutes'
    """
    historial = []
    try:
        cursor.execute(query, (client_ip, minutos))
        resultados = cursor.fetchall()
        historial = [fila[0] for fila in resultados]
    except Exception as e:
        print(f"[⚠️ CORRELACIÓN ERROR]: No se pudo leer el historial de PostgreSQL: {e}")
    finally:
        cursor.close()
        conn.close()
        
    return historial


def send_telegram_alert(categoria, riesgo, ip):
    """Envía una alerta de seguridad estructurada a Telegram"""
    token = os.getenv("TELEGRAM_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    
    if not token or not chat_id:
        return

    mensaje = (
        f"🚨 *ALERTA DE SEGURIDAD INTERCEPTADA* 🚨\n\n"
        f"🛡️ *SaktiShield AI Threat Orchestrator*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"📂 *Vector Detectado:* {categoria}\n"
        f"⚠️ *Nivel de Riesgo:* {riesgo}\n"
        f"🌐 *IP Origen:* {ip}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"⚡ _Acción: Mitigación perimetral y aislamiento SOAR ejecutado._"
    )
    
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": mensaje, "parse_mode": "Markdown"}
    
    try:
        requests.post(url, data=payload, timeout=5)
        print(f"[OK]: Alerta crítica enviada a Telegram con éxito.")
    except Exception as e:
        print(f"[ERROR]: Fallo en el envío de alerta a Telegram: {e}")
    
BLACKLIST_FILE = "blacklist.txt"

def simulate_firewall_block(ip, reason):
    """Simula la ejecución de una regla perimetral."""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(BLACKLIST_FILE, "a") as f:
        f.write(f"{ip} | {timestamp} | Razón: {reason}\n")
    print(f"\n[SISTEMA]: 🛡️ EJECUTANDO BLOQUEO: La IP {ip} ha sido enviada al Firewall.")


def orchestrator_ai(log_entry, client_ip="192.168.1.50", empresa_name="Empresa Alfa C.A."):
    print(f"[*] Procesando evento desde {client_ip} para {empresa_name}...")

    # 1. Normalización del payload
    log_decoded = urllib.parse.unquote(log_entry).replace('+', ' ')
    log_upper = log_decoded.upper()
    
    # Valores por defecto
    categoria_detectada = None
    nivel_riesgo = "BAJO"
    decision = "PERMITIR"

    # 🎯 CONTROL ESTRICTO PERIMETRAL: Mapeo duro para evitar falsos negativos del modelo 1B
    if "SELECT" in log_upper or "UNION" in log_upper or "OR 1=1" in log_upper:
        categoria_detectada = "SQL Injection"
        nivel_riesgo = "CRÍTICO"
        decision = "BLOQUEAR"
    elif "SCRIPT" in log_upper or "XSS" in log_upper or "<SCRIPT>" in log_upper or "ALERT(" in log_upper:
        categoria_detectada = "Cross-Site Scripting (XSS)"
        nivel_riesgo = "ALTO"
        decision = "BLOQUEAR"
    elif any(k in log_upper for k in ["FAILED LOGIN", "INVALID CREDENTIALS", "ACCESS DENIED", "AUTH_FAILURE"]):
        categoria_detectada = "Brute Force"
        nivel_riesgo = "MEDIO"
        decision = "EVALUAR"
    elif any(k in log_upper for k in ["WHOAMI", "NC -E", "/BIN/BASH", "CMD.EXE"]):
        categoria_detectada = "Remote Code Execution (RCE)"
        nivel_riesgo = "CRÍTICO"
        decision = "BLOQUEAR"
    elif ".." in log_upper or "/ETC/PASSWD" in log_upper:
        categoria_detectada = "Directory Traversal"
        nivel_riesgo = "ALTO"
        decision = "BLOQUEAR"

    # 2. Si no cayó en ninguna firma conocida, dejamos que la IA decida semánticamente
    if not categoria_detectada:
        prompt_analisis = (
            "Analiza el siguiente log de un entorno web corporativo. Determina de manera estricta si es un ataque o tráfico legítimo.\n"
            f"Log: {log_decoded}\n\n"
            "Responde EXCLUSIVAMENTE en formato JSON plano con la siguiente estructura:\n"
            '{"categoria": "Nombre Exacto (SQL Injection, Remote Code Execution (RCE), Cross-Site Scripting (XSS), Directory Traversal, Brute Force, Tráfico Legítimo)", '
            '"riesgo": "CRÍTICO, ALTO, MEDIO o BAJO", '
            '"decision": "BLOQUEAR o PERMITIR"}'
        )
        try:
            response_json = ollama.chat(
                model='llama3.2:1b',
                messages=[{"role": "user", "content": prompt_analisis}],
                options={"temperature": 0.1, "num_predict": 150}
            )
            raw_content = response_json['message']['content'].strip()
            raw_content = re.sub(r'```json|```', '', raw_content).strip()
            
            datos = json.loads(raw_content)
            categoria_detectada = datos.get("categoria", "Tráfico Legítimo")
            nivel_riesgo = datos.get("riesgo", "BAJO")
            decision = datos.get("decision", "PERMITIR")
        except Exception as e:
            print(f"[⚠️ IA ERROR]: Usando contingencia rutinaria: {e}")
            categoria_detectada = "Tráfico Legítimo"

    # 3. MOTOR DE CORRELACIÓN TEMPORAL
    historial_previo = obtener_historial_reciente(client_ip, minutos=5)
    
    if categoria_detectada == "Brute Force":
        intentos_fallidos = len([x for x in historial_previo if "Brute Force" in x])
        if intentos_fallidos >= 2:
            nivel_riesgo = "ALTO"
            decision = "BLOQUEAR"
            print(f"[⚠️ CORRELACIÓN]: Ráfaga detectada ({intentos_fallidos + 1} intentos). Escalando a BLOQUEO.")
        else:
            nivel_riesgo = "MEDIO"
            decision = "PERMITIR"

    contexto_correlacion = (
        f"IP sospechosa con {len(historial_previo)} anomalías previas detectadas."
        if historial_previo else "No registra incidentes previos en esta ventana de tiempo."
    )

    # 4. GENERACIÓN DE TEXTO FORENSE ASOCIADO
    if categoria_detectada not in ["Tráfico Legítimo", "Tráfico Rutinario"]:
        try:
            response_forense = ollama.chat(
                model='llama3.2:1b',
                messages=[
                    {
                        "role": "system",
                        "content": "Eres un Analista SOC Senior. Genera un reporte forense técnico corto (máximo 3 líneas) detallando el peligro del payload y el impacto. Sé directo."
                    },
                    {"role": "user", "content": f"Payload: {log_decoded} | Vector: {categoria_detectada} | Contexto: {contexto_correlacion}"}
                ],
                options={"temperature": 0.2, "num_predict": 180}
            )
            analysis_text = response_forense['message']['content'].strip()
        except:
            analysis_text = f"Alerta preventiva del sistema para el vector {categoria_detectada}."
    else:
        analysis_text = "Tráfico rutinario aprobado. No se detectan anomalías estructurales."

    # 5. ORQUESTACIÓN DEFENSIVA SOAR
    soar_riesgo = "ALTO" if (decision == "BLOQUEAR" and nivel_riesgo == "MEDIO") else nivel_riesgo
    accion_tomada = SaktiSOAR.ejecutar_playbook(
        categoria_ataque=categoria_detectada,
        ip_origen=client_ip,
        nivel_riesgo=soar_riesgo
    )

    if decision == "BLOQUEAR":
        status = "BLOQUEADO"
        simulate_firewall_block(client_ip, f"Orquestación SOAR: {categoria_detectada}")
        # 🔔 CORRECCIÓN DEL DISPARADOR: Si es bloqueado por firma o IA, se envía la alerta real
        send_telegram_alert(categoria_detectada, soar_riesgo, client_ip)
    else:
        status = "PERMITIDO" if categoria_detectada in ["Tráfico Legítimo", "Tráfico Rutinario"] else "REVISIÓN"

    # 6. Guardado consistente en PostgreSQL de producción
    save_report_v2(log_entry, analysis_text, status, client_ip, nivel_riesgo, categoria_detectada, accion_tomada, empresa_name)

    return f"{status} - {nivel_riesgo} ({categoria_detectada})"


def save_report_v2(log_entry, analysis, status, client_ip, nivel_riesgo, categoria, accion_mitigacion, empresa_name):
    """Guarda directamente en PostgreSQL asegurando consistencia absoluta con los nombres de columnas."""
    try:
        conn = get_pg_connection()
        cursor = conn.cursor()
        
        query = """
            INSERT INTO sakti_incidents (created_at, client_ip, resultado_ia, tipo_ataque, nivel_riesgo, alerta_status, log_entry, soar_active, empresa_name)
            VALUES (NOW(), %s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (
            client_ip, 
            analysis, 
            categoria, 
            nivel_riesgo, 
            status, 
            log_entry,
            accion_mitigacion,
            empresa_name
        ))
        conn.commit()
        cursor.close()
        conn.close()
        print(f"[DB - POSTGRES] Incidente guardado con mitigación SOAR activa: {accion_mitigacion}")
    except Exception as e:
        print(f"[❌ DB ERROR]: Error guardando en Postgres estructurado: {e}")