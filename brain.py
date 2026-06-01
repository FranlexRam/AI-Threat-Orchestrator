#from datetime import datetime
import re
import socket
import ollama
import datetime
import os
import json
import sqlite3
import requests
import urllib.parse
from dotenv import load_dotenv

# 🚀 PASO 2 (IMPORTACIÓN): Traemos el módulo avanzado SOAR que programamos
from orchestrator_core import SaktiSOAR

# Cargar las variables del archivo .env
load_dotenv()

def init_db():
    conn = sqlite3.connect('security_vault.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidentes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_origen TEXT,
            analisis_ia TEXT,
            categoria TEXT,
            nivel_riesgo TEXT,
            estatus TEXT,
            log_original TEXT,
            accion_mitigacion TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# --- 🧠 MOTOR DE CORRELACIÓN DE EVENTOS ---
def obtener_historial_reciente(client_ip, minutos=5):
    """
    Consulta la base de datos para ver si la IP atacó o falló autenticación recientemente.
    """
    conn = sqlite3.connect('security_vault.db')
    cursor = conn.cursor()
    
    query = """
        SELECT categoria FROM incidentes 
        WHERE ip_origen = ? 
        AND categoria != 'Tráfico Legítimo'
        AND fecha >= datetime('now', '-5 minutes', 'localtime')
    """
    try:
        cursor.execute(query, (client_ip,))
        resultados = cursor.fetchall()
        historial = [fila[0] for fila in resultados]
    except Exception as e:
        print(f"[⚠️ CORRELACIÓN ERROR]: No se pudo leer el historial: {e}")
        historial = []
    finally:
        conn.close()
        
    return historial


# Función de Telegram Alert
def send_telegram_alert(categoria, riesgo, ip):
    """Envía una alerta de seguridad estructurada a Telegram"""
    token = os.getenv("TELEGRAM_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    
    mensaje = (
        f"🚨 *ALERTA DE SEGURIDAD* 🚨\n\n"
        f"🛡️ *SaktiShield ha detectado un ataque*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"📂 *Categoría:* {categoria}\n"
        f"⚠️ *Nivel de Riesgo:* {riesgo}\n"
        f"🌐 *IP Atacante:* {ip}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"⚡ _Acción: IP Bloqueada en Firewall._"
    )
    
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": mensaje,
        "parse_mode": "Markdown"
    }
    
    try:
        response = requests.post(url, data=payload)
        if response.status_code == 200:
            print(f"[OK]: Alerta enviada a tu iPhone con éxito.")
        else:
            print(f"[ERROR]: Telegram respondió con código {response.status_code}")
    except Exception as e:
        print(f"[ERROR]: Fallo crítico en el envío de alerta: {e}")
    
BLACKLIST_FILE = "blacklist.txt"

def simulate_firewall_block(ip, reason):
    """Simula la ejecución de una regla de IPTables o Firewall."""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(BLACKLIST_FILE, "a") as f:
        f.write(f"{ip} | {timestamp} | Razón: {reason}\n")
    print(f"\n[SISTEMA]: 🛡️ EJECUTANDO BLOQUEO: La IP {ip} ha sido enviada al Firewall.")

def orchestrator_ai(log_entry, client_ip="192.168.1.50"):
    print(f"[*] Procesando evento desde {client_ip}...")

    # 1. NORMALIZACIÓN AVANZADA
    log_decoded = urllib.parse.unquote(log_entry).replace('+', ' ')
    log_upper = log_decoded.upper()
    es_ataque = True
    
    # 2. MOTOR DE FIRMAS MEJORADO CON REGEX
    if re.search(r"<SCRIPT|SCRIPT>|ALERT\(|ONLOAD=|ONERROR=|<[A-Z]+>", log_upper):
        categoria_detectada = "XSS (Cross-Site Scripting)"
        nivel_riesgo = "CRÍTICO"
        decision = "BLOQUEAR"
   
    elif re.search(r"UNION\(?(\/\*.*\*\/|\s)+SELECT", log_upper) or \
         re.search(r"OR(\/\*.*\*\/|\s)+\d+=\d+", log_upper) or \
         any(k in log_upper for k in ["SELECT ", "--"]):
        categoria_detectada = "SQL Injection"
        nivel_riesgo = "CRÍTICO"
        decision = "BLOQUEAR"
        
    elif re.search(r"\.\.\/|\.\.\\|/ETC/PASSWD|BOOT\.INI|WIN\.INI", log_upper):
        categoria_detectada = "Directory Traversal"
        nivel_riesgo = "ALTO"
        decision = "BLOQUEAR"

    elif re.search(r"(;|&&|\|\||\|)[\s\+]*_*(WHOAMI|CAT\s+|ID|UNAME|DIR|IPCONFIG|WGET|CURL)", log_upper):
        categoria_detectada = "Remote Code Execution (RCE)"
        nivel_riesgo = "CRÍTICO"
        decision = "BLOQUEAR"

    elif re.search(r"(LOCALHOST|127\.0\.0\.1|169\.254\.169\.254)", log_upper) and \
         any(k in log_upper for k in ["URL=", "URI=", "PATH=", "DEST=", "REDIRECT="]):
        categoria_detectada = "SSRF Attack (Server-Side Request Forgery)"
        nivel_riesgo = "ALTO"
        decision = "BLOQUEAR"    

    # 🎯 NUEVA FIRMA: Captura intentos fallidos de inicio de sesión de forma proactiva
    elif any(k in log_upper for k in ["FAILED LOGIN", "INVALID CREDENTIALS", "ACCESS DENIED"]) or "ATTEMPT" in log_upper:
        categoria_detectada = "Brute Force"
        nivel_riesgo = "MEDIO"
        decision = "EVALUAR" # Deja que la correlación temporal decida si bloquea
        
    else:
        es_ataque = False
        categoria_detectada = "Tráfico Legítimo"
        nivel_riesgo = "BAJO"
        decision = "PERMITIR"

    # 3. CONTEXTO DE CORRELACIÓN Y GENERACIÓN DE REPORTES SOC CON IA
    if categoria_detectada != "Tráfico Legítimo":
        # Extraemos lo que hizo esta IP en los últimos 5 minutos
        historial_previo = obtener_historial_reciente(client_ip, minutos=5)
        
        # Lógica de escalamiento por volumen (Fuerza Bruta)
        if categoria_detectada == "Brute Force" and len(historial_previo) >= 3:
            nivel_riesgo = "ALTO"
            decision = "BLOQUEAR"
            print(f"[⚠️ ALERTA]: Fuerza Bruta Confirmada por volumen desde {client_ip}. Escalando a BLOQUEO.")
            
        if historial_previo:
            contexto_correlacion = f"¡IP REINCIDENTE! Ha generado {len(historial_previo)} alertas previas de tipo: {', '.join(historial_previo)}."
        else:
            contexto_correlacion = "No registra incidentes previos en la ventana de tiempo analizada."

        try:
            response = ollama.chat(
                model='llama3.2:1b',
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "Eres un Analista de Ciberseguridad SOC Senior de SaktiShield. Tu tarea es generar un reporte "
                            "forense altamente descriptivo, analítico y profesional (máximo 4 líneas). "
                            "Debes detallar qué busca el atacante con este vector técnico y evaluar la gravedad considerando el historial provisto. "
                            "Sé directo, técnico y preciso, sin introducciones corporativas ni saludos."
                        )
                    },
                    {
                        "role": "user",
                        "content": f"Log de Evento: {log_decoded} | Vector Detectado: {categoria_detectada} | Contexto de Correlación: {contexto_correlacion}"
                    }
                ],
                options={
                    "temperature": 0.3,
                    "top_p": 0.8,
                    "num_predict": 200
                }
            )
            motivo_ia = response['message']['content'].strip().replace("'", '"')
        except Exception as e:
            motivo_ia = f"Análisis Automático: Actividad anómala confirmada para la firma {categoria_detectada}."
    else:
        motivo_ia = "Tráfico rutinario aprobado. No se detectaron anomalías estructurales ni firmas de inyección de código."

    # 🟢 LIMPIEZA: Guardamos únicamente el reporte puro de la IA sin metadatos redundantes
    analysis_text = motivo_ia

    # 4. APLICACIÓN DE POLÍTICAS EN EL FIREWALL & INTEGRACIÓN SOAR
    accion_tomada = SaktiSOAR.ejecutar_playbook(
        categoria_ataque=categoria_detectada,
        ip_origen=client_ip,
        nivel_riesgo=nivel_riesgo
    )

    if decision == "BLOQUEAR":
        status = "BLOQUEADO"
        simulate_firewall_block(client_ip, f"Firma detectada: {categoria_detectada}")
        if nivel_riesgo in ["ALTO", "CRÍTICO"]:
            send_telegram_alert(categoria_detectada, nivel_riesgo, client_ip)
    elif decision == "EVALUAR":
        status = "REVISIÓN"
    else:
        status = "PERMITIDO"

    # 5. Guardado en la base de datos
    save_report_v2(log_entry, analysis_text, status, client_ip, nivel_riesgo, categoria_detectada, accion_tomada)

    return f"{status} - {nivel_riesgo} ({categoria_detectada})"

def save_report_v2(log_entry, analysis, status, client_ip, nivel_riesgo, categoria, accion_mitigacion):
    conn = sqlite3.connect('security_vault.db')
    cursor = conn.cursor()
    cursor.execute('''
            INSERT INTO incidentes (fecha, ip_origen, analisis_ia, categoria, nivel_riesgo, estatus, log_original, accion_mitigacion)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
            client_ip, 
            analysis, 
            categoria, 
            nivel_riesgo, 
            status, 
            log_entry,
            accion_mitigacion
        ))
    conn.commit()
    conn.close()
    print(f"[DB] Incidente guardado con mitigación activa: {accion_mitigacion}")

def start_listener():
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.bind(('0.0.0.0', 9999))
    servidor.listen(1)
    
    print("\n" + "="*50)
    print("[*] ORQUESTRADOR ACTIVO: Escuchando en el puerto 9999...")
    print("[*] Esperando señales de ataque...")
    print("="*50 + "\n")
    
    while True:
        cliente, direccion = servidor.accept()
        log_recibido = cliente.recv(1024).decode('utf-8')
        
        if log_recibido:
            resultado = orchestrator_ai(log_recibido, client_ip=direccion[0])
            print(f"\n[DECISIÓN FINAL]:\n{resultado}")
            print("\n" + "-"*30 + "\n[*] Esperando siguiente evento...")
            
        cliente.close()

if __name__ == "__main__":
    start_listener()