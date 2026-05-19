#from datetime import datetime
import re
import socket
import ollama
import datetime
import os
import json
import sqlite3
import requests
from dotenv import load_dotenv

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
            log_original TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db() # Llama a la función aquí mismo

#Función de Telegram Alert
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
    
# Archivo que funcionará como nuestra "Lista Negra"
BLACKLIST_FILE = "blacklist.txt"

def simulate_firewall_block(ip, reason):
    """Simula la ejecución de una regla de IPTables o Firewall."""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(BLACKLIST_FILE, "a") as f:
        f.write(f"{ip} | {timestamp} | Razón: {reason}\n")
    print(f"\n[SISTEMA]: 🛡️ EJECUTANDO BLOQUEO: La IP {ip} ha sido enviada al Firewall.")

def extraer_categoria(reporte):
    # Convertimos a mayúsculas para que la búsqueda no falle por minúsculas
    reporte_up = reporte.upper()
    
    # Búsqueda por palabras clave (Mucho más seguro que Regex rígido)
    if "SQL INJECTION" in reporte_up:
        return "SQL Injection"
    elif "XSS" in reporte_up or "SCRIPT" in reporte_up:
        return "XSS (Cross-Site Scripting)"
    elif "DIRECTORY TRAVERSAL" in reporte_up or "PASSWD" in reporte_up:
        return "Directory Traversal"
    elif "BRUTE FORCE" in reporte_up:
        return "Brute Force"
    elif "DOS" in reporte_up or "DENIAL OF SERVICE" in reporte_up:
        return "Denial of Service"
    elif "LEGÍTIMO" in reporte_up or "PERMITIR" in reporte_up:
        return "Tráfico Legítimo"
    
    # Si nada de lo anterior funciona, intentamos el Regex como último recurso
    match = re.search(r"CATEGORÍA:\s*(.*)", reporte, re.IGNORECASE)
    if match:
        return match.group(1).strip()
        
    return "Otras Amenazas"

import urllib.parse  # Asegúrate de tener esta importación al inicio del archivo si no está

def orchestrator_ai(log_entry, client_ip="192.168.1.50"):
    print(f"[*] Procesando evento desde {client_ip}...")

    # 1. NORMALIZACIÓN AVANZADA: Decodificamos caracteres URL y forzamos el reemplazo de '+' por espacios reales
    log_decoded = urllib.parse.unquote(log_entry).replace('+', ' ')
    log_upper = log_decoded.upper()
    
    es_ataque = True
    
    # 2. MOTOR DE FIRMAS MEJORADO CON REGEX (Indestructible a variaciones de formato)
    # Detecta <script, script>, alert(, onload=, onerror=, o cualquier etiqueta HTML básica
    
    # Vector 1: XSS
    if re.search(r"<SCRIPT|SCRIPT>|ALERT\(|ONLOAD=|ONERROR=|<[A-Z]+>", log_upper):
        categoria_detectada = "XSS (Cross-Site Scripting)"
        nivel_riesgo = "CRÍTICO"
        decision = "BLOQUEAR"

    # Vector 2: SQL Injection    
    elif re.search(r"UNION\(?(\/\*.*\*\/|\s)+SELECT", log_upper) or \
         re.search(r"OR(\/\*.*\*\/|\s)+\d+=\d+", log_upper) or \
         any(k in log_upper for k in ["SELECT ", "--"]):
        categoria_detectada = "SQL Injection"
        nivel_riesgo = "CRÍTICO"
        decision = "BLOQUEAR"
        
    # Vector 3: Directory Traversal (Mejorado con Regex para variaciones de barras)
    elif re.search(r"\.\.\/|\.\.\\|/ETC/PASSWD|BOOT\.INI|WIN\.INI", log_upper):
        categoria_detectada = "Directory Traversal"
        nivel_riesgo = "ALTO"
        decision = "BLOQUEAR"

    # Vector 4: Remote Code Execution (RCE)
    # Detecta de forma estricta metacaracteres de encadenamiento (; , &&, ||, |) seguidos de comandos del sistema
    elif re.search(r"(;|&&|\|\||\|)[\s\+]*_*(WHOAMI|CAT\s+|ID|UNAME|DIR|IPCONFIG|WGET|CURL)", log_upper):
        categoria_detectada = "Remote Code Execution (RCE)"
        nivel_riesgo = "CRÍTICO"
        decision = "BLOQUEAR"

    # Vector 5: SSRF (Server-Side Request Forgery)
    # Detecta cuando intentan forzar al servidor a mirar a su propia red local o metadatos de nube
    elif re.search(r"(LOCALHOST|127\.0\.0\.1|169\.254\.169\.254)", log_upper) and \
         any(k in log_upper for k in ["URL=", "URI=", "PATH=", "DEST=", "REDIRECT="]):
        categoria_detectada = "SSRF Attack"
        nivel_riesgo = "ALTO"
        decision = "BLOQUEAR"    
        
    else:
        # Si está completamente limpio, pasa directo sin tocar la IA
        es_ataque = False
        categoria_detectada = "Tráfico Legítimo"
        nivel_riesgo = "BAJO"
        decision = "PERMITIR"

    # 3. GENERACIÓN DE REPORTES SOC EXTENSOS CON LA IA
    if es_ataque:
        tiempo_actual = datetime.datetime.now().strftime('%Y-%m-%d a las %H:%M:%S')
        
        try:
            # Usamos ollama.chat para separar de forma estricta el rol del sistema y el evento
            response = ollama.chat(
                model='llama3.2:1b',
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "Eres un Ingeniero Forense de Ciberseguridad Nivel 3. Tu tarea es redactar un "
                            "único párrafo extenso, continuo y altamente técnico que explique el incidente. "
                            "Debes detallar con lenguaje severo qué comandos o caracteres del payload son peligrosos, "
                            "cuál es el peligro real para el servidor si no se bloquea y cómo mitiga SaktiShield. "
                            "IMPORTANTE: No uses viñetas, no dejes campos vacíos, no repitas los datos del evento, "
                            "ve directo al análisis pericial profundo."
                        )
                    },
                    {
                        "role": "user",
                        "content": (
                            f"Fecha: {tiempo_actual}\n"
                            f"Vector: {categoria_detectada}\n"
                            f"Riesgo: {nivel_riesgo}\n"
                            f"Payload a analizar: {log_decoded}"
                        )
                    }
                ],
                options={
                    "temperature": 0.4,      # Mantiene al modelo enfocado y técnico
                    "top_p": 0.85,
                    "num_predict": 450       # Espacio suficiente para un párrafo robusto sin cortarse
                }
            )
            
            motivo_ia = response['message']['content'].strip().replace("'", '"')
            
        except Exception as e:
            motivo_ia = f"Análisis automatizado de emergencia: Detección de firma coincidente con {categoria_detectada} en los filtros de SaktiShield."
    else:
        motivo_ia = "Solicitud web rutinaria y segura analizada por el núcleo analítico de SaktiShield. No se encontraron anomalías estructurales ni firmas de inyección de código. Tráfico aprobado."

    # Formateamos el bloque de análisis limpio eliminando duplicados mecánicos
    analysis_text = f"Categoría: {categoria_detectada} | Riesgo: {nivel_riesgo} | Análisis Forense: {motivo_ia}"

    # 4. APLICACIÓN DE POLÍTICAS EN EL FIREWALL
    if decision == "BLOQUEAR":
        status = "BLOQUEADO"
        simulate_firewall_block(client_ip, f"Firma detectada: {categoria_detectada}")
        
        if nivel_riesgo in ["ALTO", "CRÍTICO"]:
            send_telegram_alert(categoria_detectada, nivel_riesgo, client_ip)
    else:
        status = "PERMITIDO"

    # 5. Guardado en la base de datos
    save_report_v2(log_entry, analysis_text, status, client_ip, nivel_riesgo, categoria_detectada)

    return f"{status} - {nivel_riesgo} ({categoria_detectada})"

def save_report_v2(log_entry, analysis, status, client_ip, nivel_riesgo, categoria):
    conn = sqlite3.connect('security_vault.db')
    cursor = conn.cursor()
    cursor.execute('''
            INSERT INTO incidentes (fecha, ip_origen, analisis_ia, categoria, nivel_riesgo, estatus, log_original)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
            client_ip, 
            analysis, 
            categoria, 
            nivel_riesgo, 
            status, 
            log_entry
        ))
    conn.commit()
    conn.close()
    print(f"[DB] Incidente guardado como {status} ({nivel_riesgo}) -> Categoría: {categoria}")

def start_listener():
    # Creamos el socket (nuestra antena de red)
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Escuchamos en todas las interfaces del Mac en el puerto 9999
    servidor.bind(('0.0.0.0', 9999))
    servidor.listen(1)
    
    print("\n" + "="*50)
    print("[*] ORQUESTRADOR ACTIVO: Escuchando en el puerto 9999...")
    print("[*] Esperando señales de ataque desde Kali Linux.")
    print("="*50 + "\n")
    
    while True:
        # Aceptamos la conexión de Kali
        cliente, direccion = servidor.accept()
        # Recibimos el mensaje
        log_recibido = cliente.recv(1024).decode('utf-8')
        
        if log_recibido:
            # Mandamos el log a la IA
            resultado = orchestrator_ai(log_recibido, client_ip=direccion[0])
            print(f"\n[DECISIÓN FINAL]:\n{resultado}")
            print("\n" + "-"*30 + "\n[*] Esperando siguiente evento...")
            
        cliente.close()

if __name__ == "__main__":
    start_listener()