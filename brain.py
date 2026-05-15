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
    match = re.search(r"CATEGORÍA:\s*(.*)", reporte)
    return match.group(1).strip() if match else "Otras Amenazas"

def orchestrator_ai(log_entry, client_ip="192.168.1.50"):
    print(f"[*] Procesando evento desde {client_ip}...")

    prompt = f"""
    SISTEMA DE DETECCIÓN DE INTRUSOS. Analiza el siguiente LOG y responde siguiendo REGLAS ESTRICTAS.
    LOG: {log_entry}

    REGLAS DE CLASIFICACIÓN:
    1. Si el LOG contiene '<script>', 'alert(', o etiquetas HTML: CATEGORÍA: XSS | RIESGO: CRÍTICO | DECISIÓN: BLOQUEAR.
    2. Si el LOG contiene 'OR 1=1', '--', o 'UNION SELECT': CATEGORÍA: SQL INJECTION | RIESGO: CRÍTICO | DECISIÓN: BLOQUEAR.
    3. Si el LOG contiene '../', '/etc/passwd' o 'boot.ini': CATEGORÍA: DIRECTORY TRAVERSAL | RIESGO: ALTO | DECISIÓN: BLOQUEAR.
    4. Si el LOG es una petición normal (ej. /about, /contact, /index): CATEGORÍA: LEGÍTIMO | RIESGO: BAJO | DECISIÓN: PERMITIR.

    INSTRUCCIÓN DE LENGUAJE: Responde EXCLUSIVAMENTE en ESPAÑOL TÉCNICO. Prohibido inventar palabras.

    FORMATO DE RESPUESTA (OBLIGATORIO):
    DECISIÓN: [BLOQUEAR o PERMITIR]
    NIVEL DE RIESGO: [CRÍTICO, ALTO, MEDIO o BAJO]
    CATEGORÍA: [Nombre de la categoría]
    MOTIVO: [Explicación técnica de 10 palabras máximo]

    """

    # Llamada a la IA usando la variable 'prompt'
    response = ollama.chat(model='llama3.2:1b', messages=[
        {"role": "system", "content": "Eres un analista de seguridad estricto. No converses, solo clasifica."},
        {"role": "user", "content": prompt} # <--- Aquí usamos el prompt con las reglas
    ])

    # Limpiamos asteriscos y espacios que rompen los 'if'
    analysis = response['message']['content'].replace("*", "").strip()
    
    # Imprimimos el análisis en consola para que lo veas
    print("-" * 30)
    print(analysis)
    print("-" * 30)

    # Convertimos a mayúsculas una sola vez para comparar fácil
    analysis_upper = analysis.upper()

    # 1. Determinamos el nivel de riesgo
    if "CRÍTICO" in analysis_upper: nivel_riesgo = "CRÍTICO"
    elif "ALTO" in analysis_upper: nivel_riesgo = "ALTO"
    elif "MEDIO" in analysis_upper: nivel_riesgo = "MEDIO"
    else: nivel_riesgo = "BAJO"

    # 2. Decidimos si bloqueamos buscando la palabra exacta
    if "BLOQUEAR" in analysis_upper:
        status = "BLOQUEADO"
        simulate_firewall_block(client_ip, "Ataque detectado por IA")
        
        # 3. Filtro estricto de Telegram
        if nivel_riesgo in ["ALTO", "CRÍTICO"]:
            # Usamos extraer_categoria para que el mensaje de Telegram sea bonito
            cat = extraer_categoria(analysis)
            send_telegram_alert(cat, nivel_riesgo, client_ip)
    else:
        status = "PERMITIDO"

    # 4. Guardamos todo pasando el nivel_riesgo que ya calculamos
    save_report(log_entry, analysis, status, client_ip, nivel_riesgo)

    return f"{status} - {nivel_riesgo}"

def save_report(log_entry, analysis, status, client_ip, nivel_riesgo):
    # La categoría la seguimos extrayendo del texto
    categoria_detectada = extraer_categoria(analysis)

    conn = sqlite3.connect('security_vault.db')
    cursor = conn.cursor()
    cursor.execute('''
            INSERT INTO incidentes (fecha, ip_origen, analisis_ia, categoria, nivel_riesgo, estatus, log_original)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
            client_ip, 
            analysis, 
            categoria_detectada, 
            nivel_riesgo, 
            status, 
            log_entry
        ))
    conn.commit()
    conn.close()
    print(f"[DB] Incidente guardado como {status} ({nivel_riesgo})")

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