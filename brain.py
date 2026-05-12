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
    Eres un Analista de Ciberseguridad de Nivel 3. Analiza el siguiente log:
    {log_entry}

    REGLAS DE ORO:
    INSTRUCCIONES DE CLASIFICACIÓN:
    1. CATEGORÍA: Clasifica EXCLUSIVAMENTE como: [SQL INJECTION, XSS, DIRECTORY TRAVERSAL, BRUTE FORCE, DOS, o LEGÍTIMO].
    2. NIVEL DE RIESGO: Clasifica como: [CRÍTICO, ALTO, MEDIO, o BAJO].
    3. DECISIÓN: Si el riesgo es ALTO o CRÍTICO, la decisión DEBE ser BLOQUEAR.
    4. Si detectas patrones de SQL Injection (OR '1'='1', UNION SELECT, etc.) o XSS (etiquetas <script>, alert, event handlers), la DECISIÓN debe ser obligatoriamente: BLOQUEAR.
    5. No ignores ataques "simples"; cualquier intento de manipulación se considera malicioso.
    - Si hay ' OR '1'='1 es SQL INJECTION.
    - Si hay <script> o alert es XSS.
    - Si es normal es TRÁFICO LEGÍTIMO.

    RESPONDE ÚNICAMENTE CON ESTE FORMATO:
    DECISIÓN: [BLOQUEAR o PERMITIR]
    NIVEL DE RIESGO: [CRÍTICO, ALTO, MEDIO o BAJO]
    CATEGORÍA: [Nombre de la vulnerabilidad]
    MOTIVO: [Breve explicación técnica]
    ...
    """

    # Llamada a la IA
    response = ollama.chat(model='llama3.2:1b', messages=[
        {"role": "system", "content": "Eres un experto en ciberseguridad. Analiza el siguiente log y determina si es un ataque. Responde SIEMPRE con este formato exacto:\nDECISIÓN: [BLOQUEAR/PERMITIR]\nNIVEL DE RIESGO: [ALTO/MEDIO/BAJO]\nCATEGORÍA: [Nombre de la categoría]\nMOTIVO: [Breve explicación]"},
        {"role": "user", "content": log_entry}
    ])

    analysis = response['message']['content']
    
    # Imprimimos el análisis en consola para que lo veas
    print("-" * 30)
    print(analysis)
    print("-" * 30)

    # Lógica de Orquestación: Si la IA dice "Bloquear", el sistema actúa
    if "BLOQUEAR" in analysis.upper():
        simulate_firewall_block(client_ip, "Ataque detectado por IA")

        #Llamando función de Telegram Alert
        send_telegram_alert("Ataque Web Detectado", "ALTO", client_ip)
        # Solo enviar a Telegram si el riesgo es importante
        #**NUEVO ARREGLO TELEGRAM ALERT:
        # if send_telegram_alert in ["ALTO", "CRÍTICO"]:
        #     send_telegram_alert(f"🚨 ALERTA SAKTISHIELD\nTipo: {categoria}\nRiesgo: {send_telegram_alert}\nAcción: {decision}")
        #     print(f"[OK] Notificación enviada por riesgo {send_telegram_alert}")
        # else:
        #     print(f"[INFO] Riesgo {send_telegram_alert}: No se requiere notificación.")
    
        save_report(log_entry, analysis, "BLOQUEADO", client_ip) 
    else:
    
        save_report(log_entry, analysis, "PERMITIDO", client_ip)

    return analysis

def save_report(log_entry, analysis, status, client_ip):
    # Extraemos la categoría y el riesgo del análisis de la IA

    # Buscamos "NIVEL DE RIESGO" ignorando mayúsculas y con espacios flexibles
    match_riesgo = re.search(r"NIVEL DE RIESGO\s*:?\s*(\w+)", analysis, flags=re.IGNORECASE)  
    # Si lo encuentra, lo pone en mayúsculas. Si no, pone REVISAR.
    #**Nueva actualización aqui:
    # Si la IA dice BLOQUEAR, el riesgo es ALTO por defecto, si no, lo extraemos.
    if "BLOQUEAR" in analysis.upper():
        nivel_riesgo = "ALTO"
    else:
        nivel_riesgo = match_riesgo.group(1).upper() if match_riesgo else "BAJO"

    categoria_detectada = extraer_categoria(analysis)
    
    riesgo_match = re.search(r"NIVEL DE RIESGO:\s*(\w+)", analysis)


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
    print(f"[DB] Incidente guardado exitosamente en security_vault.db")

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