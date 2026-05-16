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

def orchestrator_ai(log_entry, client_ip="192.168.1.50"):
    print(f"[*] Procesando evento desde {client_ip}...")

    prompt = f"""
    Analiza el siguiente LOG de servidor y clasifícalo según el riesgo.
    
    LOG: {log_entry}

    REGLAS:
    - Si contiene '<script>', 'alert(' o HTML -> categoria: "XSS", riesgo: "CRÍTICO", decision: "BLOQUEAR"
    - Si contiene 'OR 1=1', '--' o 'UNION' -> categoria: "SQL Injection", riesgo: "CRÍTICO", decision: "BLOQUEAR"
    - Si contiene '../' o '/etc/passwd' -> categoria: "Directory Traversal", riesgo: "ALTO", decision: "BLOQUEAR"
    - Si es una petición normal -> categoria: "Tráfico Legítimo", riesgo: "BAJO", decision: "PERMITIR"

    DEBES responder EXCLUSIVAMENTE con un objeto JSON válido, sin texto adicional, sin introducciones y sin asteriscos.
    
    FORMATO DE RESPUESTA JSON: {{
        "decision": "BLOQUEAR_O_PERMITIR",
        "riesgo": "NIVEL_DE_RIESGO",
        "categoria": "NOMBRE_CATEGORIA",
        "motivo": "EXPLICACION_CORTA"
    }}
    """

    # Llamada a la IA con rol estricto
    response = ollama.chat(model='llama3.2:1b', messages=[
        {"role": "system", "content": "Eres un firewall que solo responde en formato JSON estricto. No hables, no saludes, solo entrega el objeto JSON."},
        {"role": "user", "content": prompt}
    ])

    # Limpieza inicial del texto recibido
    raw_content = response['message']['content'].strip()
    
    print("-" * 30)
    print(f"Respuesta cruda de la IA:\n{raw_content}")
    print("-" * 30)

    # Valores por defecto en caso de que falle el JSON parse
    decision = "PERMITIR"
    nivel_riesgo = "BAJO"
    categoria_detectada = "Otras Amenazas"
    analysis_text = raw_content

    # Intentamos cargar la respuesta como JSON
    try:
        # Buscamos el bloque JSON por si la IA metió texto extra por error
        json_match = re.search(r"\{.*\}", raw_content, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group(0))
            decision = data.get("decision", "PERMITIR").upper()
            nivel_riesgo = data.get("riesgo", "BAJO").upper()
            categoria_detectada = data.get("categoria", "Otras Amenazas")
            analysis_text = f"Categoría: {categoria_detectada} | Riesgo: {nivel_riesgo} | Motivo: {data.get('motivo', '')}"
    except Exception as e:
        print(f"[⚠️ ERROR PARSING JSON]: Falló el formato de la IA, usando fallback manual. Detalle: {e}")
        # Fallback por si acaso falla el JSON
        if "BLOQUEAR" in raw_content.upper(): decision = "BLOQUEAR"
        if "CRÍTICO" in raw_content.upper(): nivel_riesgo = "CRÍTICO"
        elif "ALTO" in raw_content.upper(): nivel_riesgo = "ALTO"

    # 2. Ejecución de la lógica basada en el JSON limpio
    if "BLOQUEAR" in decision:
        status = "BLOQUEADO"
        simulate_firewall_block(client_ip, f"Ataque detectado: {categoria_detectada}")
        
        # Filtro estricto de Telegram
        if nivel_riesgo in ["ALTO", "CRÍTICO"]:
            send_telegram_alert(categoria_detectada, nivel_riesgo, client_ip)
    else:
        status = "PERMITIDO"

    # 4. Guardamos todo pasando los datos limpios directamente
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