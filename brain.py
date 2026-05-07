import socket
import ollama
import datetime
import os
import json

import sqlite3 # Agrégala al principio

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
            nivel_riesgo TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db() # Llama a la función aquí mismo

def save_report(log, report, status):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Creamos una estructura de datos profesional
    incident_data = {
        "timestamp": timestamp,
        "status": status,
        "log_original": log,
        "analisis_ia": report
    }
    
# Archivo que funcionará como nuestra "Lista Negra"
BLACKLIST_FILE = "blacklist.txt"

def simulate_firewall_block(ip, reason):
    """Simula la ejecución de una regla de IPTables o Firewall."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(BLACKLIST_FILE, "a") as f:
        f.write(f"{ip} | {timestamp} | Razón: {reason}\n")
    print(f"\n[SISTEMA]: 🛡️ EJECUTANDO BLOQUEO: La IP {ip} ha sido enviada al Firewall.")

def extraer_categoria(texto):
    texto = texto.upper()
    if "SQL" in texto: return "Inyección SQL"
    if "MALWARE" in texto: return "Malware"
    if "ACCESO" in texto or "UNAUTHORIZED" in texto: return "Acceso No Autorizado"
    if "SCAN" in texto or "ESCANEO" in texto: return "Escaneo de Puertos"
    if "BRUTE FORCE" in texto or "FUERZA BRUTA" in texto: return "Fuerza Bruta"
    return "Otras Amenazas"    

def orchestrator_ai(log_entry, client_ip="192.168.1.50"):
    print(f"[*] Procesando evento desde {client_ip}...")

    prompt = f"""
    Eres un analista SOC Nivel 3. Analiza este log: '{log_entry}'
    Responde estrictamente con este formato:
    CATEGORÍA: [Nombre]
    NIVEL DE RIESGO: [Bajo/Medio/Alto]
    ACCIÓN: [Bloquear/Ignorar]
    RESUMEN: [Una frase]
    """

    # Llamada a la IA
    response = ollama.chat(model='llama3.2:1b', messages=[
        {'role': 'user', 'content': prompt},
    ])

    analysis = response['message']['content']
    
    # Imprimimos el análisis en consola para que lo veas
    print("-" * 30)
    print(analysis)
    print("-" * 30)

    # Lógica de Orquestación: Si la IA dice "Bloquear", el sistema actúa
    if "Bloquear" in analysis:
        simulate_firewall_block(client_ip, "Ataque detectado por IA")
    # MODIFICA ESTA LÍNEA (90):
        save_report(log_entry, analysis, "BLOQUEADO", client_ip) 
    else:
    # MODIFICA ESTA LÍNEA (93):
        save_report(log_entry, analysis, "PERMITIDO", client_ip)

    return analysis

def save_report(log, report, status, client_ip):
    # Extraemos la categoría y el riesgo del análisis de la IA
    # (Usaremos la función extraer_categoria que añadiremos abajo)
    categoria_detectada = extraer_categoria(report)
    nivel_riesgo = "ALTO" if "Bloquear" in status else "MEDIO"

    conn = sqlite3.connect('security_vault.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO incidentes (ip_origen, analisis_ia, categoria, nivel_riesgo)
        VALUES (?, ?, ?, ?)
    ''', (client_ip, report, categoria_detectada, nivel_riesgo))
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