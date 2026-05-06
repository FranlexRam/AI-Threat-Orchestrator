import socket
import ollama
import datetime
import os
import json

def save_report(log, report, status):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Creamos una estructura de datos profesional
    incident_data = {
        "timestamp": timestamp,
        "status": status,
        "log_original": log,
        "analisis_ia": report
    }
    
    # Guardamos en un archivo .json (modo append no es nativo en JSON, así que usamos líneas)
    with open("incident_report.json", "a") as f:
        f.write(json.dumps(incident_data) + "\n")
    
    print(f"[REPORTE]: Guardado exitosamente en incident_report.json")

# Archivo que funcionará como nuestra "Lista Negra"
BLACKLIST_FILE = "blacklist.txt"

def simulate_firewall_block(ip, reason):
    """Simula la ejecución de una regla de IPTables o Firewall."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(BLACKLIST_FILE, "a") as f:
        f.write(f"{ip} | {timestamp} | Razón: {reason}\n")
    print(f"\n[SISTEMA]: 🛡️ EJECUTANDO BLOQUEO: La IP {ip} ha sido enviada al Firewall.")

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
        save_report(log_entry, analysis, "BLOQUEADO")
    else:
        save_report(log_entry, analysis, "PERMITIDO")

    return analysis

def save_report(log, report, status):
    import json
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    data = {
        "timestamp": timestamp,
        "log_original": log,
        "analisis_ia": report,
        "estado": status
    }
    
    file_name = "incident_report.json"
    
    with open(file_name, "a", encoding='utf-8') as f:
        f.write(json.dumps(data, ensure_ascii=False) + "\n")
        f.flush() # Esto obliga al sistema a escribir en el disco inmediatamente

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