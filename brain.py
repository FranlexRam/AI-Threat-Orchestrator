import ollama
import datetime
import os

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
    
    response = ollama.chat(model='llama3.2:1b', messages=[
        {'role': 'user', 'content': prompt},
    ])
    
    analysis = response['message']['content']
    
    # Lógica de Orquestación: Si la IA dice "Bloquear", el sistema actúa
    if "Bloquear" in analysis:
        simulate_firewall_block(client_ip, "Ataque detectado por IA")
        save_report(log_entry, analysis, "BLOQUEADO")
    else:
        save_report(log_entry, analysis, "PERMITIDO")
    
    return analysis

def save_report(log, report, status):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("incident_report.txt", "a") as f:
        f.write(f"--- EVENTO {status}: {timestamp} ---\nLOG: {log}\n{report}\n{'-'*40}\n")

if __name__ == "__main__":
    logs_finales = [
        "GET /search?id=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1", # XSS Codificado en URL
        "POST /api/v1/users HTTP/1.1 -- data: {'user': 'admin', 'pass': {'$ne': null}}", # Intento de NoSQL Injection
        "GET /wp-admin/setup-config.php HTTP/1.1", # Escaneo de vulnerabilidades conocido
        "GET /assets/logo.png HTTP/1.1" # Tráfico legítimo
    ]
    
    print(f"--- PRUEBA DE ESTRÉS FINAL ---")
    for i, log in enumerate(logs_finales):
        ip_test = f"10.0.0.{50 + i}"
        orchestrator_ai(log, ip_test)
    
    print(f"\n--- MONITOREO FINALIZADO. REVISA TU BLACKLIST Y REPORTES ---")