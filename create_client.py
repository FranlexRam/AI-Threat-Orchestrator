import sqlite3
import secrets
import sys

DB_NAME = "security_vault.db"

def inicializar_tabla_clientes():
    """Crea la tabla de clientes SaaS si no existe en la base de datos central."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # 🟢 CORRECCIÓN: Cambiado 'NOT EXISTS' por 'NOT NULL' en las columnas
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sakti_customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            empresa_name TEXT NOT NULL UNIQUE,
            api_key TEXT NOT NULL UNIQUE,
            estatus TEXT DEFAULT 'ACTIVO',
            fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def generar_cliente_saas(nombre_empresa: str):
    """Genera un token criptográfico único y registra al nuevo cliente corporativo."""
    inicializar_tabla_clientes()
    
    # Generamos un token seguro y aleatorio con prefijo identificable de SaktiShield
    token_aleatorio = secrets.token_hex(24)
    api_key_segura = f"sakti_live_{token_aleatorio}"
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO sakti_customers (empresa_name, api_key) VALUES (?, ?)",
            (nombre_empresa, api_key_segura)
        )
        conn.commit()
        print("\n" + "="*60)
        print(f"🚀 ¡NUEVO CLIENTE SAAS REGISTRADO CON ÉXITO!")
        print("="*60)
        print(f"🏢 Empresa: {nombre_empresa}")
        print(f"🔑 X-Sakti-Token: {api_key_segura}")
        print("="*60)
        print("💡 Copia este token y entrégaselo de forma segura a tu cliente.")
        
    except sqlite3.IntegrityError:
        print(f"\n❌ ERROR: La empresa '{nombre_empresa}' ya se encuentra registrada en el sistema.")
    finally:
        conn.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\n⚠️ Uso correcto: python3 create_client.py \"Nombre de la Empresa\"")
    else:
        nombre = sys.argv[1]
        generar_cliente_saas(nombre)