# migrate_to_postgres.py
import sqlite3
import psycopg2
import os
from dotenv import load_dotenv

# Cargamos las variables del .env local
load_dotenv()

SQLITE_DB = "security_vault.db"

def migrar_sistema():
    print("\n🚀 INICIANDO MIGRACIÓN CRUCIAL — SAKTISHIELD SaaS 🚀")
    print("-" * 60)
    
    # 1. Validar existencia de la DB vieja
    if not os.path.exists(SQLITE_DB):
        print(f"❌ Error: No se encontró el archivo local '{SQLITE_DB}' para migrar.")
        return

    # 2. Conectar a PostgreSQL usando el archivo .env
    try:
        pg_conn = psycopg2.connect(
            host=os.getenv("DB_HOST", "localhost"),
            database=os.getenv("DB_NAME", "saktishield_production"),
            user=os.getenv("DB_USER", "sakti_admin"),
            password=os.getenv("DB_PASSWORD", "SaktiSecurePassword2026!"),
            port=os.getenv("DB_PORT", "5432")
        )
        pg_cursor = pg_conn.cursor()
        print("🐘 Conexión exitosa al clúster de PostgreSQL.")
    except Exception as e:
        print(f"❌ Error al conectar a PostgreSQL: {e}")
        return

    try:
        # 3. CREAR LA TABLA EN POSTGRESQL (Si no existe)
        print("🛠️  Creando estructura de tablas corporativas en Postgres...")
        pg_cursor.execute("""
            CREATE TABLE IF NOT EXISTS sakti_customers (
                id SERIAL PRIMARY KEY,
                empresa_name VARCHAR(100) NOT NULL,
                api_key VARCHAR(150) UNIQUE NOT NULL,
                estatus VARCHAR(20) DEFAULT 'ACTIVO',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        pg_conn.commit()
        
        # 4. LEER LOS DATOS DE SQLITE
        print("📁 Extrayendo clientes activos desde SQLite...")
        sl_conn = sqlite3.connect(SQLITE_DB)
        sl_cursor = sl_conn.cursor()
        
        sl_cursor.execute("SELECT id, empresa_name, api_key, estatus FROM sakti_customers;")
        clientes_sqlite = sl_cursor.fetchall()
        sl_conn.close()
        
        if not clientes_sqlite:
            print("⚠️  No se encontraron clientes en SQLite para migrar.")
            return

        # 5. INYECTAR LOS DATOS EN POSTGRESQL (Evitando duplicados)
        print(f"🔄 Migrando {len(clientes_sqlite)} registros hacia PostgreSQL...")
        for cliente in clientes_sqlite:
            c_id, c_nombre, c_key, c_estatus = cliente
            
            # Verificamos si la llave ya existe en Postgres para no duplicar si corres el script dos veces
            pg_cursor.execute("SELECT id FROM sakti_customers WHERE api_key = %s;", (c_key,))
            if pg_cursor.fetchone():
                print(f"   ⏩ Cliente '{c_nombre}' ya existe en Postgres. Omitiendo...")
                continue
                
            pg_cursor.execute("""
                INSERT INTO sakti_customers (id, empresa_name, api_key, estatus)
                VALUES (%s, %s, %s, %s);
            """, (c_id, c_nombre, c_key, c_estatus))
            print(f"   ✅ Cliente '{c_nombre}' migrado con éxito.")
            
        pg_conn.commit()
        print("-" * 60)
        print("🏆 ¡MIGRACIÓN DE INFRAESTRUCTURA COMPLETADA CON ÉXITO! 🏆\n")

    except Exception as e:
        print(f"❌ Fallo crítico durante el proceso de migración: {e}")
        pg_conn.rollback()
    finally:
        pg_cursor.close()
        pg_conn.close()

if __name__ == "__main__":
    migrar_sistema()