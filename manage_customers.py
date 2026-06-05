# manage_customers.py
import sqlite3
import os
import secrets
import psycopg2

DB_PATH = "security_vault.db"

# 🐘 CONFIGURACIÓN COPIADA DE TU DOCKER-COMPOSE
# Como corres el script desde la Mac, "localhost" se conectará al puerto 5432 expuesto por Docker
PG_CONFIG = {
    "dbname": "saktishield_production",
    "user": "sakti_admin",
    "password": "SaktiSecurePassword2026!",
    "host": "localhost",
    "port": "5432"
}

def conectar_db():
    return sqlite3.connect(DB_PATH)

def conectar_postgres():
    """Establece conexión con el clúster relacional de PostgreSQL"""
    return psycopg2.connect(**PG_CONFIG)

def listar_clientes():
    conn = conectar_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id, empresa_name, api_key, estatus FROM sakti_customers;")
        clientes = cursor.fetchall()
        
        print("\n" + "="*85)
        print("🛡️  SAKTISHIELD — PANEL DE CONTROL DE CLIENTES SaaS 🛡️")
        print("="*85)
        print(f"{'ID':<4} | {'ORGANIZACIÓN / EMPRESA':<25} | {'X-SAKTI-TOKEN':<50} | {'ESTATUS':<10}")
        print("-" * 85)
        
        if not clientes:
            print("⚠️  No hay ningún cliente registrado en el ecosistema aún.")
        else:
            for c in clientes:
                print(f"{c[0]:<4} | {c[1]:<25} | {c[2]:<50} | {c[3]:<10}")
        print("="*85 + "\n")
        
    except sqlite3.OperationalError as e:
        print(f"❌ Error: La tabla 'sakti_customers' no fue encontrada en la DB ({e}).")
    finally:
        conn.close()

def agregar_cliente():
    nombre_empresa = input("\n📝 Introduce el nombre de la nueva Empresa/Organización: ").strip()
    if not nombre_empresa:
        print("❌ El nombre de la empresa no puede estar vacío.")
        return
        
    # Pedir credenciales administrativas para el Dashboard Web
    print(f"\n--- 🌐 Configuración de Acceso Web para {nombre_empresa} ---")
    username_web = input("👤 Define el usuario administrador para la plataforma: ").strip()
    password_web = input("🔑 Define la contraseña para este usuario: ").strip()
    
    if not username_web or not password_web:
        print("❌ El usuario y la contraseña no pueden estar vacíos.")
        return

    # Generamos el token criptográfico con tu formato
    token_seguro = f"sakti_live_{secrets.token_hex(24)}"
    
    # Abrimos la conexión local de SQLite
    conn_sqlite = conectar_db()
    cursor_sqlite = conn_sqlite.cursor()
    
    try:
        # 1. Inserción en SQLite (Perímetro / API Ingest)
        cursor_sqlite.execute(
            "INSERT INTO sakti_customers (empresa_name, api_key, estatus) VALUES (?, ?, 'ACTIVO');",
            (nombre_empresa, token_seguro)
        )
        
        # 2. Inserción en PostgreSQL (Aplicación / Dashboard SaaS)
        conn_pg = conectar_postgres()
        cursor_pg = conn_pg.cursor()
        
        cursor_pg.execute("""
            INSERT INTO sakti_users (username, password, rol, empresa_name)
            VALUES (%s, %s, 'CLIENT_ADMIN', %s);
        """, (username_web, password_web, nombre_empresa))
        
        # Si ambas bases de datos responden bien, guardamos cambios
        conn_sqlite.commit()
        conn_pg.commit()
        
        print(f"\n✅ ¡Ecosistema sincronizado con éxito!")
        print(f"🏢 Empresa: {nombre_empresa}")
        print(f"🔑 Token Ingesta: {token_seguro}")
        print(f"👤 Acceso Web Dashboard: {username_web} / {password_web}")
        
        cursor_pg.close()
        conn_pg.close()
        
    except Exception as e:
        print(f"❌ Error crítico en la sincronización Multi-tenant: {e}")
        conn_sqlite.rollback()
    finally:
        conn_sqlite.close()

def eliminar_cliente():
    listar_clientes()
    id_input = input("🚨 Introduce el ID del cliente que deseas ELIMINAR permanentemente: ").strip()
    if not id_input.isdigit():
        print("❌ ID inválido. Debe ser un número entero.")
        return
        
    id_cliente = int(id_input)
    
    conn_sqlite = conectar_db()
    cursor_sqlite = conn_sqlite.cursor()
    try:
        cursor_sqlite.execute("SELECT empresa_name FROM sakti_customers WHERE id = ?;", (id_cliente,))
        cliente = cursor_sqlite.fetchone()
        
        if not cliente:
            print(f"❌ No se encontró ningún cliente con el ID {id_cliente}.")
            return
            
        confirmacion = input(f"⚠️ ¿Estás seguro de que quieres eliminar a '{cliente[0]}'? Esto también borrará su acceso web (s/n): ").strip().lower()
        if confirmacion == 's':
            # Eliminar de SQLite
            cursor_sqlite.execute("DELETE FROM sakti_customers WHERE id = ?;", (id_cliente,))
            
            # Eliminar de PostgreSQL de manera automática
            conn_pg = conectar_postgres()
            cursor_pg = conn_pg.cursor()
            cursor_pg.execute("DELETE FROM sakti_users WHERE empresa_name = %s;", (cliente[0],))
            
            conn_sqlite.commit()
            conn_pg.commit()
            
            print(f"🗑️ Cliente '{cliente[0]}' y sus credenciales web fueron removidos del sistema.")
            cursor_pg.close()
            conn_pg.close()
        else:
            print("❌ Operación de borrado cancelada.")
            
    except Exception as e:
        print(f"❌ Error al eliminar el cliente: {e}")
        conn_sqlite.rollback()
    finally:
        conn_sqlite.close()

def menu():
    if not os.path.exists(DB_PATH):
        print(f"❌ Alerta: No se detecta el archivo '{DB_PATH}' en este directorio.")
        return

    while True:
        print("📁 GESTOR DE PLATAFORMA SAKTISHIELD")
        print("1. Ver lista de clientes organizada")
        print("2. Registrar un nuevo cliente (Generar Token y Acceso Web)")
        print("3. Eliminar un cliente por ID")
        print("4. Salir")
        
        opcion = input("Selecciona una opción (1-4): ").strip()
        
        if opcion == "1":
            listar_clientes()
        elif opcion == "2":
            agregar_cliente()
        elif opcion == "3":
            eliminar_cliente()
        elif opcion == "4":
            print("👋 Saliendo del gestor. ¡Listo para continuar!")
            break
        else:
            print("❌ Opción no válida. Intenta de nuevo.\n")

if __name__ == "__main__":
    menu()