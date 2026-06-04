# manage_customers.py
import sqlite3
import os
import secrets

DB_PATH = "security_vault.db"

def conectar_db():
    return sqlite3.connect(DB_PATH)

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
        
    # Generamos un token criptográfico seguro de 24 bytes en hex (48 caracteres) con tu prefijo
    token_seguro = f"sakti_live_{secrets.token_hex(24)}"
    
    conn = conectar_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO sakti_customers (empresa_name, api_key, estatus) VALUES (?, ?, 'ACTIVO');",
            (nombre_empresa, token_seguro)
        )
        conn.commit()
        print(f"\n✅ ¡Cliente agregado con éxito!")
        print(f"🏢 Empresa: {nombre_empresa}")
        print(f"🔑 Token Asignado: {token_seguro}")
    except Exception as e:
        print(f"❌ Error al insertar el cliente: {e}")
    finally:
        conn.close()

def eliminar_cliente():
    listar_clientes()
    id_input = input("🚨 Introduce el ID del cliente que deseas ELIMINAR permanentemente: ").strip()
    if not id_input.isdigit():
        print("❌ ID inválido. Debe ser un número entero.")
        return
        
    id_cliente = int(id_input)
    
    conn = conectar_db()
    cursor = conn.cursor()
    try:
        # Verificamos si existe antes de borrar
        cursor.execute("SELECT empresa_name FROM sakti_customers WHERE id = ?;", (id_cliente,))
        cliente = cursor.fetchone()
        
        if not cliente:
            print(f"❌ No se encontró ningún cliente con el ID {id_cliente}.")
            return
            
        confirmacion = input(f"⚠️ ¿Estás seguro de que quieres eliminar a '{cliente[0]}'? (s/n): ").strip().lower()
        if confirmacion == 's':
            cursor.execute("DELETE FROM sakti_customers WHERE id = ?;", (id_cliente,))
            conn.commit()
            print(f"🗑️ Cliente '{cliente[0]}' eliminado correctamente del sistema.")
        else:
            print("❌ Operación de borrado cancelada.")
            
    except Exception as e:
        print(f"❌ Error al eliminar el cliente: {e}")
    finally:
        conn.close()

def menu():
    if not os.path.exists(DB_PATH):
        print(f"❌ Alerta: No se detecta el archivo '{DB_PATH}' en este directorio.")
        return

    while True:
        print("📁 GESTOR DE PLATAFORMA SAKTISHIELD")
        print("1. Ver lista de clientes organizada")
        print("2. Registrar un nuevo cliente (Generar Token)")
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