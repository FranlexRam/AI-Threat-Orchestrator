import sqlite3

# 1. Nos conectamos a tu base de datos existente
conn = sqlite3.connect("security_vault.db")
cursor = conn.cursor()

try:
    # 2. Le ordenamos a la base de datos que agregue la nueva columna
    cursor.execute("ALTER TABLE incidentes ADD COLUMN accion_mitigacion TEXT DEFAULT 'Ninguna - Tráfico Auditado';")
    conn.commit()
    print("✅ ¡Éxito! Columna 'accion_mitigacion' añadida a la base de datos.")
except Exception as e:
    print(f"⚠️ Nota: Es posible que la columna ya exista o ocurrió este aviso: {e}")

# 3. Cerramos la conexión de forma segura
conn.close()