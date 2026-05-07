import pandas as pd
import matplotlib.pyplot as plt
import sqlite3
import os

def generate_dashboard():
    db_path = "security_vault.db"
    
    # 1. Verificar si la base de datos existe
    if not os.path.exists(db_path):
        print(f"[ERROR] No se encuentra la base de datos {db_path}. ¡Lanza un ataque primero!")
        return

    print("[*] Conectando a la Bóveda de Seguridad...")
    
    # 2. Leer los datos directamente desde SQL
    try:
        conn = sqlite3.connect(db_path)
        # Traemos todos los incidentes ordenados por fecha
        df = pd.read_sql_query("SELECT * FROM incidentes ORDER BY fecha DESC", conn)
        conn.close()
    except Exception as e:
        print(f"[ERROR] Fallo al leer la base de datos: {e}")
        return

    if df.empty:
        print("[!] La base de datos está vacía. Esperando por incidentes...")
        return

    print(f"[+] Se cargaron {len(df)} incidentes correctamente.")

    # 3. Preparar los datos para la gráfica
    conteo = df['categoria'].value_counts()

    # 4. Crear la visualización profesional
    plt.figure(figsize=(12, 7))
    # Paleta de colores profesional
    colores = ['#ff4d4d', '#3399ff', '#33cc33', '#ffcc00', '#9966ff']
    
    ax = conteo.plot(kind='bar', color=colores[:len(conteo)], edgecolor='black', linewidth=1.2)
    
    # Añadir los números exactos sobre cada barra
    for p in ax.patches:
        ax.annotate(f'{int(p.get_height())}', 
                    (p.get_x() + p.get_width() / 2., p.get_height()), 
                    ha='center', va='center', 
                    xytext=(0, 10), 
                    textcoords='offset points',
                    fontsize=12, fontweight='bold')

    # Personalización del diseño
    plt.title('REPORTE DE AMENAZAS DETECTADAS (IA ORCHESTRATOR)', fontsize=16, fontweight='bold', pad=20)
    plt.xlabel('Tipo de Amenaza Identificada', fontsize=12, labelpad=10)
    plt.ylabel('Número de Intentos Detectados', fontsize=12, labelpad=10)
    plt.xticks(rotation=15, ha='right')
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    
    # Guardar el reporte para mostrar al cliente
    report_name = "reporte_ejecutivo_ia.png"
    plt.tight_layout()
    plt.savefig(report_name)
    
    print(f"[SUCCESS] Dashboard generado: {report_name}")
    plt.show()

if __name__ == "__main__":
    generate_dashboard()