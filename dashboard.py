import pandas as pd
import matplotlib.pyplot as plt
import json
import os

def generate_dashboard():
    file_path = "incident_report.json"
    
    # 1. Verificar si el archivo existe
    if not os.path.exists(file_path):
        print(f"[ERROR]: No se encuentra el archivo {file_path}. ¡Lanza un ataque primero!")
        return

    print("[*] Leyendo datos de incidentes...")
    eventos = []
    
    with open(file_path, "r") as f:
        for i, linea in enumerate(f):
            try:
                eventos.append(json.loads(linea))
            except json.JSONDecodeError:
                print(f"[!] Error al leer la línea {i+1}. Saltando...")

    # 2. Verificar si hay datos cargados
    if not eventos:
        print("[!] El archivo está vacío. No hay nada que graficar.")
        return

    print(f"[+] Se cargaron {len(eventos)} eventos correctamente.")
    df = pd.DataFrame(eventos)
    
    # 3. Limpieza de datos (Búsqueda flexible de categorías)
    def extraer_categoria(texto):
        texto = texto.upper() # Pasamos todo a mayúsculas para no fallar por tildes o minúsculas
        if "SQL INJECTION" in texto or "INYECCIÓN SQL" in texto:
            return "Inyección SQL"
        elif "MALWARE" in texto:
            return "Malware"
        elif "UNAUTHORIZED" in texto or "ACCESO NO AUTORIZADO" in texto:
            return "Acceso No Autorizado"
        elif "SCAN" in texto or "ESCANEO" in texto:
            return "Escaneo de Puertos"
        elif "BRUTE FORCE" in texto or "FUERZA BRUTA" in texto:
            return "Fuerza Bruta"
        else:
            return "Otras Amenazas"

    # Aplicamos la función a cada análisis de la IA
    df['categoria_limpia'] = df['analisis_ia'].apply(extraer_categoria)

    # 4. Contar los ataques por cada nueva categoría limpia
    conteo = df['categoria_limpia'].value_counts()

    # --- CREAR LA GRÁFICA ---
    plt.figure(figsize=(12, 7))
    colores = plt.cm.Paired(range(len(conteo)))
    ax = conteo.plot(kind='bar', color=colores, edgecolor='black')
    
    for p in ax.patches:
        ax.annotate(f'{int(p.get_height())}', 
                    (p.get_x() + p.get_width() / 2., p.get_height()), 
                    ha='center', va='center', 
                    xytext=(0, 9), 
                    textcoords='offset points',
                    fontsize=11, fontweight='bold')

    plt.title('Análisis Estadístico de Amenazas: Orquestador IA', fontsize=16, fontweight='bold', pad=20)
    plt.xlabel('Categoría de Ataque Identificada', fontsize=12, labelpad=10)
    plt.ylabel('Número de Intentos Detectados', fontsize=12, labelpad=10)
    plt.xticks(rotation=20, ha='right', fontsize=10)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()

    plt.savefig("security_summary.png")
    print("[SUCCESS]: Gráfica guardada como security_summary.png")
    plt.show()

if __name__ == "__main__":
    generate_dashboard()