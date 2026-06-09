import asyncio
import urllib.parse
import datetime
import os  # 🟢 Para leer las variables del archivo .env
import psycopg2  # 🐘 Driver oficial de PostgreSQL
from fastapi import FastAPI, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import pydantic
import json
from brain import orchestrator_ai
import sqlite3

# Inicializamos la plataforma API SaaS Enterprise
app = FastAPI(
    title="SaktiShield Corporate API Ingestion Pipeline", 
    version="2.1.0",  # Escalamos la versión por el análisis de ventanas de tiempo y arquitectura de datos SOAR
    description="Endpoint universal de ingesta con autenticación perimetral, correlación temporal y base de datos estructurada."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuramos FastAPI para que busque obligatoriamente esta cabecera en los HTTP Headers
X_SAKTI_TOKEN = APIKeyHeader(name="X-Sakti-Token", auto_error=False)

# 🧠 MOTOR DE CORRELACIÓN EN RAM: Almacén de timestamps por IP para atrapar ráfagas de Fuerza Bruta
HISTORIAL_CONEXIONES = {}

def obtener_conexion_db():
    """🛡️ FUNCIÓN AUXILIAR: Obtiene una conexión limpia hacia el clúster de PostgreSQL"""
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        database=os.getenv("DB_NAME", "saktishield_production"),
        user=os.getenv("DB_USER", "sakti_admin"),
        password=os.getenv("DB_PASSWORD", "SaktiSecurePassword2026!"),
        port=os.getenv("DB_PORT", "5432")
    )

def crear_tabla_incidentes_if_not_exists():
    """🐘 EVOLUCIÓN ESTRUCTURAL: Asegura un esquema relacional con soporte para reportes profundos y SOAR"""
    try:
        conn = obtener_conexion_db()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sakti_incidents (
                id SERIAL PRIMARY KEY,
                empresa_name VARCHAR(100),
                client_ip VARCHAR(50),
                log_entry TEXT,
                resultado_ia TEXT,
                alerta_status VARCHAR(50),
                nivel_riesgo VARCHAR(30) DEFAULT 'BAJO',
                tipo_ataque VARCHAR(100) DEFAULT 'Tráfico Rutinario',
                soar_active VARCHAR(20) DEFAULT 'INACTIVO',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()
        cursor.close()
        conn.close()
        print("🛡️ [POSTGRESQL]: Estructura corporativa multi-tenant verificada y lista para operar.")
    except Exception as e:
        print(f"⚠️ [POSTGRESQL]: No se pudo verificar/crear la tabla de incidentes estructurada: {e}")

# Ejecutamos la verificación de la tabla al cargar el módulo
crear_tabla_incidentes_if_not_exists()

def validar_api_key(api_key: str = Security(X_SAKTI_TOKEN)):
    """
    🧠 FILTRO DINÁMICO PERIMETRAL: Busca y valida la credencial directamente 
    en el Vault Local de SQLite (security_vault.db) compartido en tiempo real.
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Acceso Denegado: X-Sakti-Token ausente en las cabeceras."
        )
    
    try:
        conn = sqlite3.connect("security_vault.db")
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT empresa_name FROM sakti_customers WHERE api_key = ? AND estatus = 'ACTIVO'", 
            (api_key,)
        )
        cliente = cursor.fetchone()
        cursor.close()
        conn.close()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Fallo de enlace con el vault local perimetral (SQLite): {str(e)}"
        )
    
    if not cliente:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Acceso Denegado: X-Sakti-Token inválido o revocado de la firma."
        )
    
    return cliente[0]

class LogPayload(pydantic.BaseModel):
    client_ip: str
    log_entry: str

eventos_tiempo_real = asyncio.Queue()

@app.post("/api/v1/ingest")
async def ingestar_log_corporativo(payload: LogPayload, empresa_cliente: str = Security(validar_api_key)):
    """
    Endpoint Ejecutivo Autenticado: Recibe logs de empresas autorizadas, 
    aplica ventanas de tiempo, escala anomalías a la IA y persiste 
    toda la telemetría estructurada para auditoría y visualización del SOC.
    """
    try:
        ip_cliente = payload.client_ip
        log_crudo = payload.log_entry
        ahora = datetime.datetime.now()
        
        print(f"\n[🔑 AUTENTICADO]: Tráfico recibido de cliente SaaS: -> {empresa_cliente}")
        
        # 🛡️ CONTROL DE VENTANAS TEMPORALES EN RAM (Correlación de eventos para capturar ráfagas masivas)
        if ip_cliente not in HISTORIAL_CONEXIONES:
            HISTORIAL_CONEXIONES[ip_cliente] = []
        
        # Limpiamos accesos con antigüedad mayor a 60 segundos
        HISTORIAL_CONEXIONES[ip_cliente] = [t for t in HISTORIAL_CONEXIONES[ip_cliente] if (ahora - t).total_seconds() <= 60]
        HISTORIAL_CONEXIONES[ip_cliente].append(ahora)
        
        peticiones_en_ventana = len(HISTORIAL_CONEXIONES[ip_cliente])
        
        # 🛡️ FILTRO ANALÍTICO EN RAM (Separación de casos analíticos)
        log_decoded = urllib.parse.unquote(log_crudo).replace('+', ' ')
        log_upper = log_decoded.upper()
        
        es_intento_fallido = "FAILED LOGIN" in log_upper or "INVALID CREDENTIALS" in log_upper or "AUTH_FAILURE" in log_upper
        
        # Correlación temporal explícita para detener ráfagas de Fuerza Bruta
        fuerza_bruta_detectada = es_intento_fallido and peticiones_en_ventana >= 3

        disparadores_rce = [
            ";", "|", "&&", "`", "$(", 
            "whoami", "WHOAMI", "id", "ID", "uname", "UNAME", 
            "nc", "NC", "netcat", "NETCAT", "wget", "WGET", 
            "curl", "CURL", "bash", "BASH", "sh", "SH"
        ]

        disparadores_web = [
            "169.254.169.254", "METADATA", "LOCALHOST", "127.0.0.1",
            "../", "..\\", "/ETC/PASSWD", "BOOT.INI", "WIN.INI",
            "UNION", "SELECT", "INSERT", "DROP", "UPDATE", "OR 1=1", "--",
            "<SCRIPT", "SCRIPT>", "ALERT(", "ONLOAD=", "ONERROR="
        ]
        
        detectado_rce = any(patron in log_decoded for patron in disparadores_rce)
        detectado_web = any(patron in log_upper for patron in disparadores_web)
        
        requiere_ia = detectado_rce or detectado_web or fuerza_bruta_detectada
        
        # Flujo A: Tráfico Rutinario / Legítimo
        if not requiere_ia:
            resultado_brain = "PERMITIDO - Tráfico Rutinario Aprobado"
            status_final = "PERMITIDO"
            nivel_riesgo = "BAJO"
            tipo_ataque = "Tráfico Rutinario"
            soar_active = "INACTIVO"
            
            try:
                conn_pg = obtener_conexion_db()
                cursor_pg = conn_pg.cursor()
                cursor_pg.execute(
                    """INSERT INTO sakti_incidents (empresa_name, client_ip, log_entry, resultado_ia, alerta_status, nivel_riesgo, tipo_ataque, soar_active) 
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                    (empresa_cliente, ip_cliente, log_crudo, resultado_brain, status_final, nivel_riesgo, tipo_ataque, soar_active)
                )
                conn_pg.commit()
                cursor_pg.close()
                conn_pg.close()
            except Exception as db_err:
                print(f"❌ Error guardando telemetría rutinaria en Postgres: {db_err}")
                
            return JSONResponse(
                status_code=200,
                content={
                    "status": "PERMITIDO",
                    "code": "TRAFICO_LEGITIMO",
                    "client": empresa_cliente,
                    "message": "Filtro Autolimpiante: Solicitud rutinaria aprobada y registrada en el perímetro."
                }
            )
            
        # Flujo B: Alerta Perimetral Activada -> Escalabilidad a Motor de IA / Correlación Temporal
        print(f"[🚀 API PIPELINE]: Alerta perimetral activada para {empresa_cliente} (IP {ip_cliente}). Escalando...")
        
        # Interceptamos la decisión si el motor de tiempo real descubrió una ráfaga anómala
        if fuerza_bruta_detectada:
            resultado_brain = f"BLOQUEADO - CRÍTICO (Ataque Masivo de Fuerza Bruta Detectado por Ventana Temporal: {peticiones_en_ventana} solicitudes/min)"
        else:
            resultado_brain = orchestrator_ai(log_crudo, client_ip=ip_cliente)
        
        # 🧠 PARSER PARA EXTRACCIÓN QUIRÚRGICA DE MÉTRICAS COMERCIALES
        if " - " in resultado_brain:
            partes = resultado_brain.split(" - ")
            status_final = partes[0]
        else:
            status_final = "BLOQUEADO" if ("⚠️" in resultado_brain or "BLOQUEADO" in resultado_brain.upper() or "ATAQUE" in resultado_brain.upper() or fuerza_bruta_detectada) else "REVISIÓN"
        
        # Clasificación dinámica de niveles de riesgo
        if "CRÍTICO" in resultado_brain.upper() or "CRITICO" in resultado_brain.upper():
            nivel_riesgo = "CRÍTICO"
        elif "ALTO" in resultado_brain.upper():
            nivel_riesgo = "ALTO"
        elif "MEDIO" in resultado_brain.upper() or "REVISIÓN" in resultado_brain.upper() or "REVISION" in resultado_brain.upper():
            nivel_riesgo = "MEDIO"
        else:
            nivel_riesgo = "BAJO"

        # Clasificación estricta del Vector de Ataque real evaluado
        if fuerza_bruta_detectada or "BRUTE" in resultado_brain.upper() or "FORCE" in resultado_brain.upper() or "LOGIN" in log_upper:
            tipo_ataque = "Brute Force Attack"
        elif "RCE" in resultado_brain.upper() or "EXECUTION" in resultado_brain.upper() or detectado_rce:
            tipo_ataque = "Remote Code Execution (RCE)"
        elif "SQL" in resultado_brain.upper() or "UNION" in log_upper or "SELECT" in log_upper:
            tipo_ataque = "SQL Injection (SQLi)"
        elif "XSS" in resultado_brain.upper() or "SCRIPT" in log_upper:
            tipo_ataque = "Cross-Site Scripting (XSS)"
        elif "TRAVERSAL" in resultado_brain.upper() or "../" in log_upper:
            tipo_ataque = "Directory Traversal"
        elif "SSRF" in resultado_brain.upper():
            tipo_ataque = "SSRF Attack"
        else:
            tipo_ataque = "Anomalía de Red detectada por IA"

        # ⚡ ACCIÓN AUTOMATIZADA SOAR (Security Orchestration, Automation, and Response)
        soar_active = "EJECUTADO ✅" if status_final == "BLOQUEADO" else "INACTIVO"
        
        # 🐘 PERSISTENCIA EN POSTGRESQL (Estructura relacional robusta)
        try:
            conn_pg = obtener_conexion_db()
            cursor_pg = conn_pg.cursor()
            cursor_pg.execute(
                """INSERT INTO sakti_incidents (empresa_name, client_ip, log_entry, resultado_ia, alerta_status, nivel_riesgo, tipo_ataque, soar_active) 
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (empresa_cliente, ip_cliente, log_crudo, resultado_brain, status_final, nivel_riesgo, tipo_ataque, soar_active)
            )
            conn_pg.commit()
            cursor_pg.close()
            conn_pg.close()
            print(f"✅ Incidente persistido estructuradamente para {empresa_cliente}")
        except Exception as db_err:
            print(f"❌ Error guardando incidente estructurado en Postgres: {db_err}")
        
        # 🛡️ ESTRUCTURA DE ALERTA PARA STREAMING EN VIVO (Mantiene compatibilidad de eventos con el Dashboard)
        alerta_dashboard = {
            "ip": ip_cliente,
            "log": log_crudo,
            "resultado": f"[{empresa_cliente}] {resultado_brain}", 
            "status": status_final,
            "timestamp": datetime.datetime.now().strftime('%H:%M:%S')
        }
        
        await eventos_tiempo_real.put(alerta_dashboard)
        
        return {
            "status": "PROCESADO",
            "code": "AMENAZA_EVALUADA",
            "client": empresa_cliente,
            "decision_core": resultado_brain,
            "message": "Evento analizado por el Motor de Correlación y transmitido en tiempo real."
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fallo crítico en el pipeline corporativo: {str(e)}")

@app.get("/api/v1/stream")
async def stream_incidentes(request: Request):
    async def generador_eventos():
        while True:
            if await request.is_disconnected():
                break
            try:
                alerta = await asyncio.wait_for(eventos_tiempo_real.get(), timeout=1.0)
                yield f"data: {json.dumps(alerta)}\n\n"
            except asyncio.TimeoutError:
                continue
    return StreamingResponse(generador_eventos(), media_type="text/event-stream")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api_ingest:app", host="0.0.0.0", port=8000, reload=True)