import asyncio
import urllib.parse
import datetime
import os  # 🟢 AGREGADO: Para leer las variables del archivo .env
import psycopg2  # 🐘 MODIFICADO: Cambiamos sqlite3 por el driver oficial de PostgreSQL
from fastapi import FastAPI, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import pydantic
import json
from brain import orchestrator_ai
import sqlite3

# Inicializamos la plataforma API SaaS
app = FastAPI(
    title="SaktiShield Corporate API Ingestion Pipeline", 
    version="2.0.0",  # Escalamos la versión por el paso a infraestructura Enterprise con Postgres
    description="Endpoint universal de ingesta con autenticación perimetral conectada a Base de Datos PostgreSQL."
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
    """🐘 AUTOMATIZACIÓN: Asegura la existencia de la estructura corporativa en Postgres al arrancar"""
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()
        cursor.close()
        conn.close()
        print("🛡️ [POSTGRESQL]: Tabla 'sakti_incidents' verificada y lista para operar.")
    except Exception as e:
        print(f"⚠️ [POSTGRESQL]: No se pudo verificar/crear la tabla de incidentes: {e}")

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
    
    # 🛡️ CONEXIÓN AL VAULT LOCAL DE SEGURIDAD (SQLite)
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
            detail="Acceso Denegado: X-Sakti-Token inválido o revocado."
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
    aplica filtro autolimpiante en RAM y escala amenazas al SOC.
    """
    try:
        ip_cliente = payload.client_ip
        log_crudo = payload.log_entry
        
        print(f"\n[🔑 AUTENTICADO]: Tráfico recibido de cliente SaaS: -> {empresa_cliente}")
        
        # 🛡️ FILTRO AUTOLIMPIANTE EN RAM (Separación de casos analíticos)
        log_decoded = urllib.parse.unquote(log_crudo).replace('+', ' ')
        log_upper = log_decoded.upper()
        
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
            "<SCRIPT", "SCRIPT>", "ALERT(", "ONLOAD=", "ONERROR=",
            "FAILED LOGIN", "INVALID CREDENTIALS", "AUTH_FAILURE"
        ]
        
        detectado_rce = any(patron in log_decoded for patron in disparadores_rce)
        detectado_web = any(patron in log_upper for patron in disparadores_web)
        
        requiere_ia = detectado_rce or detectado_web
        
        if not requiere_ia:
            return JSONResponse(
                status_code=200,
                content={
                    "status": "PERMITIDO",
                    "code": "TRAFICO_LEGITIMO",
                    "client": empresa_cliente,
                    "message": "Filtro Autolimpiante: Solicitud rutinaria aprobada en el perímetro."
                }
            )
            
        # 🧠 ESCALABILIDAD SOC
        print(f"[🚀 API PIPELINE]: Alerta perimetral activada para {empresa_cliente} (IP {ip_cliente}). Escalando...")
        resultado_brain = orchestrator_ai(log_crudo, client_ip=ip_cliente)
        
        if " - " in resultado_brain:
            partes = resultado_brain.split(" - ")
            status_final = partes[0]
        else:
            status_final = "BLOQUEADO"
        
        # 🐘 PERSISTENCIA EN POSTGRESQL (Para alimentar los gráficos del Dashboard)
        try:
            conn_pg = obtener_conexion_db()
            cursor_pg = conn_pg.cursor()
            cursor_pg.execute(
                """INSERT INTO sakti_incidents (empresa_name, client_ip, log_entry, resultado_ia, alerta_status) 
                   VALUES (%s, %s, %s, %s, %s)""",
                (empresa_cliente, ip_cliente, log_crudo, resultado_brain, status_final)
            )
            conn_pg.commit()
            cursor_pg.close()
            conn_pg.close()
            print(f"✅ Incidente persistido en Postgres para {empresa_cliente}")
        except Exception as db_err:
            print(f"❌ Error guardando incidente en Postgres: {db_err}")
        
        # 🛡️ ESTRUCTURA DE ALERTA PARA STREAMING EN VIVO
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