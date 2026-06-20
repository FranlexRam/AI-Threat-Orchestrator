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
from brain import orchestrator_ai, send_telegram_alert  # 🚀 Importación del webhook de alerta
import sqlite3

# Inicializamos la plataforma API SaaS Enterprise
app = FastAPI(
    title="SaktiShield Corporate API Ingestion Pipeline", 
    version="2.1.0",
    description="Endpoint universal de ingesta con autenticación perimetral, correlación temporal y base de datos estructurada."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

X_SAKTI_TOKEN = APIKeyHeader(name="X-Sakti-Token", auto_error=False)

# 🧠 MOTOR DE CORRELACIÓN EN RAM
HISTORIAL_CONEXIONES = {}

def obtener_conexion_db():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        database=os.getenv("DB_NAME", "saktishield_production"),
        user=os.getenv("DB_USER", "sakti_admin"),
        password=os.getenv("DB_PASSWORD", "SaktiSecurePassword2026!"),
        port=os.getenv("DB_PORT", "5432")
    )

def crear_tabla_incidentes_if_not_exists():
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

crear_tabla_incidentes_if_not_exists()

def validar_api_key(api_key: str = Security(X_SAKTI_TOKEN)):
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
    try:
        ip_cliente = payload.client_ip
        log_crudo = payload.log_entry
        ahora = datetime.datetime.now()
        
        print(f"\n[🔑 AUTENTICADO]: Tráfico recibido de cliente SaaS: -> {empresa_cliente}")
        
        # 🧠 1. MOTOR DE CORRELACIÓN EN RAM (Por IP para Fuerza Bruta)
        if ip_cliente not in HISTORIAL_CONEXIONES:
            HISTORIAL_CONEXIONES[ip_cliente] = []
        
        HISTORIAL_CONEXIONES[ip_cliente] = [t for t in HISTORIAL_CONEXIONES[ip_cliente] if (ahora - t).total_seconds() <= 60]
        HISTORIAL_CONEXIONES[ip_cliente].append(ahora)
        peticiones_en_ventana = len(HISTORIAL_CONEXIONES[ip_cliente])

        # 🌊 2. CONTROL GLOBAL MULTI-TENANT (Para detección de DDoS por Empresa)
        if not hasattr(app.state, "global_traffic"):
            app.state.global_traffic = {}
            
        if empresa_cliente not in app.state.global_traffic:
            app.state.global_traffic[empresa_cliente] = []
            
        app.state.global_traffic[empresa_cliente] = [t for t in app.state.global_traffic[empresa_cliente] if (ahora - t).total_seconds() <= 2]
        app.state.global_traffic[empresa_cliente].append(ahora)
        peticiones_globales_2s = len(app.state.global_traffic[empresa_cliente])
        
        log_decoded = urllib.parse.unquote(log_crudo).replace('+', ' ')
        log_upper = log_decoded.upper()
        
        # 🎯 DETECCIÓN EXPANDIDA DE FUERZA BRUTA Y VECTORES DE ATAQUE
        es_intento_fallido = any(k in log_upper for k in ["FAILED LOGIN", "INVALID CREDENTIALS", "AUTH_FAILURE", "ACCESS DENIED", "LOGIN_ATTEMPT"])
        fuerza_bruta_detectada = es_intento_fallido and peticiones_en_ventana >= 3

        # 🔥 NUEVA REGLA PERIMETRAL: Mitigación DDoS activa
        ddos_detectado = peticiones_globales_2s >= 10

        disparadores_rce = ["WHOAMI", "NC -E", "/BIN/BASH", "CMD.EXE", "EXEC(", "SYSTEM("]
        disparadores_ssrf = ["169.254.169.254", "METADATA", "INSTANCE/DATA"]
        disparadores_sqli = ["UNION", "SELECT", "INSERT", "DROP", "UPDATE", "OR 1=1", "INFORMATION_SCHEMA"]
        disparadores_web_general = ["../", "..\\", "/ETC/PASSWD", "BOOT.INI", "<SCRIPT", "SCRIPT>", "ALERT(", "ONLOAD="]
        
        detectado_rce = any(patron in log_upper for patron in disparadores_rce)
        detectado_ssrf = any(patron in log_upper for patron in disparadores_ssrf)
        detectado_sqli = any(patron in log_upper for patron in disparadores_sqli)
        detectado_web = any(patron in log_upper for patron in disparadores_web_general)
        
        # Evaluación perimetral estricta
        requiere_ia = detectado_rce or detectado_ssrf or detectado_sqli or detectado_web or fuerza_bruta_detectada or ddos_detectado
        
        # Flujo A: Tráfico Rutinario / Legítimo Puro (NO SE GUARDA EN LA DB PARA NO ENSUCIAR EL SOC)
        if not requiere_ia:
            return JSONResponse(
                status_code=200,
                content={
                    "status": "PERMITIDO",
                    "code": "TRAFICO_LEGITIMO",
                    "client": empresa_cliente,
                    "message": "Filtro Autolimpiante: Solicitud rutinaria aprobada y descartada de auditoría."
                }
            )
            
        # Flujo B: Alerta Perimetral Activada -> Escalabilidad a Motor de IA / Correlación Temporal
        print(f"[🚀 API PIPELINE]: Alerta perimetral activada para {empresa_cliente} (IP {ip_cliente}). Escalando...")
        
        # 🧠 SECCIÓN DE DECISIONES
        if ddos_detectado:
            resultado_brain = f"BLOQUEADO - CRÍTICO (Mitigación DDoS Activa: {peticiones_globales_2s} req/2s detectadas en el perímetro)"
        elif fuerza_bruta_detectada:
            resultado_brain = f"BLOQUEADO - CRÍTICO (Ataque Masivo de Fuerza Bruta Detectado por Ventana Temporal: {peticiones_en_ventana} solicitudes/min)"
        else:
            resultado_brain = orchestrator_ai(log_crudo, client_ip=ip_cliente, empresa_name=empresa_cliente)
        
        # Parser rápido para el estado del streaming en vivo
        status_final = "BLOQUEADO" if "BLOQUEADO" in resultado_brain.upper() else "REVISIÓN"

        # Clasificación exacta y ordenada para el WebSocket en tiempo real del Dashboard
        if ddos_detectado or "DDOS" in resultado_brain.upper():
            tipo_ataque = "DDoS Attack"
        elif fuerza_bruta_detectada or "BRUTE" in resultado_brain.upper() or "FORCE" in resultado_brain.upper():
            tipo_ataque = "Brute Force Attack"
        elif "SQL" in resultado_brain.upper() or detectado_sqli:
            tipo_ataque = "SQL Injection (SQLi)"
        elif "SSRF" in resultado_brain.upper() or detectado_ssrf:
            tipo_ataque = "Server-Side Request Forgery (SSRF)"
        elif "RCE" in resultado_brain.upper() or detectado_rce:
            tipo_ataque = "Remote Code Execution (RCE)"
        elif "XSS" in resultado_brain.upper() or "SCRIPT" in log_upper:
            tipo_ataque = "Cross-Site Scripting (XSS)"
        elif "TRAVERSAL" in resultado_brain.upper() or detectado_web:
            tipo_ataque = "Directory Traversal"
        else:
            tipo_ataque = "Ataque Indefinido"

        # Si fue procesado por mitigación estática perimetral (Fuerza Bruta o DDoS), se persiste aquí
        if fuerza_bruta_detectada or ddos_detectado:
            try:
                conn_pg = obtener_conexion_db()
                cursor_pg = conn_pg.cursor()
                cursor_pg.execute(
                    """INSERT INTO sakti_incidents (empresa_name, client_ip, log_entry, resultado_ia, alerta_status, nivel_riesgo, tipo_ataque, soar_active) 
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                    (empresa_cliente, ip_cliente, log_crudo, resultado_brain, status_final, "CRÍTICO", tipo_ataque, "EJECUTADO ✅")
                )
                conn_pg.commit()
                cursor_pg.close()
                conn_pg.close()
                
                # Disparo instantáneo al bot de Telegram
                try:
                    send_telegram_alert(categoria=tipo_ataque, riesgo="CRÍTICO", ip=ip_cliente)
                    print(f"[📬 TELEGRAM]: Alerta perimetral de {tipo_ataque} enviada para {empresa_cliente}.")
                except Exception as tel_err:
                    print(f"❌ Error al despachar el Telegram de {tipo_ataque}: {tel_err}")

            except Exception as db_err:
                print(f"❌ Error guardando mitigación estática en Postgres: {db_err}")

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