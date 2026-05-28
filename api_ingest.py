import asyncio
import urllib.parse
import datetime
import sqlite3  # 🟢 AGREGADO: Necesario para consultar la base de datos de tokens
from fastapi import FastAPI, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import pydantic
import json
from brain import orchestrator_ai

# Inicializamos la plataforma API SaaS
app = FastAPI(
    title="SaktiShield Corporate API Ingestion Pipeline", 
    version="1.2.0",  # Escalamos la versión por el backend con persistencia
    description="Endpoint universal de ingesta con autenticación perimetral conectada a Base de Datos."
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

def validar_api_key(api_key: str = Security(X_SAKTI_TOKEN)):
    """
    🧠 FILTRO DINÁMICO: Busca y valida la credencial directamente 
    en la Base de Datos en tiempo real para verificar suscripciones.
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Acceso Denegado: X-Sakti-Token ausente en las cabeceras."
        )
    
    # 🟢 CONEXIÓN EN CALIENTE A LA DB
    conn = sqlite3.connect("security_vault.db")
    cursor = conn.cursor()
    
    # Consultamos si el token exacto existe y si la cuenta está 'ACTIVO'
    cursor.execute(
        "SELECT empresa_name FROM sakti_customers WHERE api_key = ? AND estatus = 'ACTIVO'", 
        (api_key,)
    )
    cliente = cursor.fetchone()
    conn.close()
    
    # Si la consulta no devuelve filas, el token es falso o fue revocado
    if not cliente:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Acceso Denegado: X-Sakti-Token inválido o revocado de la firma."
        )
    
    return cliente[0]  # Retorna el nombre de la empresa real extraído de la fila

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
        
        # Log informativo en tu consola para saber qué cliente corporativo está enviando datos
        print(f"\n[🔑 AUTENTICADO]: Tráfico recibido de cliente SaaS: -> {empresa_cliente}")
        
        # 🛡️ FILTRO AUTOLIMPIANTE EN RAM
        log_decoded = urllib.parse.unquote(log_crudo).replace('+', ' ').upper()
        patrones_peligro = [
            "<SCRIPT", "SCRIPT>", "ALERT(", "UNION", "SELECT", 
            "../", "..\\", "/ETC/PASSWD", "WHOAMI", "LOCALHOST", "127.0.0.1"
        ]
        
        requiere_ia = any(patron in log_decoded for patron in patrones_peligro)
        
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
        
        partes = resultado_brain.split(" - ")
        status_final = partes[0]
        
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