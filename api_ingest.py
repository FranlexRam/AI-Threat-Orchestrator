import asyncio
import urllib.parse
import datetime
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
    version="1.1.0",
    description="Endpoint universal de ingesta con autenticación perimetral por API Key."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 🔑 CONTROL DE ACCESO CORPORATIVO (Simulación de Clientes en Memoria)
# En el futuro, esto se validará contra tu base de datos central de suscripciones SaaS
CLIENTES_AUTORIZADOS = {
    "sakti_token_empresa_alfa_9942": "Empresa Alfa C.A.",
    "sakti_token_bravo_secure_7711": "Corporación Bravo"
}

# Configuramos FastAPI para que busque obligatoriamente esta cabecera en los HTTP Headers
X_SAKTI_TOKEN = APIKeyHeader(name="X-Sakti-Token", auto_error=False)

def validar_api_key(api_key: str = Security(X_SAKTI_TOKEN)):
    """Filtro criptográfico en RAM: Valida si la empresa tiene su suscripción activa."""
    if not api_key or api_key not in CLIENTES_AUTORIZADOS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Acceso Denegado: X-Sakti-Token inválido o revocado de la firma."
        )
    return CLIENTES_AUTORIZADOS[api_key]  # Retorna el nombre de la empresa autenticada

class LogPayload(pydantic.BaseModel):
    client_ip: str
    log_entry: str

eventos_tiempo_real = asyncio.Queue()

@app.post("/api/v1/ingest")
# 🔒 Inyectamos la validación de la API Key como una dependencia obligatoria
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
            "resultado": f"[{empresa_cliente}] {resultado_brain}", # Añadimos contexto de la empresa en la UI
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