import asyncio
import urllib.parse
import datetime
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import pydantic
import json
# Importamos el motor analítico de tu brain.py actual
from brain import orchestrator_ai

# Inicializamos la plataforma API SaaS
app = FastAPI(
    title="SaktiShield Corporate API Ingestion Pipeline", 
    version="1.0.0",
    description="Endpoint universal de ingesta, filtro autolimpiante y streaming en tiempo real."
)

# 🌐 CONFIGURACIÓN CORS: Permite que tu Dashboard se conecte a la API sin bloqueos de seguridad
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # En producción se cambia por el dominio real de tu SaaS
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Estructura segura de datos para la ingesta
class LogPayload(pydantic.BaseModel):
    client_ip: str
    log_entry: str

# 🧠 COLA EN MEMORIA: Almacena los eventos críticos para empujarlos al Dashboard en tiempo real
eventos_tiempo_real = asyncio.Queue()

@app.post("/api/v1/ingest")
async def ingestar_log_corporativo(payload: LogPayload):
    """
    Endpoint Ejecutivo: Recibe logs, aplica filtro autolimpiante en RAM y, 
    si es una amenaza, la despacha al cerebro y la transmite en vivo al Dashboard.
    """
    try:
        ip_cliente = payload.client_ip
        log_crudo = payload.log_entry
        
        # 🛡️ FILTRO AUTOLIMPIANTE EN RAM (Pre-Análisis ultra veloz)
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
                    "message": "Filtro Autolimpiante: Solicitud rutinaria aprobada en el perímetro."
                }
            )
            
        # 🧠 ESCALABILIDAD SOC: Alerta activada, invocamos el núcleo analítico
        print(f"\n[🚀 API PIPELINE]: Alerta perimetral activada para IP {ip_cliente}. Escalando al núcleo...")
        resultado_brain = orchestrator_ai(log_crudo, client_ip=ip_cliente)
        
        # 📡 TIEMPO REAL: Estructuramos un paquete ligero con la alerta para el Dashboard
        # Extraemos la categoría y el riesgo de forma limpia para la interfaz gráfica
        partes = resultado_brain.split(" - ")
        status_final = partes[0]
        meta_datos = partes[1] if len(partes) > 1 else ""
        
        alerta_dashboard = {
            "ip": ip_cliente,
            "log": log_crudo,
            "resultado": resultado_brain,
            "status": status_final,
            "timestamp": datetime.datetime.now().strftime('%H:%M:%S')
        }
        
        # Inyectamos la alerta en la cola asíncrona para que el stream la capture de inmediato
        await eventos_tiempo_real.put(alerta_dashboard)
        
        return {
            "status": "PROCESADO",
            "code": "AMENAZA_EVALUADA",
            "decision_core": resultado_brain,
            "message": "Evento analizado por el Motor de Correlación y transmitido en tiempo real."
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fallo crítico en el pipeline corporativo: {str(e)}")

# 📡 ENDPOINT DE STREAMING (SSE): Aquí se conectará tu frontend para escuchar alertas en vivo
@app.get("/api/v1/stream")
async def stream_incidentes(request: Request):
    """
    Endpoint SSE: Mantiene una conexión abierta con el Dashboard para empujar
    alertas en el milisegundo exacto en que ocurren.
    """
    async def generador_eventos():
        while True:
            # Si el cliente cierra la pestaña del Dashboard, desconectamos el canal para liberar RAM
            if await request.is_disconnected():
                print("[📡 STREAM]: Dashboard desconectado del canal en tiempo real.")
                break
                
            try:
                # Esperamos de forma asíncrona a que caiga una nueva alerta en la cola
                # timeout de 1 segundo para verificar constantemente si el cliente sigue conectado
                alerta = await asyncio.wait_for(eventos_tiempo_real.get(), timeout=1.0)
                
                # El protocolo SSE requiere estrictamente el formato: "data: <mensaje>\n\n"
                yield f"data: {json.dumps(alerta)}\n\n"
                
            except asyncio.TimeoutError:
                # Si no hay ataques en ese segundo, el ciclo continúa esperando de forma limpia
                continue

    return StreamingResponse(generador_eventos(), media_type="text/event-stream")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api_ingest:app", host="0.0.0.0", port=8000, reload=True)