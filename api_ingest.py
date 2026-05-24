import urllib.parse
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
import pydantic
# Importamos el motor analítico de tu brain.py actual
from brain import orchestrator_ai

# Inicializamos la plataforma API SaaS
app = FastAPI(
    title="SaktiShield Corporate API Ingestion Pipeline", 
    version="1.0.0",
    description="Endpoint universal de ingesta y filtro autolimpiante para auditoría perimetral."
)

# Definimos la estructura segura de datos que deben enviar los clientes (Modelo Pydantic)
class LogPayload(pydantic.BaseModel):
    client_ip: str
    log_entry: str

@app.post("/api/v1/ingest")
async def ingestar_log_corporativo(payload: LogPayload):
    """
    Endpoint Ejecutivo: Recibe logs en tiempo real, aplica el filtro autolimpiante
    en memoria RAM y decide si escalar a la IA o mitigar pasivamente.
    """
    try:
        # Extraemos las variables de forma limpia
        ip_cliente = payload.client_ip
        log_crudo = payload.log_entry
        
        # 🛡️ FILTRO AUTOLIMPIANTE EN RAM (Pre-Análisis ultra veloz para cuidar márgenes)
        log_decoded = urllib.parse.unquote(log_crudo).replace('+', ' ').upper()
        
        # Lista de firmas de peligro estructural básico (Regex simplificado en memoria)
        patrones_peligro = [
            "<SCRIPT", "SCRIPT>", "ALERT(", "UNION", "SELECT", 
            "../", "..\\", "/ETC/PASSWD", "WHOAMI", "LOCALHOST", "127.0.0.1"
        ]
        
        # Evaluamos en microsegundos si el log requiere atención de la IA
        requiere_ia = any(patron in log_decoded for patron in patrones_peligro)
        
        if not requiere_ia:
            # 🟢 FILTRO ACTIVO: Tráfico rutinario. Destruimos de memoria RAM de inmediato.
            # No toca base de datos, no gasta procesamiento de Ollama. Costo operativo = $0.
            return JSONResponse(
                status_code=200,
                content={
                    "status": "PERMITIDO",
                    "code": "TRAFICO_LEGITIMO",
                    "message": "Filtro Autolimpiante: Solicitud rutinaria aprobada en el perímetro."
                }
            )
            
        # 🧠 ESCALABILIDAD SOC: Al activar una firma de peligro, invocamos tu brain.py
        # El sistema ejecuta la correlación por ventanas de tiempo de esa IP y mitiga con el SOAR
        print(f"\n[🚀 API PIPELINE]: Alerta perimetral activada para IP {ip_cliente}. Escalando al núcleo analítico...")
        resultado_brain = orchestrator_ai(log_crudo, client_ip=ip_cliente)
        
        return {
            "status": "PROCESADO",
            "code": "AMENAZA_EVALUADA",
            "decision_core": resultado_brain,
            "message": "Evento analizado por el Motor de Correlación y mitigado de forma autónoma."
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fallo crítico en el pipeline corporativo: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    # Corremos el servidor empresarial en el puerto 8000
    uvicorn.run("api_ingest:app", host="0.0.0.0", port=8000, reload=True)