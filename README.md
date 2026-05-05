# AI-Powered Threat Orchestrator (MVP) 🛡️

## Descripción
Este es un orquestador de seguridad inteligente desarrollado en Python que utiliza Inteligencia Artificial local (**Llama 3.2 via Ollama**) para analizar logs de red en tiempo real y automatizar respuestas de defensa.

## Características
* **Análisis Cognitivo**: Identifica ataques de Inyección SQL, XSS y Path Traversal mediante procesamiento de lenguaje natural.
* **Respuesta Automatizada**: Genera automáticamente una `blacklist.txt` con las IPs de los atacantes para su integración con Firewalls.
* **Privacidad Total**: Todo el procesamiento se realiza localmente en un chip **Apple M2**, sin enviar datos a la nube.

## Tecnologías
* Python 3.9
* Ollama (Llama 3.2:1b)
* Git / GitHub

## Cómo ejecutarlo
1. Instala Ollama y descarga el modelo: `ollama run llama3.2:1b`.
2. Clona este repositorio.
3. Ejecuta `python3 brain.py`.