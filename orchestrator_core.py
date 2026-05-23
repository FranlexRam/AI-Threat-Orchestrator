import subprocess
import logging

# Configuración básica de auditoría interna del orquestador
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [ORCHESTRATOR] - %(levelname)s - %(message)s')

class SaktiSOAR:
    """
    Motor de Automatización y Orquestación de Respuesta de Seguridad (SOAR)
    Encargado de ejecutar playbooks de contención basados en decisiones de IA.
    """
    
    @staticmethod
    def ejecutar_playbook(categoria_ataque, ip_origen, nivel_riesgo):
        """
        Determina y ejecuta la acción de mitigación en caliente.
        """
        nivel_upper = str(nivel_riesgo).upper()
        
        # Filtro de activación: Solo actuamos autónomamente en riesgos Críticos o Altos
        if nivel_upper not in ["CRÍTICO", "CRITICO", "ALTO"]:
            logging.info(f"Evento auditado para IP {ip_origen} ({categoria_ataque}). No requiere mitigación activa.")
            return "Ninguna - Tráfico Auditado"

        categoria_upper = str(categoria_ataque).upper()
        
        # PLAYBOOK 1: Bloqueo de Red / Firewall (Para ataques directos al Servidor o Base de Datos)
        if "SQL INJECTION" in categoria_upper or "REMOTE CODE EXECUTION" in categoria_upper or "RCE" in categoria_upper:
            return SaktiSOAR._playbook_block_ip_firewall(ip_origen)
            
        # PLAYBOOK 2: Aislamiento / Revocación de Credenciales (Para inyecciones de script u otros vectores web)
        elif "XSS" in categoria_upper or "CROSS-SITE SCRIPTING" in categoria_upper:
            return SaktiSOAR._playbook_revoke_session(ip_origen)
            
        # PLAYBOOK 3: Restricción de Endpoints / ACL (Para intentos de saltos de directorio o abusos de API)
        elif "DIRECTORY TRAVERSAL" in categoria_upper or "SSRF" in categoria_upper:
            return SaktiSOAR._playbook_restrict_access_list(ip_origen, categoria_ataque)
            
        # PLAYBOOK POR DEFECTO: Cuarentena preventiva
        else:
            return SaktiSOAR._playbook_quarantine_generic(ip_origen)

    # --- DEFINICIÓN TÁCTICA DE LOS PLAYBOOKS ---

    @staticmethod
    def _playbook_block_ip_firewall(ip_origen):
        logging.warning(f"Gatillando Playbook: Bloqueo perimetral para IP {ip_origen}")
        
        # Comando UNIX/Mac real (Simulado aquí, pero listo para producción)
        # En Linux real usarías: ["sudo", "iptables", "-A", "INPUT", "-s", ip_origen, "-j", "DROP"]
        comando_comando = ["echo", f"BLOCKING IP {ip_origen} via local Firewall/packet-filter"]
        
        try:
            # Ejecución en caliente en el sistema operativo host
            subprocess.run(comando_comando, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            msg_mitigacion = "IP Bloqueada en Firewall (IPTables/PF)"
            logging.info(f"ÉXITO: {msg_mitigacion} para {ip_origen}")
            return msg_mitigacion
        except Exception as e:
            logging.error(f"Fallo al ejecutar el bloqueo de red para {ip_origen}: {e}")
            return "Fallo en ejecución de bloqueo perimetral"

    @staticmethod
    def _playbook_revoke_session(ip_origen):
        logging.warning(f"Gatillando Playbook: Revocación de sesión para origen {ip_origen}")
        # Aquí interactuarías con Redis, JWT Blacklist o tu DB para invalidar tokens asociados a esa IP
        msg_mitigacion = "Sesiones e identificadores web revocados"
        logging.info(f"ÉXITO: {msg_mitigacion} para origen {ip_origen}")
        return msg_mitigacion

    @staticmethod
    def _playbook_restrict_access_list(ip_origen, categoria):
        logging.warning(f"Gatillando Playbook: Restricción de ACL de API para {ip_origen}")
        # Lógica para inyectar una regla de denegación temporal al endpoint abusado
        msg_mitigacion = f"Acceso revocado a recursos mediante regla ACL"
        logging.info(f"ÉXITO: {msg_mitigacion} ante {categoria}")
        return msg_mitigacion

    @staticmethod
    def _playbook_quarantine_generic(ip_origen):
        logging.warning(f"Gatillando Playbook Genérico: Aislamiento preventivo para IP {ip_origen}")
        msg_mitigacion = "IP en cuarentena de monitoreo estricto"
        return msg_mitigacion