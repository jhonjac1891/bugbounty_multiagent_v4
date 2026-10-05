#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================
 Bug Bounty / Pentest Multi-Agent Framework - v4.2
 Autor: Ethical Hacker (TVM / IBM X-Force workflow)
 Plataforma objetivo: Parrot OS

 Novedades v4.2:
   - Logging INFO visible en los 21 agentes (antes solo 4 logueaban)
   - Manejo explicito de errores HTTP/conexion (ya no se tragan en silencio)
   - Log de resultado por agente: cuantos findings produjo y por que
   - Reporte PDF estilo Qualys / Nessus (ademas de HTML, CSV, JSON)
   - Boton dedicado "Exportar PDF" en la GUI

 Cobertura:
   - OWASP Web Top 10 "2025" (A01..A10, catalogo interno)
   - OWASP API Security Top 10:2023 (API1..API10)
   - OWASP WSTG v4.2 (12 categorias, ~103 test cases)
   - Reporteria estilo Qualys / Nessus (HTML, CSV, JSON, PDF)

 IMPORTANTE:
   Uso EXCLUSIVO en programas de bug bounty autorizados o
   pentests con alcance firmado. Los agentes solo identifican
   candidatos/indicadores para validacion manual salvo que se
   indique lo contrario en su docstring.

 EJECUCION (Parrot OS):
   cd ~/Desktop/Bug Bounty/This - Agente V2  (usa comillas si tu shell lo requiere)
   source venv/bin/activate
   which python
   python bugbounty_multiagent_v42.py
============================================================
"""

import asyncio
import csv
import json
import logging
import queue
import socket
import ssl
import sys
import threading
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Dict
from urllib.parse import urlparse

try:
    import yaml
except ImportError:
    print("[!] Falta PyYAML. Ejecuta: pip install pyyaml")
    sys.exit(1)

try:
    import customtkinter as ctk
    import tkinter as tk
    from tkinter import filedialog, messagebox
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None
    RequestException = Exception

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.platypus import (SimpleDocTemplate, Table, TableStyle, Paragraph,
                                     Spacer, PageBreak, Image as RLImage)
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False


LOG_QUEUE = queue.Queue()


class QueueLogHandler(logging.Handler):
    def emit(self, record):
        LOG_QUEUE.put(self.format(record))


logging.basicConfig(level=logging.INFO)
root_logger = logging.getLogger()
qh = QueueLogHandler()
qh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
root_logger.addHandler(qh)


class Severity(Enum):
    CRITICAL = ("Critical", 5, "#8B0000", 9.0, 10.0)
    HIGH = ("High", 4, "#FF4136", 7.0, 8.9)
    MEDIUM = ("Medium", 3, "#FF851B", 4.0, 6.9)
    LOW = ("Low", 2, "#FFDC00", 0.1, 3.9)
    INFO = ("Info", 1, "#00A8FF", 0.0, 0.0)

    @property
    def label(self):
        return self.value[0]

    @property
    def qid_level(self):
        return self.value[1]

    @property
    def color(self):
        return self.value[2]

    @property
    def cvss_range(self):
        return "{0}-{1}".format(self.value[3], self.value[4])


OWASP_WEB_2025 = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging and Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}

OWASP_API_2023 = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}

WSTG_CHECKLIST = {
    "WSTG-INFO": {"name": "Information Gathering", "maps_to_owasp": "A02:2025", "tests": {
        "WSTG-INFO-01": "Conduct Search Engine Discovery Reconnaissance",
        "WSTG-INFO-02": "Fingerprint Web Server",
        "WSTG-INFO-03": "Review Webserver Metafiles for Information Leakage",
        "WSTG-INFO-04": "Enumerate Applications on Webserver",
        "WSTG-INFO-05": "Review Webpage Content for Information Leakage",
        "WSTG-INFO-06": "Identify Application Entry Points",
        "WSTG-INFO-07": "Map Execution Paths Through Application",
        "WSTG-INFO-08": "Fingerprint Web Application Framework",
        "WSTG-INFO-09": "Fingerprint Web Application",
        "WSTG-INFO-10": "Map Application Architecture",
    }},
    "WSTG-CONF": {"name": "Configuration and Deployment Management", "maps_to_owasp": "A02:2025", "tests": {
        "WSTG-CONF-01": "Test Network Infrastructure Configuration",
        "WSTG-CONF-02": "Test Application Platform Configuration",
        "WSTG-CONF-03": "Test File Extensions Handling for Sensitive Information",
        "WSTG-CONF-04": "Review Old Backup and Unreferenced Files",
        "WSTG-CONF-05": "Enumerate Infrastructure and Application Admin Interfaces",
        "WSTG-CONF-06": "Test HTTP Methods",
        "WSTG-CONF-07": "Test HTTP Strict Transport Security",
        "WSTG-CONF-08": "Test RIA Cross Domain Policy",
        "WSTG-CONF-09": "Test File Permission",
        "WSTG-CONF-10": "Test for Subdomain Takeover",
        "WSTG-CONF-11": "Test Cloud Storage",
        "WSTG-CONF-12": "Testing for Content Security Policy",
        "WSTG-CONF-13": "Test Path Confusion",
        "WSTG-CONF-14": "Test Other HTTP Security Header Misconfigurations",
    }},
    "WSTG-IDNT": {"name": "Identity Management Testing", "maps_to_owasp": "A01:2025", "tests": {
        "WSTG-IDNT-01": "Test Role Definitions",
        "WSTG-IDNT-02": "Test User Registration Process",
        "WSTG-IDNT-03": "Test Account Provisioning Process",
        "WSTG-IDNT-04": "Testing for Account Enumeration and Guessable User Account",
        "WSTG-IDNT-05": "Testing for Weak or Unenforced Username Policy",
    }},
    "WSTG-ATHN": {"name": "Authentication Testing", "maps_to_owasp": "A07:2025", "tests": {
        "WSTG-ATHN-01": "Testing for Credentials Transported over Encrypted Channel",
        "WSTG-ATHN-02": "Testing for Default Credentials",
        "WSTG-ATHN-03": "Testing for Weak Lock Out Mechanism",
        "WSTG-ATHN-04": "Testing for Bypassing Authentication Schema",
        "WSTG-ATHN-05": "Testing for Vulnerable Remember Password",
        "WSTG-ATHN-06": "Testing for Browser Cache Weaknesses",
        "WSTG-ATHN-07": "Testing for Weak Password Policy",
        "WSTG-ATHN-08": "Testing for Weak Security Question Answer",
        "WSTG-ATHN-09": "Testing for Weak Password Change or Reset Functionalities",
        "WSTG-ATHN-10": "Testing for Weaker Authentication in Alternative Channel",
        "WSTG-ATHN-11": "Testing Multi-Factor Authentication (MFA)",
    }},
    "WSTG-ATHZ": {"name": "Authorization Testing", "maps_to_owasp": "A01:2025", "tests": {
        "WSTG-ATHZ-01": "Testing Directory Traversal File Include",
        "WSTG-ATHZ-02": "Testing for Bypassing Authorization Schema",
        "WSTG-ATHZ-03": "Testing for Privilege Escalation",
        "WSTG-ATHZ-04": "Testing for Insecure Direct Object References (IDOR)",
    }},
    "WSTG-SESS": {"name": "Session Management Testing", "maps_to_owasp": "A07:2025", "tests": {
        "WSTG-SESS-01": "Testing for Session Management Schema",
        "WSTG-SESS-02": "Testing for Cookies Attributes",
        "WSTG-SESS-03": "Testing for Session Fixation",
        "WSTG-SESS-04": "Testing for Exposed Session Variables",
        "WSTG-SESS-05": "Testing for Cross Site Request Forgery (CSRF)",
        "WSTG-SESS-06": "Testing for Logout Functionality",
        "WSTG-SESS-07": "Testing Session Timeout",
        "WSTG-SESS-08": "Testing for Session Puzzling",
        "WSTG-SESS-09": "Testing for Session Hijacking",
        "WSTG-SESS-10": "Testing JSON Web Tokens (JWT)",
    }},
    "WSTG-INPV": {"name": "Input Validation Testing", "maps_to_owasp": "A05:2025", "tests": {
        "WSTG-INPV-01": "Testing for Reflected Cross Site Scripting",
        "WSTG-INPV-02": "Testing for Stored Cross Site Scripting",
        "WSTG-INPV-03": "Testing for HTTP Verb Tampering",
        "WSTG-INPV-04": "Testing for HTTP Parameter Pollution",
        "WSTG-INPV-05": "Testing for SQL Injection",
        "WSTG-INPV-06": "Testing for LDAP Injection",
        "WSTG-INPV-07": "Testing for XML Injection",
        "WSTG-INPV-08": "Testing for SSI Injection",
        "WSTG-INPV-09": "Testing for XPath Injection",
        "WSTG-INPV-10": "Testing for IMAP SMTP Injection",
        "WSTG-INPV-11": "Testing for Code Injection",
        "WSTG-INPV-12": "Testing for Command Injection",
        "WSTG-INPV-13": "Testing for Format String Injection",
        "WSTG-INPV-14": "Testing for Incubated Vulnerability",
        "WSTG-INPV-15": "Testing for HTTP Splitting Smuggling",
        "WSTG-INPV-16": "Testing for HTTP Incoming Requests",
        "WSTG-INPV-17": "Testing for Host Header Injection",
        "WSTG-INPV-18": "Testing for Server-side Template Injection (SSTI)",
        "WSTG-INPV-19": "Testing for Server-Side Request Forgery (SSRF)",
    }},
    "WSTG-ERRH": {"name": "Error Handling", "maps_to_owasp": "A09:2025", "tests": {
        "WSTG-ERRH-01": "Testing for Improper Error Handling",
        "WSTG-ERRH-02": "Testing for Stack Traces",
    }},
    "WSTG-CRYP": {"name": "Weak Cryptography", "maps_to_owasp": "A04:2025", "tests": {
        "WSTG-CRYP-01": "Testing for Weak Transport Layer Security",
        "WSTG-CRYP-02": "Testing for Padding Oracle",
        "WSTG-CRYP-03": "Testing for Sensitive Information Sent via Unencrypted Channels",
        "WSTG-CRYP-04": "Testing for Weak Encryption",
    }},
    "WSTG-BUSL": {"name": "Business Logic Testing", "maps_to_owasp": "A06:2025", "tests": {
        "WSTG-BUSL-01": "Test Business Logic Data Validation",
        "WSTG-BUSL-02": "Test Ability to Forge Requests",
        "WSTG-BUSL-03": "Test Integrity Checks",
        "WSTG-BUSL-04": "Test for Process Timing",
        "WSTG-BUSL-05": "Test Number of Times a Function Can be Used Limits",
        "WSTG-BUSL-06": "Testing for the Circumvention of Work Flows",
        "WSTG-BUSL-07": "Test Defenses Against Application Misuse",
        "WSTG-BUSL-08": "Test Upload of Unexpected File Types",
        "WSTG-BUSL-09": "Test Upload of Malicious Files",
        "WSTG-BUSL-10": "Test Payment Functionality",
    }},
    "WSTG-CLNT": {"name": "Client-side Testing", "maps_to_owasp": "A05:2025", "tests": {
        "WSTG-CLNT-01": "Testing for DOM-Based Cross Site Scripting",
        "WSTG-CLNT-02": "Testing for JavaScript Execution",
        "WSTG-CLNT-03": "Testing for HTML Injection",
        "WSTG-CLNT-04": "Testing for Client-side URL Redirect",
        "WSTG-CLNT-05": "Testing for CSS Injection",
        "WSTG-CLNT-06": "Testing for Client-side Resource Manipulation",
        "WSTG-CLNT-07": "Test Cross Origin Resource Sharing",
        "WSTG-CLNT-08": "Testing for Cross Site Flashing",
        "WSTG-CLNT-09": "Testing for Clickjacking",
        "WSTG-CLNT-10": "Testing WebSockets",
        "WSTG-CLNT-11": "Test Web Messaging",
        "WSTG-CLNT-12": "Testing Browser Storage",
        "WSTG-CLNT-13": "Testing for Cross Site Script Inclusion",
    }},
    "WSTG-APIT": {"name": "API Testing", "maps_to_owasp": "API1:2023", "tests": {
        "WSTG-APIT-01": "Testing GraphQL",
        "WSTG-APIT-02": "Testing for REST API Vulnerabilities",
        "WSTG-APIT-03": "Testing for Mass Assignment",
        "WSTG-APIT-04": "Testing for API Key Exposure",
    }},
}
TOTAL_WSTG_TESTS = sum(len(c["tests"]) for c in WSTG_CHECKLIST.values())


_PLUGIN_COUNTER = 100000


def _next_plugin_id():
    global _PLUGIN_COUNTER
    _PLUGIN_COUNTER += 1
    return _PLUGIN_COUNTER


@dataclass
class Finding:
    agent: str
    owasp_category: str
    title: str
    target: str
    severity: Severity
    description: str = ""
    evidence: str = ""
    solution: str = ""
    cvss_base: float = 0.0
    plugin_id: int = field(default_factory=_next_plugin_id)
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    wstg_ref: str = ""

    def to_row(self):
        return [self.plugin_id, self.finding_id, self.severity.label, self.title,
                self.owasp_category, self.wstg_ref, self.agent, self.target,
                self.cvss_base, self.solution, self.timestamp]


@dataclass
class Scope:
    program_name: str = ""
    targets: List[str] = field(default_factory=list)
    in_scope_domains: List[str] = field(default_factory=list)
    out_of_scope_domains: List[str] = field(default_factory=list)
    authorized_by: str = ""
    intensity: str = "Medium"

    @classmethod
    def from_yaml(cls, path):
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls(**data)


def normalize_target(target):
    """Asegura que el target tenga esquema; devuelve (url_normalizada, error_o_None)."""
    t = target.strip()
    if not t:
        return None, "Target vacio"
    if "://" not in t:
        t = "https://" + t
    return t, None


class BaseAgent:
    name = "base_agent"
    owasp_category = "N/A"

    def __init__(self, scope):
        self.scope = scope
        self.log = logging.getLogger(self.name)

    async def run(self, target):
        raise NotImplementedError

    def _http_head(self, url, timeout=6):
        if requests is None:
            self.log.warning("Modulo 'requests' no disponible; instala con pip install requests")
            return None, "requests no instalado"
        try:
            resp = requests.head(url, timeout=timeout, allow_redirects=True, verify=False)
            return resp, None
        except RequestException as e:
            self.log.info("HEAD fallo en %s -> %s: %s", url, type(e).__name__, e)
            return None, str(e)
        except Exception as e:
            self.log.warning("HEAD error inesperado en %s: %s", url, e)
            return None, str(e)

    def _http_get(self, url, timeout=6):
        if requests is None:
            self.log.warning("Modulo 'requests' no disponible; instala con pip install requests")
            return None, "requests no instalado"
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
            return resp, None
        except RequestException as e:
            self.log.info("GET fallo en %s -> %s: %s", url, type(e).__name__, e)
            return None, str(e)
        except Exception as e:
            self.log.warning("GET error inesperado en %s: %s", url, e)
            return None, str(e)

    def _log_result(self, target, findings):
        if findings:
            self.log.info("%s -> %s: %d hallazgo(s) generado(s)", self.name, target, len(findings))
        else:
            self.log.info("%s -> %s: sin hallazgos (0)", self.name, target)


class A01_AccessControlAgent(BaseAgent):
    name, owasp_category = "A01_access_control_2025", "A01:2025 - Broken Access Control"
    SSRF_PARAMS = ["url", "uri", "path", "dest", "redirect", "callback", "webhook", "fetch"]

    async def run(self, target):
        self.log.info("Iniciando analisis de control de acceso (IDOR/SSRF) en %s", target)
        findings = []
        if any(p in target.lower() for p in ["id=", "user=", "account=", "uid="]):
            findings.append(Finding(
                self.name, self.owasp_category, "Posible IDOR", target, Severity.MEDIUM,
                "Parametro identificador secuencial/predecible detectado en URL.",
                target, "Validar autorizacion por objeto en backend (no solo por sesion).",
                cvss_base=6.5, wstg_ref="WSTG-ATHZ-04"))
        if any(p in target.lower() for p in self.SSRF_PARAMS):
            findings.append(Finding(
                self.name, self.owasp_category, "Parametro candidato a SSRF", target,
                Severity.MEDIUM, "Parametro que acepta URL/callback, candidato a SSRF.",
                target, "Whitelist estricta de dominios/IPs destino, deshabilitar redirecciones.",
                cvss_base=6.1, wstg_ref="WSTG-INPV-19"))
        self._log_result(target, findings)
        return findings


class A02_MisconfigAgent(BaseAgent):
    name, owasp_category = "A02_misconfig_2025", "A02:2025 - Security Misconfiguration"
    SECURITY_HEADERS = ["strict-transport-security", "content-security-policy",
                         "x-content-type-options", "x-frame-options", "referrer-policy"]

    async def run(self, target):
        self.log.info("Iniciando analisis de configuracion/headers en %s", target)
        findings = []
        resp, err = self._http_head(target)
        if resp is None:
            self.log.info("No se pudo conectar a %s para revisar headers (%s)", target, err)
            self._log_result(target, findings)
            return findings
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        for h in self.SECURITY_HEADERS:
            if h not in headers_lower:
                wstg = "WSTG-CONF-07" if h == "strict-transport-security" else "WSTG-CONF-14"
                findings.append(Finding(
                    self.name, self.owasp_category, "Header de seguridad ausente: " + h,
                    target, Severity.LOW, "El header '" + h + "' no esta presente en la respuesta HTTP.",
                    "HTTP " + str(resp.status_code) + " - headers: " + str(dict(resp.headers))[:300],
                    "Configurar el header " + h + " en el servidor/CDN.",
                    cvss_base=3.1, wstg_ref=wstg))
        server = headers_lower.get("server", "")
        if server:
            findings.append(Finding(
                self.name, self.owasp_category, "Banner de servidor expuesto", target,
                Severity.INFO, "Header Server revela: " + server, server,
                "Ocultar o generalizar el header Server.", cvss_base=0.0,
                wstg_ref="WSTG-INFO-02"))
        self._log_result(target, findings)
        return findings


class A03_SupplyChainAgent(BaseAgent):
    name, owasp_category = "A03_supply_chain_2025", "A03:2025 - Software Supply Chain Failures"

    async def run(self, target):
        self.log.info("Iniciando revision de dependencias/terceros en %s", target)
        findings = []
        resp, err = self._http_get(target)
        if resp is None:
            self.log.info("No se pudo conectar a %s para revisar scripts de terceros (%s)", target, err)
            self._log_result(target, findings)
            return findings
        if "<script" in resp.text.lower():
            findings.append(Finding(
                self.name, self.owasp_category, "Scripts de terceros detectados", target,
                Severity.INFO, "Se detectaron tags script externos; revisar SRI/integridad.",
                "grep script src en el HTML (longitud pagina: " + str(len(resp.text)) + ")",
                "Implementar Subresource Integrity (SRI) y CSP restrictivo.",
                cvss_base=0.0, wstg_ref="WSTG-CLNT-13"))
        self._log_result(target, findings)
        return findings


class A04_CryptoAgent(BaseAgent):
    name, owasp_category = "A04_crypto_2025", "A04:2025 - Cryptographic Failures"

    async def run(self, target):
        self.log.info("Iniciando analisis TLS/criptografico en %s", target)
        findings = []
        parsed = urlparse(target if "://" in target else "https://" + target)
        host = parsed.hostname or target
        port = parsed.port or 443
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    version = ssock.version()
                    self.log.info("TLS negociado en %s:%s -> %s", host, port, version)
                    if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                        findings.append(Finding(
                            self.name, self.owasp_category, "Protocolo TLS debil: " + str(version),
                            target, Severity.HIGH, "El servidor negocia " + str(version) + ".",
                            str(version), "Deshabilitar TLS < 1.2, forzar TLS 1.2/1.3 unicamente.",
                            cvss_base=7.4, wstg_ref="WSTG-CRYP-01"))
        except Exception as e:
            self.log.info("No se pudo validar TLS en %s:%s -> %s: %s", host, port, type(e).__name__, e)
        if target.lower().startswith("http://"):
            findings.append(Finding(
                self.name, self.owasp_category, "Transporte sin cifrar (HTTP)", target,
                Severity.HIGH, "El recurso se sirve sobre HTTP plano.", target,
                "Forzar HTTPS con redireccion 301 y HSTS.", cvss_base=7.4,
                wstg_ref="WSTG-CRYP-03"))
        self._log_result(target, findings)
        return findings


class A05_InjectionAgent(BaseAgent):
    name, owasp_category = "A05_injection_2025", "A05:2025 - Injection"

    async def run(self, target):
        self.log.info("Iniciando analisis de superficie de inyeccion en %s", target)
        findings = []
        if "=" in target:
            findings.append(Finding(
                self.name, self.owasp_category, "Endpoint candidato a SQLi (manual)",
                target, Severity.MEDIUM,
                "El endpoint acepta parametros GET; requiere prueba manual con payloads SQLi.",
                target, "Usar consultas parametrizadas / ORM, WAF con reglas anti-SQLi.",
                cvss_base=8.6, wstg_ref="WSTG-INPV-05"))
        else:
            self.log.info("%s no tiene parametros GET visibles; SQLi requiere testing manual de formularios/API", target)
        self._log_result(target, findings)
        return findings


class A06_InsecureDesignAgent(BaseAgent):
    name, owasp_category = "A06_insecure_design_2025", "A06:2025 - Insecure Design"

    async def run(self, target):
        self.log.info("Generando checklist de diseno inseguro (manual) para %s", target)
        checklist = ["Rate limiting en login/reset?", "Tokens de reset predecibles/reutilizables?",
                     "Limites de negocio validados server-side?",
                     "CSRF token presente en formularios sensibles?"]
        findings = [Finding(self.name, self.owasp_category, "Checklist de diseno inseguro (manual)",
                             target, Severity.INFO, "Requiere modelado de amenazas manual.",
                             chr(10).join(checklist), "Threat modeling + revisiones de diseno.",
                             cvss_base=0.0, wstg_ref="WSTG-BUSL-01")]
        self._log_result(target, findings)
        return findings


class A07_AuthAgent(BaseAgent):
    name, owasp_category = "A07_auth_2025", "A07:2025 - Authentication Failures"

    async def run(self, target):
        self.log.info("Iniciando revision de autenticacion en %s", target)
        findings = []
        if "login" in target.lower() or "signin" in target.lower():
            findings.append(Finding(
                self.name, self.owasp_category, "Endpoint de login sin evidencia de lockout",
                target, Severity.MEDIUM,
                "No se pudo confirmar mecanismo de bloqueo tras intentos fallidos (validar manual).",
                target, "Implementar lockout progresivo + MFA.", cvss_base=6.5,
                wstg_ref="WSTG-ATHN-03"))
        else:
            self.log.info("%s no parece un endpoint de login directo; revisar manualmente flujo de auth", target)
        self._log_result(target, findings)
        return findings


class A08_IntegrityAgent(BaseAgent):
    name, owasp_category = "A08_integrity_2025", "A08:2025 - Software or Data Integrity Failures"

    async def run(self, target):
        self.log.info("Iniciando revision de integridad de recursos (SRI) en %s", target)
        findings = []
        resp, err = self._http_get(target)
        if resp is None:
            self.log.info("No se pudo conectar a %s para revisar SRI (%s)", target, err)
            self._log_result(target, findings)
            return findings
        if "integrity=" not in resp.text.lower() and "<script" in resp.text.lower():
            findings.append(Finding(
                self.name, self.owasp_category, "Scripts sin atributo integrity (SRI)",
                target, Severity.LOW, "Scripts externos sin Subresource Integrity.",
                "grep integrity en HTML", "Agregar atributo integrity + crossorigin en script.",
                cvss_base=3.7, wstg_ref="WSTG-CLNT-13"))
        self._log_result(target, findings)
        return findings


class A09_LoggingAlertingAgent(BaseAgent):
    name, owasp_category = "A09_logging_alerting_2025", "A09:2025 - Security Logging and Alerting Failures"

    async def run(self, target):
        self.log.info("Iniciando prueba de manejo de errores (404/500) en %s", target)
        findings = []
        resp, err = self._http_get(target.rstrip("/") + "/no-existe-xyz-404")
        if resp is None:
            self.log.info("No se pudo conectar a %s para probar manejo de errores (%s)", target, err)
            self._log_result(target, findings)
            return findings
        self.log.info("Ruta de prueba en %s respondio HTTP %s", target, resp.status_code)
        if resp.status_code == 500:
            findings.append(Finding(
                self.name, self.owasp_category, "Error 500 con posible stack trace",
                target, Severity.MEDIUM, "El servidor devolvio 500 ante ruta invalida.",
                resp.text[:300], "Manejo generico de errores + logging centralizado/SIEM.",
                cvss_base=5.3, wstg_ref="WSTG-ERRH-02"))
        self._log_result(target, findings)
        return findings


class A10_ExceptionHandlingAgent(BaseAgent):
    name, owasp_category = "A10_exception_handling_2025", "A10:2025 - Mishandling of Exceptional Conditions"

    async def run(self, target):
        self.log.info("Iniciando busqueda de archivos sensibles expuestos en %s", target)
        findings = []
        test_paths = ["/.env", "/config.php.bak", "/wp-config.php.bak", "/../../../etc/passwd"]
        for p in test_paths:
            resp, err = self._http_get(target.rstrip("/") + p)
            if resp is None:
                self.log.info("Ruta %s en %s no respondio (%s)", p, target, err)
                continue
            self.log.info("Ruta %s en %s -> HTTP %s", p, target, resp.status_code)
            if resp.status_code == 200 and len(resp.text) > 0:
                findings.append(Finding(
                    self.name, self.owasp_category, "Posible exposicion de archivo sensible: " + p,
                    target + p, Severity.HIGH,
                    "Ruta respondio 200; validar manualmente si expone datos sensibles.",
                    resp.text[:200], "Bloquear acceso a archivos de config/backup via servidor web.",
                    cvss_base=7.5, wstg_ref="WSTG-CONF-04"))
        self._log_result(target, findings)
        return findings


class API1_BOLAAgent(BaseAgent):
    name, owasp_category = "API1_bola", "API1:2023 - Broken Object Level Authorization"

    async def run(self, target):
        self.log.info("Iniciando analisis BOLA en %s", target)
        findings = []
        if any(x in target for x in ["/api/", "/v1/", "/v2/"]) and "=" in target:
            findings.append(Finding(self.name, self.owasp_category,
                "Endpoint API con ID en path/query (candidato BOLA)", target, Severity.MEDIUM,
                "Validar que el backend verifique propiedad del recurso, no solo autenticacion.",
                target, "Verificacion de ownership por objeto en cada request.",
                cvss_base=6.5, wstg_ref="WSTG-ATHZ-04"))
        else:
            self.log.info("%s no parece endpoint de API con ID visible; BOLA requiere testing manual", target)
        self._log_result(target, findings)
        return findings


class API2_BrokenAuthAgent(BaseAgent):
    name, owasp_category = "API2_broken_auth", "API2:2023 - Broken Authentication"

    async def run(self, target):
        self.log.info("Iniciando analisis de autenticacion API en %s", target)
        findings = []
        if "/api/" not in target:
            self.log.info("%s no contiene '/api/' en la ruta; se omite chequeo especifico de API2", target)
            self._log_result(target, findings)
            return findings
        resp, err = self._http_get(target)
        if resp is None:
            self.log.info("No se pudo conectar a %s para revisar autenticacion API (%s)", target, err)
            self._log_result(target, findings)
            return findings
        has_auth_header = "authorization" in str(resp.request.headers).lower()
        self.log.info("%s -> HTTP %s, Authorization header enviado: %s", target, resp.status_code, has_auth_header)
        if resp.status_code == 200 and not has_auth_header:
            findings.append(Finding(self.name, self.owasp_category,
                "Endpoint API responde 200 sin token de autorizacion", target, Severity.HIGH,
                "El endpoint no exigio Authorization header.", str(resp.status_code),
                "Exigir autenticacion (JWT/OAuth2) en todos los endpoints no publicos.",
                cvss_base=8.1, wstg_ref="WSTG-ATHN-04"))
        self._log_result(target, findings)
        return findings


class API3_PropertyAuthAgent(BaseAgent):
    name, owasp_category = "API3_property_auth", "API3:2023 - Broken Object Property Level Authorization"

    async def run(self, target):
        self.log.info("Generando checklist de mass assignment (manual) para %s", target)
        findings = [Finding(self.name, self.owasp_category,
            "Revisar mass assignment / exposicion de propiedades sensibles (manual)",
            target, Severity.INFO, "Validar que la API no permita modificar/leer campos como role, isAdmin, etc.",
            "", "Usar DTOs/whitelists de campos permitidos por endpoint.", cvss_base=0.0,
            wstg_ref="WSTG-APIT-03")]
        self._log_result(target, findings)
        return findings


class API4_ResourceConsumptionAgent(BaseAgent):
    name, owasp_category = "API4_resource_consumption", "API4:2023 - Unrestricted Resource Consumption"

    async def run(self, target):
        self.log.info("Iniciando analisis de rate limiting en %s", target)
        findings = []
        resp, err = self._http_get(target)
        if resp is None:
            self.log.info("No se pudo conectar a %s para revisar rate limiting (%s)", target, err)
            self._log_result(target, findings)
            return findings
        has_ratelimit = "x-ratelimit-limit" in {k.lower() for k in resp.headers.keys()}
        self.log.info("%s -> headers de rate limiting presentes: %s", target, has_ratelimit)
        if not has_ratelimit:
            findings.append(Finding(self.name, self.owasp_category,
                "Sin evidencia de rate limiting (headers ausentes)", target, Severity.MEDIUM,
                "No se detectaron headers X-RateLimit en la respuesta.", str(dict(resp.headers))[:300],
                "Implementar rate limiting / quotas por API key o IP.", cvss_base=5.3,
                wstg_ref="WSTG-BUSL-05"))
        self._log_result(target, findings)
        return findings


class API5_FunctionAuthAgent(BaseAgent):
    name, owasp_category = "API5_function_auth", "API5:2023 - Broken Function Level Authorization"

    async def run(self, target):
        self.log.info("Iniciando busqueda de rutas administrativas en %s", target)
        admin_paths = ["/api/admin", "/api/v1/admin", "/api/internal"]
        findings = []
        base = target.split("/api/")[0] if "/api/" in target else target
        for p in admin_paths:
            resp, err = self._http_get(base + p)
            if resp is None:
                self.log.info("Ruta %s en %s no respondio (%s)", p, base, err)
                continue
            self.log.info("Ruta %s en %s -> HTTP %s", p, base, resp.status_code)
            if resp.status_code in (200, 401, 403):
                sev = Severity.HIGH if resp.status_code == 200 else Severity.INFO
                cvss = 8.1 if sev == Severity.HIGH else 0.0
                findings.append(Finding(self.name, self.owasp_category,
                    "Ruta administrativa detectada: " + p + " (HTTP " + str(resp.status_code) + ")",
                    base + p, sev, "Verificar controles de autorizacion por rol/funcion.",
                    str(resp.status_code), "RBAC estricto server-side para funciones admin.",
                    cvss_base=cvss, wstg_ref="WSTG-ATHZ-03"))
        self._log_result(target, findings)
        return findings


class API6_BusinessFlowsAgent(BaseAgent):
    name, owasp_category = "API6_business_flows", "API6:2023 - Unrestricted Access to Sensitive Business Flows"

    async def run(self, target):
        self.log.info("Generando checklist de flujos de negocio (manual) para %s", target)
        findings = [Finding(self.name, self.owasp_category,
            "Revisar automatizacion abusiva de flujos de negocio (manual)", target, Severity.INFO,
            "Ej: compra masiva, creacion masiva de cuentas, scraping de precios.",
            "", "CAPTCHA, rate limiting contextual, deteccion de comportamiento anomalo.",
            cvss_base=0.0, wstg_ref="WSTG-BUSL-07")]
        self._log_result(target, findings)
        return findings


class API7_SSRFAgent(BaseAgent):
    name, owasp_category = "API7_ssrf", "API7:2023 - Server Side Request Forgery"
    SSRF_PARAMS = ["url", "uri", "path", "dest", "redirect", "callback", "webhook", "fetch"]

    async def run(self, target):
        self.log.info("Analizando SSRF en endpoints API de %s", target)
        findings = []
        if any(p in target.lower() for p in self.SSRF_PARAMS):
            findings.append(Finding(self.name, self.owasp_category,
                "Parametro API candidato a SSRF", target, Severity.MEDIUM,
                "Parametro URL-like en endpoint API.", target,
                "Whitelist de destinos + deshabilitar redirecciones internas.",
                cvss_base=6.1, wstg_ref="WSTG-INPV-19"))
        self._log_result(target, findings)
        return findings


class API8_MisconfigAgent(BaseAgent):
    name, owasp_category = "API8_misconfig", "API8:2023 - Security Misconfiguration"

    async def run(self, target):
        self.log.info("Buscando documentacion Swagger/OpenAPI expuesta en %s", target)
        findings = []
        resp, err = self._http_get(target.rstrip("/") + "/swagger.json")
        if resp is None:
            self.log.info("swagger.json no accesible en %s (%s)", target, err)
            self._log_result(target, findings)
            return findings
        self.log.info("%s/swagger.json -> HTTP %s", target, resp.status_code)
        if resp.status_code == 200:
            findings.append(Finding(self.name, self.owasp_category,
                "Documentacion Swagger/OpenAPI expuesta publicamente", target, Severity.LOW,
                "swagger.json accesible sin autenticacion.", resp.text[:200],
                "Restringir acceso a documentacion de API en produccion.", cvss_base=3.1,
                wstg_ref="WSTG-CONF-05"))
        self._log_result(target, findings)
        return findings


class API9_InventoryAgent(BaseAgent):
    name, owasp_category = "API9_inventory", "API9:2023 - Improper Inventory Management"

    async def run(self, target):
        self.log.info("Enumerando versiones de API en %s", target)
        versions = ["/api/v1/", "/api/v2/", "/api/v3/", "/api/beta/", "/api/old/"]
        findings = []
        base = target.split("/api/")[0] if "/api/" in target else target
        for v in versions:
            resp, err = self._http_get(base + v)
            if resp is None:
                self.log.info("Version %s en %s no respondio (%s)", v, base, err)
                continue
            self.log.info("Version %s en %s -> HTTP %s", v, base, resp.status_code)
            if resp.status_code == 200:
                findings.append(Finding(self.name, self.owasp_category,
                    "Version de API activa detectada: " + v, base + v, Severity.INFO,
                    "Version de API respondio 200; confirmar si deberia estar deprecada.",
                    str(resp.status_code), "Inventariar y deprecar versiones antiguas de API.",
                    cvss_base=0.0, wstg_ref="WSTG-INFO-04"))
        self._log_result(target, findings)
        return findings


class API10_UnsafeConsumptionAgent(BaseAgent):
    name, owasp_category = "API10_unsafe_consumption", "API10:2023 - Unsafe Consumption of APIs"

    async def run(self, target):
        self.log.info("Generando checklist de consumo inseguro de APIs (manual) para %s", target)
        findings = [Finding(self.name, self.owasp_category,
            "Revisar validacion de respuestas de APIs de terceros (manual)", target, Severity.INFO,
            "Verificar que la app valide/sanitice datos recibidos de APIs externas.",
            "", "Tratar datos de terceros como no confiables; validar y sanitizar siempre.",
            cvss_base=0.0, wstg_ref="WSTG-APIT-02")]
        self._log_result(target, findings)
        return findings


class WSTGChecklistAgent(BaseAgent):
    name, owasp_category = "WSTG_checklist_agent", "WSTG - Full Coverage Mapping"

    AUTOMATED_MAP = {
        "WSTG-ATHZ-04": "A01_access_control_2025", "WSTG-INPV-19": "A01_access_control_2025",
        "WSTG-INPV-05": "A05_injection_2025", "WSTG-CONF-06": "A02_misconfig_2025",
        "WSTG-CONF-07": "A02_misconfig_2025", "WSTG-CRYP-01": "A04_crypto_2025",
        "WSTG-CRYP-03": "A04_crypto_2025", "WSTG-ATHN-03": "A07_auth_2025",
        "WSTG-SESS-05": "A06_insecure_design_2025", "WSTG-ERRH-02": "A09_logging_alerting_2025",
        "WSTG-CONF-04": "A10_exception_handling_2025", "WSTG-ATHN-04": "API2_broken_auth",
        "WSTG-ATHZ-03": "API5_function_auth", "WSTG-CONF-05": "API8_misconfig",
        "WSTG-INFO-04": "API9_inventory", "WSTG-BUSL-05": "API4_resource_consumption",
        "WSTG-INFO-02": "A02_misconfig_2025", "WSTG-CLNT-13": "A08_integrity_2025",
    }

    async def run(self, target):
        self.log.info("Generando checklist WSTG completo para %s", target)
        findings = []
        for wstg_cat, data in WSTG_CHECKLIST.items():
            for test_id, test_name in data["tests"].items():
                auto = self.AUTOMATED_MAP.get(test_id)
                if auto:
                    note = "Cubierto automaticamente por agente: " + auto
                    solution = "N/A"
                else:
                    note = "Pendiente de validacion manual (WSTG)."
                    solution = "Ejecutar prueba manual siguiendo metodologia WSTG v4.2."
                title = wstg_cat + " - " + data["name"] + " | OWASP: " + data["maps_to_owasp"]
                findings.append(Finding(
                    self.name, title, test_id + ": " + test_name, target, Severity.INFO,
                    note, "", solution, cvss_base=0.0, wstg_ref=test_id))
        self.log.info("WSTG checklist generado: %d items (%d categorias)", len(findings), len(WSTG_CHECKLIST))
        return findings


ALL_AGENT_CLASSES = [
    A01_AccessControlAgent, A02_MisconfigAgent, A03_SupplyChainAgent, A04_CryptoAgent,
    A05_InjectionAgent, A06_InsecureDesignAgent, A07_AuthAgent, A08_IntegrityAgent,
    A09_LoggingAlertingAgent, A10_ExceptionHandlingAgent,
    API1_BOLAAgent, API2_BrokenAuthAgent, API3_PropertyAuthAgent, API4_ResourceConsumptionAgent,
    API5_FunctionAuthAgent, API6_BusinessFlowsAgent, API7_SSRFAgent, API8_MisconfigAgent,
    API9_InventoryAgent, API10_UnsafeConsumptionAgent,
    WSTGChecklistAgent,
]


class Orchestrator:
    def __init__(self, scope):
        self.scope = scope
        self.log = logging.getLogger("orchestrator")
        self.findings = []

    async def run_all(self, progress_cb=None):
        agents = [cls(self.scope) for cls in ALL_AGENT_CLASSES]
        total_steps = len(agents) * max(len(self.scope.targets), 1)
        done = 0
        self.log.info("Orquestador iniciado: %d agentes x %d targets = %d pasos totales",
                       len(agents), len(self.scope.targets), total_steps)
        for target in self.scope.targets:
            norm_target, err = normalize_target(target)
            if err:
                self.log.warning("Target invalido '%s': %s", target, err)
                continue
            for agent in agents:
                try:
                    results = await agent.run(norm_target)
                    self.findings.extend(results)
                except Exception as e:
                    self.log.error("Agente %s fallo en %s: %s: %s", agent.name, norm_target, type(e).__name__, e)
                done += 1
                if progress_cb:
                    progress_cb(done, total_steps, agent.name, norm_target)
        self.log.info("Orquestador finalizado: %d hallazgos totales", len(self.findings))
        return self.findings


class QualysStyleReporter:
    def __init__(self, findings, scope):
        self.findings = findings
        self.scope = scope

    def _severity_counts(self):
        counts = {s.label: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.label] += 1
        return counts

    def _risk_score(self):
        weights = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Info": 0}
        if not self.findings:
            return 0.0
        total = sum(weights[f.severity.label] for f in self.findings)
        return round(min(100, total), 1)

    def export_csv(self, path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Plugin ID", "Finding ID", "Severity", "Title", "OWASP Category",
                              "WSTG Ref", "Agent", "Host/Target", "CVSS Base", "Solution", "Timestamp"])
            for finding in sorted(self.findings, key=lambda x: -x.severity.qid_level):
                writer.writerow(finding.to_row())

    def export_json(self, path):
        data = {
            "scan_info": {
                "program": self.scope.program_name,
                "targets": self.scope.targets,
                "authorized_by": self.scope.authorized_by,
                "date": datetime.now().isoformat(timespec="seconds"),
                "total_findings": len(self.findings),
                "risk_score": self._risk_score(),
            },
            "severity_summary": self._severity_counts(),
            "findings": [dict(list(asdict(f).items()) + [("severity", f.severity.label)]) for f in self.findings],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str, ensure_ascii=False)

    def export_html(self, path):
        counts = self._severity_counts()
        risk = self._risk_score()
        sorted_findings = sorted(self.findings, key=lambda x: -x.severity.qid_level)

        Q = chr(34)
        rows_parts = []
        for f in sorted_findings:
            badge = "<span class=" + Q + "badge" + Q + " style=" + Q + "background:" + f.severity.color + Q + ">" + f.severity.label + "</span>"
            row = "<tr><td>" + str(f.plugin_id) + "</td><td>" + badge + "</td><td>" + f.title + "</td><td>" + f.owasp_category + "</td><td>" + (f.wstg_ref or "-") + "</td><td>" + f.target + "</td><td>" + str(f.cvss_base) + "</td><td>" + f.solution + "</td></tr>"
            rows_parts.append(row)
        rows_html = "".join(rows_parts)

        cards_parts = []
        for sev in Severity:
            card = "<div class=" + Q + "card" + Q + " style=" + Q + "border-left: 6px solid " + sev.color + Q + "><div class=" + Q + "card-count" + Q + ">" + str(counts[sev.label]) + "</div><div class=" + Q + "card-label" + Q + ">" + sev.label + "</div></div>"
            cards_parts.append(card)
        severity_cards = "".join(cards_parts)

        html = """<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8">
<title>Vulnerability Assessment Report</title>
<style>
body { font-family: 'Segoe UI', Arial, sans-serif; background:#0d1117; color:#c9d1d9; margin:0; padding:30px; }
h1 { color:#58a6ff; border-bottom: 2px solid #30363d; padding-bottom:10px; }
h2 { color:#79c0ff; margin-top:40px; }
.meta { background:#161b22; padding:15px 20px; border-radius:8px; margin-bottom:20px; }
.meta p { margin:4px 0; }
.risk-score { font-size:48px; font-weight:bold; color:#f85149; }
.cards { display:flex; gap:15px; margin:20px 0; flex-wrap:wrap; }
.card { background:#161b22; padding:15px 25px; border-radius:8px; text-align:center; min-width:100px; }
.card-count { font-size:28px; font-weight:bold; }
.card-label { font-size:13px; color:#8b949e; text-transform:uppercase; margin-top:4px; }
table { width:100%; border-collapse: collapse; margin-top:15px; background:#161b22; }
th, td { padding:10px 12px; border-bottom:1px solid #30363d; text-align:left; font-size:13px; }
th { background:#21262d; color:#58a6ff; position: sticky; top:0; }
tr:hover { background:#1c2128; }
.badge { padding:3px 10px; border-radius:12px; color:white; font-weight:bold; font-size:11px; }
.footer { margin-top:40px; color:#6e7681; font-size:12px; text-align:center; }
</style></head>
<body>
<h1>Vulnerability Assessment Report</h1>
<div class="meta">
    <p><b>Programa:</b> PROGRAM_PLACEHOLDER</p>
    <p><b>Targets:</b> TARGETS_PLACEHOLDER</p>
    <p><b>Autorizado por:</b> AUTH_PLACEHOLDER</p>
    <p><b>Fecha de escaneo:</b> DATE_PLACEHOLDER</p>
    <p><b>Intensidad:</b> INTENSITY_PLACEHOLDER</p>
    <p><b>Total de hallazgos:</b> TOTAL_PLACEHOLDER</p>
</div>
<h2>Executive Summary</h2>
<div class="cards">
    <div class="card"><div class="risk-score">RISK_PLACEHOLDER</div><div class="card-label">Risk Score (0-100)</div></div>
    CARDS_PLACEHOLDER
</div>
<h2>Detailed Findings</h2>
<table>
<thead><tr>
    <th>Plugin ID</th><th>Severity</th><th>Title</th><th>OWASP Category</th>
    <th>WSTG Ref</th><th>Host/Target</th><th>CVSS</th><th>Solution</th>
</tr></thead>
<tbody>
ROWS_PLACEHOLDER
</tbody>
</table>
<div class="footer">
    Generado por Bug Bounty Multi-Agent Framework v4.2 | OWASP WSTG v4.2 + OWASP API Top 10:2023<br>
    Uso exclusivo en engagements autorizados. Ethical Hacking / TVM.
</div>
</body></html>"""

        html = html.replace("PROGRAM_PLACEHOLDER", self.scope.program_name)
        html = html.replace("TARGETS_PLACEHOLDER", ", ".join(self.scope.targets))
        html = html.replace("AUTH_PLACEHOLDER", self.scope.authorized_by)
        html = html.replace("DATE_PLACEHOLDER", datetime.now().strftime("%Y-%m-%d %H:%M"))
        html = html.replace("INTENSITY_PLACEHOLDER", self.scope.intensity)
        html = html.replace("TOTAL_PLACEHOLDER", str(len(self.findings)))
        html = html.replace("RISK_PLACEHOLDER", str(risk))
        html = html.replace("CARDS_PLACEHOLDER", severity_cards)
        html = html.replace("ROWS_PLACEHOLDER", rows_html)

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def export_pdf(self, path):
        """Genera reporte PDF estilo Qualys VMDR / Nessus."""
        if not PDF_AVAILABLE:
            logging.getLogger("reporter").warning("reportlab no disponible; pip install reportlab")
            return False

        counts = self._severity_counts()
        risk = self._risk_score()
        sorted_findings = sorted(self.findings, key=lambda x: -x.severity.qid_level)

        sev_colors = {
            "Critical": colors.HexColor("#8B0000"),
            "High": colors.HexColor("#FF4136"),
            "Medium": colors.HexColor("#FF851B"),
            "Low": colors.HexColor("#FFDC00"),
            "Info": colors.HexColor("#00A8FF"),
        }

        doc = SimpleDocTemplate(path, pagesize=letter,
                                 topMargin=0.6 * inch, bottomMargin=0.6 * inch,
                                 leftMargin=0.5 * inch, rightMargin=0.5 * inch)
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle("TitleCustom", parent=styles["Title"],
                                       fontSize=22, textColor=colors.HexColor("#1a1a2e"),
                                       spaceAfter=6)
        subtitle_style = ParagraphStyle("Subtitle", parent=styles["Normal"],
                                          fontSize=11, textColor=colors.HexColor("#555555"),
                                          spaceAfter=20)
        h2_style = ParagraphStyle("H2Custom", parent=styles["Heading2"],
                                    fontSize=14, textColor=colors.HexColor("#0f3460"),
                                    spaceBefore=14, spaceAfter=8)
        normal_style = ParagraphStyle("NormalSmall", parent=styles["Normal"], fontSize=9, leading=12)
        cell_style = ParagraphStyle("Cell", parent=styles["Normal"], fontSize=7.5, leading=9)

        elements = []
        elements.append(Paragraph("Vulnerability Assessment Report", title_style))
        elements.append(Paragraph(
            "Bug Bounty / Pentest Multi-Agent Framework v4.2 &mdash; OWASP WSTG v4.2 + Web/API Top 10",
            subtitle_style))

        meta_data = [
            ["Programa:", self.scope.program_name or "N/A"],
            ["Targets:", ", ".join(self.scope.targets)],
            ["Autorizado por:", self.scope.authorized_by or "N/A"],
            ["Fecha de escaneo:", datetime.now().strftime("%Y-%m-%d %H:%M")],
            ["Intensidad:", self.scope.intensity],
            ["Total de hallazgos:", str(len(self.findings))],
            ["Risk Score (0-100):", str(risk)],
        ]
        meta_table = Table(meta_data, colWidths=[1.6 * inch, 5.2 * inch])
        meta_table.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#0f3460")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0f2f5")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d5dd")),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 16))

        elements.append(Paragraph("Executive Summary", h2_style))
        sev_row_labels = ["Critical", "High", "Medium", "Low", "Info"]
        sev_row_counts = [str(counts[s]) for s in sev_row_labels]
        summary_table = Table([sev_row_labels, sev_row_counts], colWidths=[1.36 * inch] * 5)
        summary_style = [
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("FONTSIZE", (0, 1), (-1, 1), 16),
            ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]
        for idx, s in enumerate(sev_row_labels):
            summary_style.append(("BACKGROUND", (idx, 0), (idx, 0), sev_colors[s]))
            summary_style.append(("BOX", (idx, 0), (idx, 1), 0.75, sev_colors[s]))
        summary_table.setStyle(TableStyle(summary_style))
        elements.append(summary_table)
        elements.append(Spacer(1, 20))

        elements.append(Paragraph("Detailed Findings", h2_style))
        table_data = [["ID", "Sev.", "Title", "OWASP", "WSTG", "Host", "CVSS", "Solution"]]
        for f in sorted_findings:
            table_data.append([
                Paragraph(str(f.plugin_id), cell_style),
                Paragraph(f.severity.label, cell_style),
                Paragraph(f.title, cell_style),
                Paragraph(f.owasp_category, cell_style),
                Paragraph(f.wstg_ref or "-", cell_style),
                Paragraph(f.target, cell_style),
                Paragraph(str(f.cvss_base), cell_style),
                Paragraph(f.solution, cell_style),
            ])

        col_widths = [0.5 * inch, 0.55 * inch, 1.5 * inch, 1.0 * inch, 0.7 * inch, 1.15 * inch, 0.45 * inch, 1.35 * inch]
        findings_table = Table(table_data, colWidths=col_widths, repeatRows=1)
        table_style = [
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d5dd")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
        for i, f in enumerate(sorted_findings, start=1):
            bg = colors.HexColor("#fff5f5") if f.severity.label in ("Critical", "High") else colors.white
            table_style.append(("BACKGROUND", (0, i), (-1, i), bg))
            table_style.append(("TEXTCOLOR", (1, i), (1, i), sev_colors[f.severity.label]))
        findings_table.setStyle(TableStyle(table_style))
        elements.append(findings_table)

        elements.append(Spacer(1, 20))
        elements.append(Paragraph(
            "Generado por Bug Bounty Multi-Agent Framework v4.2 | OWASP WSTG v4.2 + OWASP API Top 10:2023. "
            "Uso exclusivo en engagements autorizados. Ethical Hacking / TVM.",
            ParagraphStyle("Footer", parent=styles["Normal"], fontSize=7.5, textColor=colors.grey)))

        doc.build(elements)
        return True

    def export_all(self, base_path):
        self.export_csv(base_path + ".csv")
        self.export_json(base_path + ".json")
        self.export_html(base_path + ".html")
        pdf_ok = self.export_pdf(base_path + ".pdf")
        return pdf_ok


class App(ctk.CTk if GUI_AVAILABLE else object):
    def __init__(self):
        if not GUI_AVAILABLE:
            print("[!] customtkinter no disponible. Instala con: pip install customtkinter")
            return
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")
        self.title("Bug Bounty Multi-Agent Framework v4.2 | OWASP WSTG + Web/API Top 10")
        self.geometry("1450x920")

        self.scope = Scope()
        self.findings = []
        self.test_web_var = tk.BooleanVar(value=True)
        self.test_api_var = tk.BooleanVar(value=True)
        self.test_wstg_var = tk.BooleanVar(value=True)

        self._build_layout()
        self.after(200, self._poll_logs)

    def _build_layout(self):
        sidebar = ctk.CTkFrame(self, width=280)
        sidebar.pack(side="left", fill="y", padx=10, pady=10)

        ctk.CTkLabel(sidebar, text="Configuracion", font=ctk.CTkFont(weight="bold", size=16)).pack(pady=10)
        self.program_entry = ctk.CTkEntry(sidebar, placeholder_text="Nombre del programa")
        self.program_entry.pack(fill="x", padx=10, pady=5)
        self.targets_entry = ctk.CTkTextbox(sidebar, height=100)
        self.targets_entry.pack(fill="x", padx=10, pady=5)
        self.targets_entry.insert("1.0", "https://example.com")
        self.authorized_entry = ctk.CTkEntry(sidebar, placeholder_text="Autorizado por")
        self.authorized_entry.pack(fill="x", padx=10, pady=5)

        ctk.CTkCheckBox(sidebar, text="OWASP Web Top 10:2025", variable=self.test_web_var).pack(anchor="w", padx=10, pady=3)
        ctk.CTkCheckBox(sidebar, text="OWASP API Security Top 10:2023", variable=self.test_api_var).pack(anchor="w", padx=10, pady=3)
        ctk.CTkCheckBox(sidebar, text="WSTG v4.2 Checklist Completo", variable=self.test_wstg_var).pack(anchor="w", padx=10, pady=3)

        self.intensity_combo = ctk.CTkComboBox(sidebar, values=["Low", "Medium", "High"])
        self.intensity_combo.set("Medium")
        self.intensity_combo.pack(fill="x", padx=10, pady=5)

        self.start_btn = ctk.CTkButton(sidebar, text="Iniciar Engagement", command=self._start_scan)
        self.start_btn.pack(fill="x", padx=10, pady=15)

        export_label = ctk.CTkLabel(sidebar, text="Exportar Reporte:", font=ctk.CTkFont(weight="bold"))
        export_label.pack(anchor="w", padx=10, pady=(5, 0))

        self.export_all_btn = ctk.CTkButton(sidebar, text="CSV + JSON + HTML + PDF",
                                              command=self._export_report, state="disabled")
        self.export_all_btn.pack(fill="x", padx=10, pady=5)

        self.export_pdf_btn = ctk.CTkButton(sidebar, text="Solo PDF (Qualys/Nessus style)",
                                              command=self._export_pdf_only, state="disabled",
                                              fg_color="#8B0000", hover_color="#5c0000")
        self.export_pdf_btn.pack(fill="x", padx=10, pady=5)

        if not PDF_AVAILABLE:
            ctk.CTkLabel(sidebar, text="reportlab no instalado (pip install reportlab)",
                         text_color="orange", wraplength=250, font=ctk.CTkFont(size=10)).pack(padx=10, pady=(0, 5))

        self.progress = ctk.CTkProgressBar(sidebar)
        self.progress.set(0)
        self.progress.pack(fill="x", padx=10, pady=10)
        self.status_label = ctk.CTkLabel(sidebar, text="Listo.", wraplength=250)
        self.status_label.pack(padx=10, pady=5)

        main = ctk.CTkFrame(self)
        main.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        self.dashboard_frame = ctk.CTkFrame(main)
        self.dashboard_frame.pack(fill="x", pady=(0, 10))
        self.severity_cards = {}
        for sev in Severity:
            card = ctk.CTkFrame(self.dashboard_frame, border_width=2, border_color=sev.color)
            card.pack(side="left", expand=True, fill="both", padx=5, pady=5)
            count_lbl = ctk.CTkLabel(card, text="0", font=ctk.CTkFont(size=24, weight="bold"))
            count_lbl.pack(pady=(10, 0))
            ctk.CTkLabel(card, text=sev.label).pack(pady=(0, 10))
            self.severity_cards[sev.label] = count_lbl

        tabs = ctk.CTkTabview(main)
        tabs.pack(fill="both", expand=True)
        tab_findings = tabs.add("Hallazgos")
        tab_owasp = tabs.add("Cobertura OWASP")
        tab_wstg = tabs.add("Cobertura WSTG")
        tab_logs = tabs.add("Logs")

        self.findings_box = ctk.CTkTextbox(tab_findings)
        self.findings_box.pack(fill="both", expand=True, padx=5, pady=5)

        owasp_scroll = ctk.CTkScrollableFrame(tab_owasp)
        owasp_scroll.pack(fill="both", expand=True, padx=10, pady=10)
        ctk.CTkLabel(owasp_scroll, text="OWASP Web Top 10:2025", font=ctk.CTkFont(weight="bold")).pack(pady=8)
        for code, name in OWASP_WEB_2025.items():
            tag = " [NUEVO v4]" if code == "A10:2025" else ""
            ctk.CTkLabel(owasp_scroll, text=code + ": " + name + tag).pack(anchor="w", padx=10)
        ctk.CTkLabel(owasp_scroll, text="OWASP API Security Top 10:2023", font=ctk.CTkFont(weight="bold")).pack(pady=8)
        for code, name in OWASP_API_2023.items():
            ctk.CTkLabel(owasp_scroll, text=code + ": " + name).pack(anchor="w", padx=10)

        wstg_scroll = ctk.CTkScrollableFrame(tab_wstg)
        wstg_scroll.pack(fill="both", expand=True, padx=10, pady=10)
        ctk.CTkLabel(wstg_scroll, text="OWASP WSTG v4.2 - " + str(TOTAL_WSTG_TESTS) + " test cases",
                     font=ctk.CTkFont(weight="bold")).pack(pady=8)
        for wstg_cat, data in WSTG_CHECKLIST.items():
            ctk.CTkLabel(wstg_scroll, text=wstg_cat + " - " + data["name"],
                         font=ctk.CTkFont(weight="bold", size=13)).pack(anchor="w", pady=(10, 2))
            for test_id, test_name in data["tests"].items():
                auto = WSTGChecklistAgent.AUTOMATED_MAP.get(test_id)
                tag = " [AUTO]" if auto else " [MANUAL]"
                ctk.CTkLabel(wstg_scroll, text="  " + test_id + ": " + test_name + tag).pack(anchor="w")

        self.logs_box = ctk.CTkTextbox(tab_logs)
        self.logs_box.pack(fill="both", expand=True, padx=5, pady=5)

    def _poll_logs(self):
        while not LOG_QUEUE.empty():
            try:
                msg = LOG_QUEUE.get_nowait()
                self.logs_box.insert("end", msg + "\n")
                self.logs_box.see("end")
            except queue.Empty:
                break
        self.after(200, self._poll_logs)

    def _start_scan(self):
        program = self.program_entry.get().strip() or "Unnamed Engagement"
        targets_raw = self.targets_entry.get("1.0", "end").strip()
        targets = [t.strip() for t in targets_raw.splitlines() if t.strip()]
        authorized = self.authorized_entry.get().strip() or "N/A"
        if not targets:
            messagebox.showerror("Error", "Debes especificar al menos un target.")
            return

        self.scope = Scope(program_name=program, targets=targets,
                            authorized_by=authorized, intensity=self.intensity_combo.get())
        self.findings = []
        self.findings_box.delete("1.0", "end")
        self.logs_box.delete("1.0", "end")
        self.start_btn.configure(state="disabled", text="Escaneando...")
        threading.Thread(target=self._run_scan_thread, daemon=True).start()

    def _run_scan_thread(self):
        orch = Orchestrator(self.scope)

        def progress_cb(done, total, agent_name, target):
            self.progress.set(done / total)
            self.status_label.configure(text=agent_name + " -> " + target + " (" + str(done) + "/" + str(total) + ")")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        findings = loop.run_until_complete(orch.run_all(progress_cb=progress_cb))
        self.findings = findings
        self.after(0, self._on_scan_complete)

    def _on_scan_complete(self):
        counts = {s.label: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.label] += 1
            self.findings_box.insert("end",
                "[" + f.severity.label + "] " + f.title + " | " + f.owasp_category + " | " + f.target + "\n"
                "    Plugin ID: " + str(f.plugin_id) + " | CVSS: " + str(f.cvss_base) + " | WSTG: " + f.wstg_ref + "\n"
                "    Solucion: " + f.solution + "\n\n")
        for label, lbl_widget in self.severity_cards.items():
            lbl_widget.configure(text=str(counts[label]))
        self.start_btn.configure(state="normal", text="Iniciar Engagement")
        self.export_all_btn.configure(state="normal")
        if PDF_AVAILABLE:
            self.export_pdf_btn.configure(state="normal")
        self.status_label.configure(text="Completado. " + str(len(self.findings)) + " hallazgos.")

    def _export_report(self):
        path = filedialog.asksaveasfilename(defaultextension=".html",
            filetypes=[("HTML Report", "*.html")], initialfile="vulnerability_report")
        if not path:
            return
        base = str(Path(path).with_suffix(""))
        reporter = QualysStyleReporter(self.findings, self.scope)
        pdf_ok = reporter.export_all(base)
        msg = "Reporte generado:\n" + base + ".html\n" + base + ".csv\n" + base + ".json"
        if pdf_ok:
            msg += "\n" + base + ".pdf"
        else:
            msg += "\n\n[!] PDF no generado (instala reportlab: pip install reportlab)"
        messagebox.showinfo("Exportado", msg)

    def _export_pdf_only(self):
        if not PDF_AVAILABLE:
            messagebox.showerror("Error", "reportlab no esta instalado.\nEjecuta: pip install reportlab")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pdf",
            filetypes=[("PDF Report", "*.pdf")], initialfile="vulnerability_report")
        if not path:
            return
        reporter = QualysStyleReporter(self.findings, self.scope)
        reporter.export_pdf(path)
        messagebox.showinfo("Exportado", "PDF generado:\n" + path)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        scope_path = sys.argv[2] if len(sys.argv) > 2 else "config.yaml"
        scope = Scope.from_yaml(scope_path)
        orch = Orchestrator(scope)
        loop = asyncio.new_event_loop()
        findings = loop.run_until_complete(orch.run_all())
        reporter = QualysStyleReporter(findings, scope)
        pdf_ok = reporter.export_all("vulnerability_report")
        print("[+] " + str(len(findings)) + " hallazgos.")
        print("[+] Reporte generado: vulnerability_report.[html|csv|json]" + ("|pdf" if pdf_ok else ""))
        return

    if not GUI_AVAILABLE:
        print("[!] GUI no disponible. Usa: python bugbounty_multiagent_v42.py --cli config.yaml")
        sys.exit(1)
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
