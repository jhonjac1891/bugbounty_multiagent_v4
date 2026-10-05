# ============================================================
# MÓDULO WSTG (OWASP Web Security Testing Guide v4.2) — v4
# Añadir este bloque a bugbounty_multiagent_v3.py -> v4
# ============================================================

WSTG_CHECKLIST = {
    "WSTG-INFO": {
        "name": "Information Gathering",
        "maps_to_owasp": "A02:2025",
        "tests": {
            "WSTG-INFO-01": "Conduct Search Engine Discovery Reconnaissance for Information Leakage",
            "WSTG-INFO-02": "Fingerprint Web Server",
            "WSTG-INFO-03": "Review Webserver Metafiles for Information Leakage",
            "WSTG-INFO-04": "Enumerate Applications on Webserver",
            "WSTG-INFO-05": "Review Webpage Content for Information Leakage",
            "WSTG-INFO-06": "Identify Application Entry Points",
            "WSTG-INFO-07": "Map Execution Paths Through Application",
            "WSTG-INFO-08": "Fingerprint Web Application Framework",
            "WSTG-INFO-09": "Fingerprint Web Application",
            "WSTG-INFO-10": "Map Application Architecture",
        },
    },
    "WSTG-CONF": {
        "name": "Configuration and Deployment Management Testing",
        "maps_to_owasp": "A02:2025",
        "tests": {
            "WSTG-CONF-01": "Test Network Infrastructure Configuration",
            "WSTG-CONF-02": "Test Application Platform Configuration",
            "WSTG-CONF-03": "Test File Extensions Handling for Sensitive Information",
            "WSTG-CONF-04": "Review Old Backup and Unreferenced Files for Sensitive Information",
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
        },
    },
    "WSTG-IDNT": {
        "name": "Identity Management Testing",
        "maps_to_owasp": "A01:2025",
        "tests": {
            "WSTG-IDNT-01": "Test Role Definitions",
            "WSTG-IDNT-02": "Test User Registration Process",
            "WSTG-IDNT-03": "Test Account Provisioning Process",
            "WSTG-IDNT-04": "Testing for Account Enumeration and Guessable User Account",
            "WSTG-IDNT-05": "Testing for Weak or Unenforced Username Policy",
        },
    },
    "WSTG-ATHN": {
        "name": "Authentication Testing",
        "maps_to_owasp": "A07:2025",
        "tests": {
            "WSTG-ATHN-01": "Testing for Credentials Transported over an Encrypted Channel",
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
        },
    },
    "WSTG-ATHZ": {
        "name": "Authorization Testing",
        "maps_to_owasp": "A01:2025",
        "tests": {
            "WSTG-ATHZ-01": "Testing Directory Traversal File Include",
            "WSTG-ATHZ-02": "Testing for Bypassing Authorization Schema",
            "WSTG-ATHZ-03": "Testing for Privilege Escalation",
            "WSTG-ATHZ-04": "Testing for Insecure Direct Object References (IDOR)",
        },
    },
    "WSTG-SESS": {
        "name": "Session Management Testing",
        "maps_to_owasp": "A07:2025",
        "tests": {
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
        },
    },
    "WSTG-INPV": {
        "name": "Input Validation Testing",
        "maps_to_owasp": "A05:2025",
        "tests": {
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
        },
    },
    "WSTG-ERRH": {
        "name": "Error Handling",
        "maps_to_owasp": "A09:2025",
        "tests": {
            "WSTG-ERRH-01": "Testing for Improper Error Handling",
            "WSTG-ERRH-02": "Testing for Stack Traces",
        },
    },
    "WSTG-CRYP": {
        "name": "Weak Cryptography",
        "maps_to_owasp": "A04:2025",
        "tests": {
            "WSTG-CRYP-01": "Testing for Weak Transport Layer Security",
            "WSTG-CRYP-02": "Testing for Padding Oracle",
            "WSTG-CRYP-03": "Testing for Sensitive Information Sent via Unencrypted Channels",
            "WSTG-CRYP-04": "Testing for Weak Encryption",
        },
    },
    "WSTG-BUSL": {
        "name": "Business Logic Testing",
        "maps_to_owasp": "A06:2025",
        "tests": {
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
        },
    },
    "WSTG-CLNT": {
        "name": "Client-side Testing",
        "maps_to_owasp": "A05:2025",
        "tests": {
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
        },
    },
    "WSTG-APIT": {
        "name": "API Testing",
        "maps_to_owasp": "API1:2023",
        "tests": {
            "WSTG-APIT-01": "Testing GraphQL",
            "WSTG-APIT-02": "Testing for REST API Vulnerabilities",
            "WSTG-APIT-03": "Testing for Mass Assignment",
            "WSTG-APIT-04": "Testing for API Key Exposure",
        },
    },
}

TOTAL_WSTG_TESTS = sum(len(cat["tests"]) for cat in WSTG_CHECKLIST.values())


# ============================================================
# AGENTE WSTG + INTEGRACIÓN GUI (continuación del módulo v4)
# ============================================================

class WSTGChecklistAgent(BaseAgent):
    """
    Recorre el WSTG_CHECKLIST completo y produce un Finding tipo
    'checklist item' por cada test, con estado inicial MANUAL
    (requiere validación humana) salvo los que ya cubren tus
    agentes automatizados A01..A09 y API2/API7/API8/API9.
    """
    name, owasp_category = "WSTG_checklist_agent", "WSTG - Full Coverage Mapping"

    # Tests que SÍ disparan lógica automática ya existente en tus agentes v3
    AUTOMATED_MAP = {
        "WSTG-ATHZ-04": "A01_access_control_2025",   # IDOR -> ya lo hace A01
        "WSTG-INPV-19": "A01_access_control_2025",   # SSRF -> ya lo hace A01
        "WSTG-INPV-05": "A05_injection_2025",        # SQLi -> ya lo hace A05
        "WSTG-CONF-06": "A02_misconfig_2025",        # HTTP Methods
        "WSTG-CONF-07": "A02_misconfig_2025",        # HSTS
        "WSTG-CRYP-01": "A04_crypto_2025",           # TLS débil
        "WSTG-ATHN-03": "A07_auth_2025",             # Lock out
        "WSTG-SESS-05": "A06_insecure_design_2025",  # CSRF
    }

    async def run(self, target: str) -> List[Finding]:
        findings = []
        for wstg_cat, data in WSTG_CHECKLIST.items():
            for test_id, test_name in data["tests"].items():
                status = Severity.INFO
                note = "Pendiente de validación manual (WSTG)."
                automated_agent = self.AUTOMATED_MAP.get(test_id)
                if automated_agent:
                    note = f"Cubierto automáticamente por agente: {automated_agent}"
                findings.append(Finding(
                    self.name,
                    f"{wstg_cat} - {data['name']} | OWASP: {data['maps_to_owasp']}",
                    f"{test_id}: {test_name}",
                    target,
                    status,
                    note,
                    ""
                ))
        self.log.info("WSTG checklist generado: %d ítems (%d categorías)",
                       len(findings), len(WSTG_CHECKLIST))
        return findings

    def export_checklist_csv(self, path: str):
        """Exporta en el mismo formato del Google Sheet: Test ID | Test Name | Status | Notes"""
        import csv
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Test ID", "Test Name", "Category", "OWASP Mapping", "Status", "Notes"])
            for wstg_cat, data in WSTG_CHECKLIST.items():
                for test_id, test_name in data["tests"].items():
                    auto = self.AUTOMATED_MAP.get(test_id, "")
                    status = "Automated" if auto else "Manual"
                    writer.writerow([test_id, test_name, data["name"],
                                      data["maps_to_owasp"], status, auto])


# ------------------------------------------------------------
# INTEGRACIÓN EN EL ORQUESTADOR (agregar a la lista de agentes)
# ------------------------------------------------------------
# Dentro de tu clase Orchestrator / donde instancias los agentes (línea ~640):
#
#   agents = [
#       A01_AccessControlAgent(scope), A02_MisconfigAgent(scope), A03_SupplyChainAgent(scope),
#       A04_CryptoAgent(scope), A05_InjectionAgent(scope), A06_InsecureDesignAgent(scope),
#       A07_AuthAgent(scope), A08_IntegrityAgent(scope), A09_LoggingAlertingAgent(scope),
#       API2_BrokenAuthAgent(scope), API7_SSRFAgent(scope), API8_MisconfigAgent(scope),
#       API9_InventoryAgent(scope),
#       WSTGChecklistAgent(scope),          # <-- AÑADIR ESTA LÍNEA
#   ]

# ------------------------------------------------------------
# NUEVA PESTAÑA GUI: "Cobertura WSTG"  (agregar junto a tab_owasp, línea ~963)
# ------------------------------------------------------------
#
#   tab_wstg = tabs.add("Cobertura WSTG")
#   wstg_frame = ctk.CTkScrollableFrame(tab_wstg)
#   wstg_frame.pack(fill="both", expand=True, padx=10, pady=10)
#   ctk.CTkLabel(wstg_frame, text=f"OWASP WSTG v4.2 - {TOTAL_WSTG_TESTS} test cases",
#                font=ctk.CTkFont(weight="bold")).pack(pady=8)
#   for wstg_cat, data in WSTG_CHECKLIST.items():
#       ctk.CTkLabel(wstg_frame, text=f"{wstg_cat} - {data['name']}",
#                    font=ctk.CTkFont(weight="bold", size=13)).pack(anchor="w", pady=(10, 2))
#       for test_id, test_name in data["tests"].items():
#           auto = WSTGChecklistAgent.AUTOMATED_MAP.get(test_id)
#           tag = " [AUTO]" if auto else " [MANUAL]"
#           ctk.CTkLabel(wstg_frame, text=f"  {test_id}: {test_name}{tag}").pack(anchor="w")
