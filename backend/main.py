import os
import io
import re
import textwrap
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import pdfplumber
import requests
from fastapi import FastAPI, Header, HTTPException, UploadFile, File
from pydantic import BaseModel

app = FastAPI()

# ===================== AUTH CONFIG =====================
MAXI_CUIT = os.getenv("MAXI_CUIT", "")
MAXI_PASSWORD = os.getenv("MAXI_PASSWORD", "")
BACKEND_API_KEY = os.getenv("BACKEND_API_KEY", "")
DEMO_ACCESS_TOKEN = os.getenv("DEMO_ACCESS_TOKEN", "DEMO_TOKEN_OK")

# ===================== AFIP CONFIG (ENV) =====================
AFIP_ENV = (os.getenv("AFIP_ENV", "prod") or "prod").strip().lower()
AFIP_CUIT = (os.getenv("AFIP_CUIT", "") or "").strip()  # si no está, usamos MAXI_CUIT
AFIP_CERT_B64 = os.getenv("AFIP_CERT_B64", "")
AFIP_KEY_B64 = os.getenv("AFIP_KEY_B64", "")

WSAA_URLS = {
    "prod": "https://wsaa.afip.gov.ar/ws/services/LoginCms",
    "homo": "https://wsaahomo.afip.gov.ar/ws/services/LoginCms",
}
WSAA_URL = WSAA_URLS.get(AFIP_ENV, WSAA_URLS["prod"])


class LoginRequest(BaseModel):
    cuit: str
    password: str


def check_api_key(x_api_key: str):
    if BACKEND_API_KEY and x_api_key != BACKEND_API_KEY:
        raise HTTPException(status_code=401, detail="API key inválida")


def check_bearer(authorization: str):
    # Demo simple: token fijo. En prod: JWT con expiración.
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Falta Authorization Bearer token")
    token = authorization.split(" ", 1)[1].strip()
    if token != DEMO_ACCESS_TOKEN:
        raise HTTPException(status_code=401, detail="Token inválido")


def fail_wsaa(r: requests.Response):
    """
    Log pro para Render:
      - status code
      - headers básicos
      - body completo (recortado a 12k para evitar logs infinitos)
    """
    body = (r.text or "")
    body_cut = body[:12000]

    print("=== WSAA ERROR ===")
    print("STATUS:", r.status_code)
    print("URL:", getattr(r, "url", ""))
    print("HEADERS:", dict(r.headers or {}))
    print("BODY (cut 12k):")
    print(textwrap.fill(body_cut, 140))
    print("=== /WSAA ERROR ===")

    raise RuntimeError(f"WSAA HTTP {r.status_code}: {body_cut}")


@app.post("/auth/login")
def login(payload: LoginRequest, x_api_key: str = Header(default="")):
    check_api_key(x_api_key)

    if payload.cuit != MAXI_CUIT or payload.password != MAXI_PASSWORD:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    return {"access_token": DEMO_ACCESS_TOKEN}


@app.get("/health")
def health():
    return {
        "ok": True,
        "afip_env": AFIP_ENV,
        "wsaa_url": WSAA_URL,
    }


# ===================== PDF EXTRACTION (BACKEND) =====================
CAE_PATTERNS = [
    re.compile(r"\bCAE\b\D{0,30}(\d{14})\b", re.IGNORECASE),
    re.compile(r"\bC\.?A\.?E\.?\b\D{0,30}(\d{14})\b", re.IGNORECASE),
    re.compile(r"\bCAE\s*N[º°o]?\b\D{0,30}(\d{14})\b", re.IGNORECASE),
    re.compile(r"\bCAE\s*NRO\.?\b\D{0,30}(\d{14})\b", re.IGNORECASE),
]

VTO_PATTERNS = [
    re.compile(
        r"(?:Fecha\s+de\s+)?(?:Vto\.?\s*de\s*CAE|Vto\.?\s*CAE|Vencimiento\s*CAE|CAE\s*Vto\.?)\D{0,30}(\d{2}[/-]\d{2}[/-]\d{4})",
        re.IGNORECASE
    ),
    re.compile(
        r"(?:Fecha\s+de\s+)?(?:Vto\.?\s*de\s*CAE|Vto\.?\s*CAE|Vencimiento\s*CAE|CAE\s*Vto\.?)\D{0,30}(\d{4}[/-]\d{2}[/-]\d{2})",
        re.IGNORECASE
    ),
]


def find_cae(text: str) -> Optional[str]:
    for pat in CAE_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(1)
    idx = text.lower().find("cae")
    if idx != -1:
        window = text[idx: idx + 250]
        m2 = re.search(r"(\d{14})", window)
        if m2:
            return m2.group(1)
    return None


def find_vto(text: str) -> Optional[str]:
    for pat in VTO_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(1)
    return None


def parse_date(date_str: Optional[str]):
    if not date_str:
        return None
    s = date_str.strip()
    for fmt in ("%d/%m/%Y", "%d-%m-%Y", "%Y/%m/%d", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            pass
    return None


def basic_format_ok(cae: Optional[str]) -> bool:
    return bool(cae and re.fullmatch(r"\d{14}", cae))


def extract_text_pdf(file_bytes: bytes, max_pages: int = 5) -> str:
    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
        texts = []
        for page in pdf.pages[:max_pages]:
            texts.append(page.extract_text() or "")
        return "\n".join(texts)


# ===================== WSAA HOOK (LOG ONLY) =====================
def wsaa_get_ta_demo():
    """
    Hook para WSAA real. Por ahora SOLO valida que tengas credenciales cargadas
    y deja listo el logging fail_wsaa para cuando pegues a AFIP.
    """
    if not AFIP_CERT_B64 or not AFIP_KEY_B64:
        raise RuntimeError("Faltan AFIP_CERT_B64 / AFIP_KEY_B64 en Render (Environment).")

    # En este punto, tu implementación real debería:
    # 1) construir LoginTicketRequest (generationTime/expirationTime en UTC)
    # 2) firmarlo (CMS/PKCS7) con cert+key
    # 3) POST al WSAA_URL y parsear token/sign
    #
    # Como todavía no me pasaste tu función actual de CMS, no la invento acá:
    # te dejo listo el logging y el wiring.
    return None


# ===================== VERIFY ENDPOINT =====================
@app.post("/verify")
async def verify(
    files: List[UploadFile] = File(...),  # PDFs
    x_api_key: str = Header(default=""),
    authorization: str = Header(default=""),
):
    """
    Producción:
      - extrae CAE/Vto (y otros datos)
      - WSAA: obtiene TA (token+sign)
      - WSFE: consulta comprobante / CAE real
      - devuelve status por archivo

    Nota: el CUIT emisor se toma del env (AFIP_CUIT o MAXI_CUIT).
    """
    check_api_key(x_api_key)
    check_bearer(authorization)

    cuit_emisor = AFIP_CUIT or MAXI_CUIT
    if not cuit_emisor:
        raise HTTPException(status_code=500, detail="Falta AFIP_CUIT o MAXI_CUIT en variables de entorno.")

    today = datetime.now().date()
    out_rows = []

    # --- WSAA (hook) ---
    # Cuando pegues a WSAA real, si falla, llamá fail_wsaa(response)
    # Por ahora chequeamos que existan credenciales y dejamos el wiring listo.
    try:
        _ = wsaa_get_ta_demo()
    except Exception as e:
        # esto va a aparecer en Detalle AFIP para todos los archivos
        err = f"WSAA_SETUP_ERROR: {e}"
        for f in files:
            out_rows.append({
                "Archivo": f.filename,
                "CAE": "",
                "Vto CAE": "",
                "Estado": "No procesado (falló setup WSAA)",
                "AFIP": "ERROR_AFIP",
                "Detalle AFIP": err,
            })
        return {"rows": out_rows}

    # --- procesamiento PDFs ---
    for f in files:
        try:
            pdf_bytes = await f.read()
            text = extract_text_pdf(pdf_bytes, max_pages=5)

            cae = find_cae(text)
            vto_raw = find_vto(text)
            vto_date = parse_date(vto_raw)

            fmt_ok = basic_format_ok(cae)
            vig_ok = (vto_date is not None and vto_date >= today)

            estado = []
            estado.append("CAE encontrado" if cae else "CAE NO encontrado")
            if fmt_ok:
                estado.append("Formato OK")
            elif cae:
                estado.append("Formato dudoso")
            if vto_date:
                estado.append("Vigente" if vig_ok else "Vencido")
            else:
                estado.append("Vto no detectado")

            # ===== WSAA + WSFE REAL =====
            # Aquí va tu flujo real:
            # 1) wsaa_loginCms -> TA -> token/sign
            # 2) wsfe.FECompConsultar(Cuit, token, sign, PtoVta, CbteTipo, CbteNro)
            # 3) comparar CAE y Vto + estado
            #
            # Por ahora:
            afip_status = "PENDIENTE"
            afip_detail = f"AFIP: Integración pendiente (WSAA/WSFE). Emisor={cuit_emisor}. ENV={AFIP_ENV}"

            out_rows.append({
                "Archivo": f.filename,
                "CAE": cae or "",
                "Vto CAE": vto_date.strftime("%d/%m/%Y") if vto_date else "",
                "Estado": " | ".join(estado),
                "AFIP": afip_status,
                "Detalle AFIP": afip_detail,
            })

        except Exception as e:
            out_rows.append({
                "Archivo": f.filename,
                "CAE": "",
                "Vto CAE": "",
                "Estado": f"Error procesando PDF: {e}",
                "AFIP": "ERROR",
                "Detalle AFIP": str(e),
            })

    return {"rows": out_rows}
