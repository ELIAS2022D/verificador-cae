import os
import io
import re
import base64
from datetime import datetime
from typing import List, Optional

import pdfplumber
from fastapi import FastAPI, Header, HTTPException, UploadFile, File
from pydantic import BaseModel

app = FastAPI()

# ===================== AUTH CONFIG =====================
MAXI_CUIT = os.getenv("MAXI_CUIT", "")
MAXI_PASSWORD = os.getenv("MAXI_PASSWORD", "")
BACKEND_API_KEY = os.getenv("BACKEND_API_KEY", "")
DEMO_ACCESS_TOKEN = os.getenv("DEMO_ACCESS_TOKEN", "DEMO_TOKEN_OK")

# ===================== AFIP SERVER CREDENTIALS (PROD STYLE) =====================
# Guardar CRT/KEY en Render como env vars en Base64 (no via UI).
AFIP_CERT_B64 = os.getenv("AFIP_CERT_B64", "")
AFIP_KEY_B64 = os.getenv("AFIP_KEY_B64", "")
AFIP_CUIT = os.getenv("AFIP_CUIT", "") or MAXI_CUIT  # default

class LoginRequest(BaseModel):
    cuit: str
    password: str

def check_api_key(x_api_key: str):
    if BACKEND_API_KEY and x_api_key != BACKEND_API_KEY:
        raise HTTPException(status_code=401, detail="API key inválida")

def check_bearer(authorization: str):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Falta Authorization Bearer token")
    token = authorization.split(" ", 1)[1].strip()
    if token != DEMO_ACCESS_TOKEN:
        raise HTTPException(status_code=401, detail="Token inválido")

def get_afip_credentials_bytes():
    """
    En producción: credenciales AFIP viven en servidor (Render env vars / vault).
    Acá las leemos en Base64 y devolvemos bytes.
    """
    if not AFIP_CERT_B64 or not AFIP_KEY_B64:
        # Para demo: no rompemos; simplemente marcamos AFIP como PENDIENTE por falta credenciales.
        return None, None

    try:
        cert_bytes = base64.b64decode(AFIP_CERT_B64)
        key_bytes = base64.b64decode(AFIP_KEY_B64)
        if not cert_bytes or not key_bytes:
            return None, None
        return cert_bytes, key_bytes
    except Exception:
        return None, None

@app.post("/auth/login")
def login(payload: LoginRequest, x_api_key: str = Header(default="")):
    check_api_key(x_api_key)

    if payload.cuit != MAXI_CUIT or payload.password != MAXI_PASSWORD:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    return {"access_token": DEMO_ACCESS_TOKEN}

@app.get("/health")
def health():
    return {"ok": True}

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

# ===================== VERIFY ENDPOINT (PROD STYLE) =====================
@app.post("/verify")
async def verify(
    files: List[UploadFile] = File(...),                # PDFs
    x_api_key: str = Header(default=""),
    authorization: str = Header(default=""),
):
    """
    Producción: el frontend NO sube CRT/KEY.
    El backend usa credenciales del servidor (Render env vars / vault).

    Hoy:
      - extrae CAE y Vto desde los PDFs
      - valida formato/vigencia
      - AFIP queda PENDIENTE hasta implementar WSAA/WSFE real
    """
    check_api_key(x_api_key)
    check_bearer(authorization)

    cert_bytes, key_bytes = get_afip_credentials_bytes()
    has_afip_creds = bool(cert_bytes and key_bytes and AFIP_CUIT)

    today = datetime.now().date()
    out_rows = []

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

            # ===== Hook AFIP REAL =====
            # Acá vas a implementar WSAA (token/sign) + WSFE (FECompConsultar).
            # Inputs disponibles en servidor:
            #   - AFIP_CUIT
            #   - cert_bytes / key_bytes
            if has_afip_creds:
                afip_status = "PENDIENTE"
                afip_detail = "AFIP: Integración pendiente (WSAA/WSFE) - credenciales OK en servidor"
            else:
                afip_status = "PENDIENTE"
                afip_detail = "AFIP: faltan credenciales en servidor (AFIP_CERT_B64 / AFIP_KEY_B64 / AFIP_CUIT)"

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
