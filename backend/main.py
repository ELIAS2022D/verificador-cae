import os
import io
import re
from datetime import datetime
from typing import List, Optional

import pdfplumber
from fastapi import FastAPI, Header, HTTPException, UploadFile, File, Form
from pydantic import BaseModel

app = FastAPI()

# ===================== AUTH CONFIG =====================
MAXI_CUIT = os.getenv("MAXI_CUIT", "")
MAXI_PASSWORD = os.getenv("MAXI_PASSWORD", "")
BACKEND_API_KEY = os.getenv("BACKEND_API_KEY", "")
DEMO_ACCESS_TOKEN = os.getenv("DEMO_ACCESS_TOKEN", "DEMO_TOKEN_OK")

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

@app.post("/auth/login")
def login(payload: LoginRequest, x_api_key: str = Header(default="")):
    check_api_key(x_api_key)

    if not MAXI_CUIT or not MAXI_PASSWORD:
        raise HTTPException(
            status_code=500,
            detail="Backend no configurado: faltan MAXI_CUIT/MAXI_PASSWORD en variables de entorno"
        )

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

# ===================== VERIFY ENDPOINT =====================
@app.post("/verify")
async def verify(
    cuit: str = Form(...),                              # CUIT emisor a validar (desde el frontend)
    files: List[UploadFile] = File(...),                # PDFs
    cert: UploadFile = File(...),                       # certificado.crt (por ahora se sube)
    pkey: UploadFile = File(...),                       # private.key (por ahora se sube)
    x_api_key: str = Header(default=""),
    authorization: str = Header(default=""),
):
    """
    Flujo demo:
      - extrae CAE y Vto desde los PDFs
      - valida formato/vigencia
      - deja hook para integrar AFIP real (WSAA/WSFE)
    """
    check_api_key(x_api_key)
    check_bearer(authorization)

    if not cuit:
        raise HTTPException(status_code=400, detail="CUIT emisor es obligatorio")

    # Leemos credenciales (por ahora solo validamos que existan bytes)
    cert_bytes = await cert.read()
    key_bytes = await pkey.read()
    if not cert_bytes or not key_bytes:
        raise HTTPException(status_code=400, detail="Certificado o clave privada vacíos")

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
            # Implementar WSAA (token/sign) + WSFE (FECompConsultar) usando:
            #   - cuit
            #   - cert_bytes
            #   - key_bytes
            #   - datos del comprobante (a extraer del PDF: pto_vta, nro, tipo, fecha, importe)
            afip_status = "PENDIENTE"
            afip_detail = "AFIP: Integración pendiente (WSAA/WSFE)"

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
