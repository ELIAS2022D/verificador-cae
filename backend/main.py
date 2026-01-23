import os
import io
import re
from datetime import datetime
from typing import List

import pdfplumber
from fastapi import FastAPI, Header, HTTPException, UploadFile, File, Form
from pydantic import BaseModel

from afip_wsdc import wsdc_consultar

app = FastAPI()

# ===================== AUTH =====================
MAXI_CUIT = os.getenv("MAXI_CUIT")
MAXI_PASSWORD = os.getenv("MAXI_PASSWORD")
BACKEND_API_KEY = os.getenv("BACKEND_API_KEY")
DEMO_TOKEN = "DEMO_TOKEN_OK"

class LoginRequest(BaseModel):
    cuit: str
    password: str

def check_api_key(x_api_key: str):
    if BACKEND_API_KEY and x_api_key != BACKEND_API_KEY:
        raise HTTPException(401, "API key inválida")

def check_token(auth: str):
    if auth != f"Bearer {DEMO_TOKEN}":
        raise HTTPException(401, "Token inválido")

@app.post("/auth/login")
def login(payload: LoginRequest, x_api_key: str = Header("")):
    check_api_key(x_api_key)
    if payload.cuit != MAXI_CUIT or payload.password != MAXI_PASSWORD:
        raise HTTPException(401, "Credenciales inválidas")
    return {"access_token": DEMO_TOKEN}

# ===================== PDF =====================
CAE_RE = re.compile(r"\bCAE\b\D{0,20}(\d{14})", re.I)

def extract_text(pdf_bytes: bytes):
    with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
        return "\n".join([p.extract_text() or "" for p in pdf.pages[:5]])

def find_cae(text: str):
    m = CAE_RE.search(text)
    return m.group(1) if m else None

# ===================== VERIFY =====================
@app.post("/verify")
async def verify(
    files: List[UploadFile] = File(...),
    x_api_key: str = Header(default=""),
    authorization: str = Header(default=""),
):
    check_api_key(x_api_key)
    check_bearer(authorization)

    # CUIT representado fijo desde Render
    afip_cuit = os.getenv("AFIP_CUIT") or os.getenv("MAXI_CUIT")
    if not afip_cuit:
        raise HTTPException(status_code=500, detail="Falta AFIP_CUIT (o MAXI_CUIT) en variables de entorno")

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

            # ===== AFIP REAL (WSAA + WSCDC/WSFE) =====
            # Acá llamás tu validador real usando afip_cuit fijo.
            # Por ahora dejo placeholder (si ya tenés wsdc_consultar, lo conectamos).
            afip_status = "PENDIENTE"
            afip_detail = f"AFIP listo (CUIT {afip_cuit}). Falta conectar consulta WS."

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
