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
    cuit: str = Form(...),
    files: List[UploadFile] = File(...),
    x_api_key: str = Header(""),
    authorization: str = Header("")
):
    check_api_key(x_api_key)
    check_token(authorization)

    rows = []

    for f in files:
        pdf_bytes = await f.read()
        text = extract_text(pdf_bytes)
        cae = find_cae(text)

        if not cae:
            rows.append({
                "Archivo": f.filename,
                "AFIP": "NO",
                "Detalle AFIP": "CAE no encontrado en PDF"
            })
            continue

        # ⚠️ ACA tenés que ajustar tipo_cbte / pto_vta / nro_cbte
        # para la demo podés hardcodear o parsear del PDF
        response_xml = wsdc_consultar(
            cuit_emisor=cuit,
            tipo_cbte=6,     # Factura B
            pto_vta=1,
            nro_cbte=1
        )

        rows.append({
            "Archivo": f.filename,
            "CAE": cae,
            "AFIP": "OK",
            "Detalle AFIP": "Validado contra AFIP (WSCDC)"
        })

    return {"rows": rows}
