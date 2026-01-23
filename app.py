import io
import zipfile
import re
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st
import pdfplumber
import requests

# ===================== CONFIG =====================
st.set_page_config(page_title="Verificador CAE", layout="wide")
st.title("Verificador de CAE")

BASE_URL = st.secrets.get("BASE_URL", "")
DEFAULT_BACKEND_API_KEY = st.secrets.get("BACKEND_API_KEY", "")
LOGIN_CUIT_DEFAULT = st.secrets.get("LOGIN_CUIT_DEFAULT", "")

if not BASE_URL:
    st.error("Falta BASE_URL en Secrets de Streamlit (Settings → Secrets).")
    st.stop()

# ===================== HERO GIF (solo cuando NO hay login) =====================
gif_path = Path(__file__).parent / "assets" / "conexion.gif"

def show_hero_gif():
    if not gif_path.exists():
        return

    # GIF en tamaño original, alineado a la izquierda
    st.image(str(gif_path))

# ===================== EXTRACCIÓN PDF (LOCAL) =====================
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

def find_first(patterns, text: str):
    for pat in patterns:
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

def parse_date(date_str: str):
    if not date_str:
        return None
    date_str = date_str.strip()
    for fmt in ("%d/%m/%Y", "%d-%m-%Y", "%Y/%m/%d", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_str, fmt).date()
        except ValueError:
            pass
    return None

def basic_format_ok(cae: str) -> bool:
    return bool(cae and re.fullmatch(r"\d{14}", cae))

def extract_text_pdf(file_bytes: bytes, max_pages: int = 5) -> str:
    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
        texts = []
        for page in pdf.pages[:max_pages]:
            texts.append(page.extract_text() or "")
        return "\n".join(texts)

# ===================== SESSION STATE =====================
def ensure_auth_state():
    if "auth" not in st.session_state:
        st.session_state.auth = {
            "logged": False,
            "api_key": DEFAULT_BACKEND_API_KEY,
            "access_token": "",
            "cuit": ""
        }

ensure_auth_state()

# ===================== BACKEND CALLS =====================
def backend_login(base_url: str, api_key: str, cuit: str, password: str) -> str:
    r = requests.post(
        f"{base_url}/auth/login",
        json={"cuit": cuit, "password": password},
        headers={"X-API-Key": api_key} if api_key else {},
        timeout=30,
    )
    if r.status_code != 200:
        raise RuntimeError(f"Login falló ({r.status_code}): {r.text}")
    data = r.json()
    token = data.get("access_token")
    if not token:
        raise RuntimeError("Login OK pero el backend no devolvió access_token.")
    return token

def backend_verify(base_url: str, api_key: str, access_token: str, pdf_items: list):
    headers = {"Authorization": f"Bearer {access_token}"}
    if api_key:
        headers["X-API-Key"] = api_key

    files = [("files", (it["name"], it["bytes"], "application/pdf")) for it in pdf_items]

    r = requests.post(
        f"{base_url}/verify",
        headers=headers,
        files=files,
        timeout=180,
    )
    if r.status_code != 200:
        raise RuntimeError(f"Verify falló ({r.status_code}): {r.text}")
    return r.json()

# ===================== SIDEBAR: LOGIN =====================
with st.sidebar:
    st.subheader("Login")
    api_key = st.session_state.auth["api_key"]

    cuit_login = st.text_input("CUIT", value=st.session_state.auth["cuit"] or LOGIN_CUIT_DEFAULT)
    password = st.text_input("Contraseña", type="password")

    colA, colB = st.columns(2)
    with colA:
        if st.button("Ingresar"):
            try:
                token = backend_login(BASE_URL, api_key, cuit_login, password)
                st.session_state.auth = {
                    "logged": True,
                    "api_key": api_key,
                    "access_token": token,
                    "cuit": cuit_login
                }
                st.success("Sesión iniciada.")
                st.rerun()
            except Exception as e:
                st.error(str(e))

    with colB:
        if st.button("Salir"):
            st.session_state.auth = {
                "logged": False,
                "api_key": DEFAULT_BACKEND_API_KEY,
                "access_token": "",
                "cuit": ""
            }
            st.rerun()

# HERO + STOP si no está logueado
if not st.session_state.auth["logged"]:
    show_hero_gif()
    st.info("Iniciá sesión para habilitar carga y validación.")
    st.stop()

st.info(
    "Flujo: extraemos CAE/Vto desde PDF localmente. "
    "La validación AFIP se realiza en backend con credenciales del lado servidor."
)

# ===================== CARGA ARCHIVOS =====================
st.subheader("Carga de archivos")
mode = st.radio("Modo de carga", ["PDFs (hasta 20)", "ZIP (contiene PDFs)"], horizontal=True)

pdf_files = []

if mode == "PDFs (hasta 20)":
    uploaded = st.file_uploader("Subí hasta 20 facturas en PDF", type=["pdf"], accept_multiple_files=True)
    if uploaded:
        if len(uploaded) > 20:
            st.warning("Subiste más de 20. Para la demo, procesaré solo las primeras 20.")
            uploaded = uploaded[:20]
        pdf_files = [{"name": f.name, "bytes": f.getvalue()} for f in uploaded]
else:
    zip_up = st.file_uploader("Subí 1 archivo ZIP (con PDFs). Para la demo se procesan hasta 20.", type=["zip"])
    if zip_up:
        try:
            with zipfile.ZipFile(io.BytesIO(zip_up.getvalue())) as z:
                names = [n for n in z.namelist() if n.lower().endswith(".pdf") and not n.endswith("/")]
                if not names:
                    st.error("El ZIP no contiene PDFs.")
                else:
                    if len(names) > 20:
                        st.warning(f"El ZIP tiene {len(names)} PDFs. Para demo procesaré solo 20.")
                        names = names[:20]
                    pdf_files = [{"name": n.split('/')[-1], "bytes": z.read(n)} for n in names]
                    st.success(f"PDFs detectados: {len(pdf_files)}")
        except zipfile.BadZipFile:
            st.error("ZIP inválido o dañado.")

# ===================== PREVALIDACIÓN LOCAL =====================
rows = []
if pdf_files:
    today = datetime.now().date()
    progress = st.progress(0)

    for i, f in enumerate(pdf_files, start=1):
        try:
            text = extract_text_pdf(f["bytes"], max_pages=5)
            cae = find_first(CAE_PATTERNS, text)
            vto_raw = find_first(VTO_PATTERNS, text)
            vto_date = parse_date(vto_raw)

            fmt_ok = basic_format_ok(cae)
            vig_ok = (vto_date is not None and vto_date >= today)

            status = []
            status.append("CAE encontrado" if cae else "CAE NO encontrado")
            if fmt_ok:
                status.append("Formato OK")
            elif cae:
                status.append("Formato dudoso")
            if vto_date:
                status.append("Vigente" if vig_ok else "Vencido")
            else:
                status.append("Vto no detectado")

            rows.append({
                "Archivo": f["name"],
                "CAE": cae or "",
                "Vto CAE": vto_date.strftime("%d/%m/%Y") if vto_date else "",
                "Estado": " | ".join(status),
                "AFIP": "",
                "Detalle AFIP": "",
            })
        except Exception as e:
            rows.append({
                "Archivo": f["name"],
                "CAE": "",
                "Vto CAE": "",
                "Estado": f"Error PDF: {e}",
                "AFIP": "",
                "Detalle AFIP": "",
            })

        progress.progress(i / len(pdf_files))

df = pd.DataFrame(rows) if rows else pd.DataFrame(
    columns=["Archivo", "CAE", "Vto CAE", "Estado", "AFIP", "Detalle AFIP"]
)

st.subheader("Resultados (extracción local)")
st.dataframe(df, use_container_width=True)

# ===================== VALIDACIÓN AFIP VIA BACKEND =====================
st.subheader("Validación AFIP (via backend)")
st.caption("El backend valida contra AFIP y devuelve el estado por archivo.")

if st.button("Validar contra AFIP ahora"):
    if not pdf_files:
        st.error("Primero cargá PDFs o ZIP.")
        st.stop()

    try:
        with st.spinner("Consultando AFIP (via backend)..."):
            result = backend_verify(
                base_url=BASE_URL,
                api_key=st.session_state.auth["api_key"],
                access_token=st.session_state.auth["access_token"],
                pdf_items=pdf_files,
            )

        backend_rows = result.get("rows", [])
        if backend_rows:
            df = pd.DataFrame(backend_rows)
            st.success("Validación AFIP completada.")
            st.dataframe(df, use_container_width=True)
        else:
            st.warning("El backend no devolvió rows. Revisá /verify.")
    except Exception as e:
        st.error(str(e))

# ===================== EXPORTS (CSV + XLSX) =====================
# Exporta SIEMPRE lo que esté en df (si validaste, df ya es el de AFIP).
if not df.empty:
    # CAE como texto (evitar notación científica en Excel)
    if "CAE" in df.columns:
        df["CAE"] = df["CAE"].astype(str).apply(lambda x: f"'{x}" if x and x != "nan" else "")

    # limpiar saltos
    if "Estado" in df.columns:
        df["Estado"] = df["Estado"].astype(str).str.replace("\n", " ", regex=False).str.strip()

    col1, col2 = st.columns(2)

    with col1:
        csv_bytes = df.to_csv(index=False, sep=";", encoding="utf-8-sig").encode("utf-8-sig")
        st.download_button(
            "Descargar CSV (Excel)",
            data=csv_bytes,
            file_name="resultado_verificacion_cae.csv",
            mime="text/csv",
        )

    with col2:
        xlsx_buffer = io.BytesIO()
        with pd.ExcelWriter(xlsx_buffer, engine="xlsxwriter") as writer:
            df.to_excel(writer, index=False, sheet_name="Resultados")
        st.download_button(
            "Descargar Excel (.xlsx)",
            data=xlsx_buffer.getvalue(),
            file_name="resultado_verificacion_cae.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
