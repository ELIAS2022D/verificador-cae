import io
import zipfile
import re
from datetime import datetime

import pandas as pd
import streamlit as st
import pdfplumber
import requests

# ===================== CONFIG =====================
st.set_page_config(page_title="Verificador CAE", layout="wide")

BASE_URL = st.secrets.get("BASE_URL", "")
DEFAULT_BACKEND_API_KEY = st.secrets.get("BACKEND_API_KEY", "")
LOGIN_CUIT_DEFAULT = st.secrets.get("LOGIN_CUIT_DEFAULT", "")

# Límite opcional por seguridad (si está vacío o no existe => ilimitado)
MAX_FILES_RAW = st.secrets.get("MAX_FILES", None)
BATCH_SIZE = int(st.secrets.get("BATCH_SIZE", 50))

def _parse_int_or_none(x):
    try:
        if x is None:
            return None
        if isinstance(x, str) and x.strip() == "":
            return None
        return int(x)
    except Exception:
        return None

MAX_FILES = _parse_int_or_none(MAX_FILES_RAW)

if not BASE_URL:
    st.error("Falta BASE_URL en Secrets de Streamlit (Settings → Secrets).")
    st.stop()

# ===================== UI: ESTILO PRO (LOGIN + LOAD) =====================
def inject_modern_ui():
    css = """
    <style>
      /* ===================== Base ===================== */
      .stApp {
        background:
          radial-gradient(1200px circle at 18% 12%, rgba(255, 179, 0, .14), transparent 55%),
          radial-gradient(900px circle at 75% 18%, rgba(255, 60, 120, .16), transparent 55%),
          radial-gradient(1000px circle at 62% 86%, rgba(130, 80, 255, .14), transparent 60%),
          #0b0b0f !important;
        color: rgba(255,255,255,.92) !important;
      }

      /* Ocultar elementos de Streamlit */
      #MainMenu, header, footer { visibility: hidden; height: 0; }
      [data-testid="stToolbar"] { display: none; }
      [data-testid="stStatusWidget"] { display: none; }

      /* Un poco más “clean” */
      .block-container { padding-top: 1.4rem; padding-bottom: 2rem; }

      /* ===================== Animaciones suaves ===================== */
      @keyframes vc_in {
        from { opacity:0; transform: translateY(10px) scale(.985); }
        to   { opacity:1; transform: translateY(0) scale(1); }
      }

      .vc-animate {
        animation: vc_in .42s cubic-bezier(.2,.9,.2,1) both;
      }

      /* ===================== Login layout (centrado) ===================== */
      .vc-wrap{
        min-height: calc(100vh - 120px);
        display:flex;
        align-items:center;
        justify-content:center;
        padding: 24px 16px;
      }

      .vc-card{
        width: min(660px, 96vw);
        background: rgba(18, 18, 24, .78);
        border: 1px solid rgba(255,255,255,.10);
        box-shadow: 0 24px 90px rgba(0,0,0,.55);
        border-radius: 18px;
        padding: 28px 26px;
        position: relative;
        backdrop-filter: blur(14px);
        -webkit-backdrop-filter: blur(14px);
        overflow: hidden;
      }

      .vc-card:before{
        content:"";
        position:absolute;
        inset:-2px;
        border-radius: 20px;
        background: linear-gradient(90deg,
          rgba(255,179,0,.35),
          rgba(255,60,120,.32),
          rgba(130,80,255,.34)
        );
        filter: blur(22px);
        opacity: .30;
        z-index: 0;
      }
      .vc-card > * { position: relative; z-index: 1; }

      .vc-brand{
        display:flex;
        align-items:center;
        gap: 12px;
        margin-bottom: 10px;
      }
      .vc-logo{
        width: 38px;
        height: 38px;
        border-radius: 12px;
        background: linear-gradient(135deg,
          rgba(255,179,0,.95),
          rgba(255,60,120,.90),
          rgba(130,80,255,.88)
        );
        box-shadow: 0 16px 40px rgba(0,0,0,.45);
      }
      .vc-title{
        font-size: 30px;
        font-weight: 820;
        letter-spacing: .2px;
        margin: 0;
        line-height: 1.05;
      }
      .vc-sub{
        margin: 6px 0 18px 0;
        color: rgba(255,255,255,.66);
        font-size: 13.5px;
        line-height: 1.45;
      }

      .vc-chiprow{
        display:flex;
        gap: 8px;
        flex-wrap: wrap;
        margin-top: 10px;
        margin-bottom: 16px;
      }
      .vc-chip{
        display:inline-flex;
        gap:8px;
        align-items:center;
        padding: 6px 10px;
        border-radius: 999px;
        border: 1px solid rgba(255,255,255,.10);
        background: rgba(255,255,255,.04);
        font-size: 12px;
        color: rgba(255,255,255,.72);
      }

      .vc-grid{
        display:grid;
        grid-template-columns: 1.05fr .95fr;
        gap: 16px;
      }
      @media (max-width: 920px){
        .vc-grid{ grid-template-columns: 1fr; }
      }

      .vc-panel{
        border: 1px solid rgba(255,255,255,.08);
        background: rgba(255,255,255,.03);
        border-radius: 16px;
        padding: 16px 14px;
      }
      .vc-panel h3{
        margin: 0 0 8px 0;
        font-size: 16px;
        font-weight: 760;
        color: rgba(255,255,255,.92);
      }
      .vc-steps{
        display:grid;
        grid-template-columns: 1fr 1fr;
        gap: 10px;
        margin-top: 8px;
      }
      @media (max-width: 920px){
        .vc-steps{ grid-template-columns: 1fr; }
      }
      .vc-step{
        border: 1px solid rgba(255,255,255,.08);
        background: rgba(0,0,0,.18);
        border-radius: 14px;
        padding: 12px 12px;
      }
      .vc-step b{ display:block; font-size: 13px; margin-bottom: 4px; }
      .vc-step span{ color: rgba(255,255,255,.66); font-size: 12.5px; line-height: 1.35; }

      /* ===================== Inputs (global) ===================== */
      .stTextInput input, .stPassword input{
        background: rgba(255,255,255,.05) !important;
        border: 1px solid rgba(255,255,255,.10) !important;
        color: rgba(255,255,255,.92) !important;
        border-radius: 12px !important;
        padding: 12px 12px !important;
        transition: border-color .18s ease, box-shadow .18s ease, transform .18s ease;
      }
      .stTextInput input:focus, .stPassword input:focus{
        border-color: rgba(255,179,0,.45) !important;
        box-shadow: 0 0 0 4px rgba(255,179,0,.10) !important;
        transform: translateY(-1px);
      }
      label, .stTextInput label, .stPassword label{
        color: rgba(255,255,255,.70) !important;
        font-size: 12px !important;
      }

      /* ===================== Buttons (global) ===================== */
      .stButton button{
        border: 1px solid rgba(255,255,255,.12) !important;
        background: linear-gradient(90deg,
          rgba(255,179,0,.90),
          rgba(255,60,120,.88),
          rgba(130,80,255,.86)
        ) !important;
        color: #0b0b0f !important;
        font-weight: 820 !important;
        border-radius: 12px !important;
        padding: 12px 14px !important;
        transition: transform .18s ease, filter .18s ease, box-shadow .18s ease;
        box-shadow: 0 14px 30px rgba(0,0,0,.35);
      }
      .stButton button:hover{
        transform: translateY(-1px) scale(1.01);
        filter: brightness(1.03);
      }
      .stButton button:active{
        transform: translateY(0px) scale(.995);
      }

      /* ===================== Sidebar “prolijo” ===================== */
      [data-testid="stSidebar"]{
        background: rgba(18, 18, 24, .45) !important;
        border-right: 1px solid rgba(255,255,255,.08);
        backdrop-filter: blur(10px);
      }
      [data-testid="stSidebar"] .stMarkdown,
      [data-testid="stSidebar"] label,
      [data-testid="stSidebar"] span,
      [data-testid="stSidebar"] p {
        color: rgba(255,255,255,.86) !important;
      }

      /* ===================== Overlay de carga ===================== */
      .vc-overlay {
        position: fixed;
        inset: 0;
        z-index: 99999;
        display: flex;
        align-items: center;
        justify-content: center;
        background: rgba(8, 8, 12, .62);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        animation: vc_fade .20s ease-out both;
      }
      @keyframes vc_fade{
        from { opacity:0; }
        to   { opacity:1; }
      }
      .vc-overlay-card{
        width: min(520px, 92vw);
        background: rgba(18, 18, 24, .82);
        border: 1px solid rgba(255,255,255,.10);
        box-shadow: 0 24px 90px rgba(0,0,0,.6);
        border-radius: 18px;
        padding: 22px 20px;
        position: relative;
        overflow: hidden;
      }
      .vc-overlay-card:before{
        content:"";
        position:absolute;
        inset:-2px;
        border-radius: 20px;
        background: linear-gradient(90deg,
          rgba(255,179,0,.32),
          rgba(255,60,120,.28),
          rgba(130,80,255,.30)
        );
        filter: blur(24px);
        opacity: .28;
      }
      .vc-overlay-card > * { position: relative; z-index: 1; }

      .vc-spin{
        width: 54px; height: 54px;
        border-radius: 999px;
        border: 4px solid rgba(255,255,255,.14);
        border-top-color: rgba(255,179,0,.92);
        animation: vc_spin 1s linear infinite;
        margin: 8px auto 10px auto;
      }
      @keyframes vc_spin{ to { transform: rotate(360deg); } }

      .vc-overlay-title{
        text-align:center;
        font-size: 16px;
        font-weight: 780;
        margin: 0 0 6px 0;
      }
      .vc-overlay-sub{
        text-align:center;
        color: rgba(255,255,255,.66);
        font-size: 12.5px;
        margin: 0;
      }
      .vc-progressbar{
        height: 8px;
        border-radius: 999px;
        background: rgba(255,255,255,.10);
        overflow: hidden;
        margin-top: 14px;
      }
      .vc-progressbar > div{
        height: 100%;
        width: 45%;
        border-radius: 999px;
        background: linear-gradient(90deg,
          rgba(255,179,0,.90),
          rgba(255,60,120,.86),
          rgba(130,80,255,.84)
        );
        animation: vc_load 1.0s ease-in-out infinite alternate;
      }
      @keyframes vc_load{
        from { transform: translateX(-20%); width: 35%; }
        to   { transform: translateX(40%);  width: 60%; }
      }
    </style>
    """
    st.markdown(css, unsafe_allow_html=True)

inject_modern_ui()

# ===================== OVERLAY HELPERS =====================
def show_loading_overlay(placeholder, title: str, subtitle: str = ""):
    html = f"""
    <div class="vc-overlay">
      <div class="vc-overlay-card">
        <div class="vc-spin"></div>
        <p class="vc-overlay-title">{title}</p>
        <p class="vc-overlay-sub">{subtitle}</p>
        <div class="vc-progressbar"><div></div></div>
      </div>
    </div>
    """
    placeholder.markdown(html, unsafe_allow_html=True)

def hide_loading_overlay(placeholder):
    placeholder.empty()

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

def backend_verify(base_url: str, api_key: str, access_token: str, pdf_items: list, timeout_s: int = 180):
    headers = {"Authorization": f"Bearer {access_token}"}
    if api_key:
        headers["X-API-Key"] = api_key

    files = [("files", (it["name"], it["bytes"], "application/pdf")) for it in pdf_items]

    r = requests.post(
        f"{base_url}/verify",
        headers=headers,
        files=files,
        timeout=timeout_s,
    )
    if r.status_code != 200:
        raise RuntimeError(f"Verify falló ({r.status_code}): {r.text}")
    return r.json()

def backend_usage_current(base_url: str, api_key: str, access_token: str):
    headers = {"Authorization": f"Bearer {access_token}"}
    if api_key:
        headers["X-API-Key"] = api_key
    r = requests.get(f"{base_url}/usage/current", headers=headers, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Usage falló ({r.status_code}): {r.text}")
    return r.json()

def backend_send_usage_email(base_url: str, api_key: str, access_token: str):
    """
    Dispara el envío del reporte por email desde el BACKEND.
    El backend debe tener implementado: POST /usage/email
    y usar SMTP_* + CLIENT_REPORT_EMAIL desde ENV VARS en Render.
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    if api_key:
        headers["X-API-Key"] = api_key

    r = requests.post(f"{base_url}/usage/email", headers=headers, timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f"Enviar email falló ({r.status_code}): {r.text}")
    return r.json()

def chunk_list(items, size: int):
    if size <= 0:
        return [items]
    return [items[i:i+size] for i in range(0, len(items), size)]

# ===================== LOGIN SCREEN (PRO) =====================
def render_login_screen():
    st.markdown('<div class="vc-wrap vc-animate"><div class="vc-card">', unsafe_allow_html=True)

    st.markdown(
        """
        <div class="vc-brand">
          <div class="vc-logo"></div>
          <div>
            <h1 class="vc-title">Verificador de CAE</h1>
            <div class="vc-sub">Workspace seguro para validar facturas y confirmar CAE contra AFIP (WSCDC).</div>
          </div>
        </div>
        <div class="vc-chiprow">
          <div class="vc-chip">🔒 Acceso con token</div>
          <div class="vc-chip">⚡ Procesamiento por tandas</div>
          <div class="vc-chip">✅ Validación AFIP</div>
          <div class="vc-chip">📄 PDF / ZIP</div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown('<div class="vc-grid">', unsafe_allow_html=True)

    # Panel izquierda: Login
    st.markdown('<div class="vc-panel">', unsafe_allow_html=True)
    st.markdown("<h3>Acceso</h3>", unsafe_allow_html=True)
    st.markdown('<div class="vc-sub" style="margin-top:-2px;">Iniciá sesión para comenzar. Tu sesión se valida contra el backend.</div>', unsafe_allow_html=True)

    api_key = st.session_state.auth["api_key"]
    cuit_login = st.text_input("CUIT (sin guiones)", value=st.session_state.auth["cuit"] or LOGIN_CUIT_DEFAULT, key="login_cuit_main")
    password = st.text_input("Contraseña", type="password", key="login_pass_main")

    colA, colB = st.columns(2)
    with colA:
        if st.button("Ingresar", use_container_width=True, key="btn_login_main"):
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
        if st.button("Limpiar", use_container_width=True, key="btn_clear_main"):
            st.session_state.pop("login_pass_main", None)
            st.rerun()

    st.markdown(
        """
        <div class="vc-sub" style="margin-top:10px;">
          Consejo: si vas a procesar muchos archivos, usá ZIP y dejá que el sistema lo procese en tandas.
        </div>
        """,
        unsafe_allow_html=True
    )
    st.markdown('</div>', unsafe_allow_html=True)

    # Panel derecha: Cómo funciona
    st.markdown('<div class="vc-panel">', unsafe_allow_html=True)
    st.markdown("<h3>Cómo funciona</h3>", unsafe_allow_html=True)
    st.markdown('<div class="vc-sub" style="margin-top:-2px;">Flujo estándar de validación, pensado para uso operativo.</div>', unsafe_allow_html=True)

    st.markdown(
        """
        <div class="vc-steps">
          <div class="vc-step"><b>1) Ingresá</b><span>Accedé con tu CUIT y contraseña.</span></div>
          <div class="vc-step"><b>2) Subí PDFs/ZIP</b><span>Cargá facturas en PDF o un ZIP con PDFs.</span></div>
          <div class="vc-step"><b>3) Vista previa</b><span>Detectamos CAE y vencimiento localmente desde el PDF.</span></div>
          <div class="vc-step"><b>4) Validación AFIP</b><span>Confirmamos contra AFIP vía WSCDC (servidor).</span></div>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)  # grid

    st.markdown(
        """
        <div class="vc-sub" style="margin-top:14px;">
          Al iniciar sesión, vas a ver el resumen del mes y la carga de archivos. 
          La interfaz está optimizada para evitar demoras y mantener consistencia.
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown('</div></div>', unsafe_allow_html=True)  # card + wrap

# ===================== SIDEBAR (solo cuando está logueado) =====================
def render_sidebar_logged():
    with st.sidebar:
        st.markdown("### Acceso")
        st.markdown(f"**CUIT:** `{st.session_state.auth.get('cuit','')}`")

        colA, colB = st.columns(2)
        with colA:
            st.caption("Sesión")
            st.write("✅ Activa")
        with colB:
            st.caption("Backend")
            st.write("🟢 OK" if BASE_URL else "🔴")

        st.divider()

        if st.button("Salir", use_container_width=True):
            st.session_state.auth = {
                "logged": False,
                "api_key": DEFAULT_BACKEND_API_KEY,
                "access_token": "",
                "cuit": ""
            }
            st.rerun()

# ===================== HOME (NO LOGUEADO) =====================
if not st.session_state.auth["logged"]:
    # Mostramos login pro y cortamos.
    render_login_screen()
    st.stop()

# Sidebar pro cuando está logueado
render_sidebar_logged()

# ===================== HEADER =====================
st.title("Verificador de CAE")

# ===================== INFO GENERAL =====================
st.info(
    "Flujo: detectamos CAE/Vto desde el PDF localmente. "
    "La validación AFIP se realiza del lado servidor utilizando el servicio oficial WSCDC (ComprobanteConstatar)."
)

# ===================== CONSUMO DEL MES + ENVÍO EMAIL =====================
st.subheader("Resumen de uso del mes")

try:
    usage = backend_usage_current(
        base_url=BASE_URL,
        api_key=st.session_state.auth["api_key"],
        access_token=st.session_state.auth["access_token"],
    )
    ym = usage.get("year_month", "")
    files_count = int(usage.get("files_count", 0) or 0)
    requests_count = int(usage.get("requests_count", 0) or 0)

    colm1, colm2, colm3 = st.columns(3)
    with colm1:
        st.metric("PDFs procesados", files_count)
    with colm2:
        st.metric("Solicitudes realizadas", requests_count)
    with colm3:
        st.metric("Mes", ym or "-")

    cbtn1, cbtn2 = st.columns([1, 3])
    with cbtn1:
        if st.button("Enviar resumen por email", use_container_width=True):
            try:
                backend_send_usage_email(
                    base_url=BASE_URL,
                    api_key=st.session_state.auth["api_key"],
                    access_token=st.session_state.auth["access_token"],
                )
                st.success("Email enviado correctamente.")
            except Exception as e:
                st.error(str(e))

except Exception:
    st.warning("No pudimos obtener el resumen de uso en este momento. Probá nuevamente en unos segundos.")

st.divider()

# ===================== CARGA ARCHIVOS =====================
st.subheader("Carga de facturas")

help_text = "sin límite" if MAX_FILES is None else f"hasta {MAX_FILES}"
mode = st.radio(
    "Modo de carga",
    [f"PDFs ({help_text})", f"ZIP (contiene PDFs) ({help_text})"],
    horizontal=True
)

pdf_files = []

if mode.startswith("PDFs"):
    uploaded = st.file_uploader("Subí tus facturas en PDF", type=["pdf"], accept_multiple_files=True)
    if uploaded:
        if MAX_FILES is not None and len(uploaded) > MAX_FILES:
            st.warning(f"Subiste {len(uploaded)} PDFs. Por configuración se procesarán solo los primeros {MAX_FILES}.")
            uploaded = uploaded[:MAX_FILES]
        pdf_files = [{"name": f.name, "bytes": f.getvalue()} for f in uploaded]
else:
    zip_up = st.file_uploader("Subí 1 archivo ZIP (con PDFs)", type=["zip"])
    if zip_up:
        try:
            with zipfile.ZipFile(io.BytesIO(zip_up.getvalue())) as z:
                names = [n for n in z.namelist() if n.lower().endswith(".pdf") and not n.endswith("/")]
                if not names:
                    st.error("No encontramos PDFs dentro del ZIP.")
                else:
                    if MAX_FILES is not None and len(names) > MAX_FILES:
                        st.warning(f"El ZIP tiene {len(names)} PDFs. Por configuración se procesarán solo {MAX_FILES}.")
                        names = names[:MAX_FILES]
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
            status.append("CAE encontrado" if cae else "CAE no encontrado")
            if fmt_ok:
                status.append("Formato OK")
            elif cae:
                status.append("Formato a revisar")
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
                "Estado": f"Error al leer el PDF: {e}",
                "AFIP": "",
                "Detalle AFIP": "",
            })

        progress.progress(i / len(pdf_files))

df = pd.DataFrame(rows) if rows else pd.DataFrame(
    columns=["Archivo", "CAE", "Vto CAE", "Estado", "AFIP", "Detalle AFIP"]
)

st.subheader("Vista previa (datos detectados en el PDF)")
st.dataframe(df, use_container_width=True)

# ===================== VALIDACIÓN AFIP VIA BACKEND =====================
st.subheader("Validación contra AFIP")
st.caption("Validamos contra AFIP y devolvemos el estado por archivo.")
st.caption(f"Para evitar demoras, procesamos los archivos en tandas de {BATCH_SIZE} PDFs (ajustable).")

overlay = st.empty()

if st.button("Validar ahora", use_container_width=True):
    if not pdf_files:
        st.error("Primero cargá PDFs o un ZIP con PDFs.")
        st.stop()

    try:
        all_rows = []
        batches = chunk_list(pdf_files, BATCH_SIZE)

        # Overlay pro + progreso por tandas
        show_loading_overlay(
            overlay,
            title="Consultando AFIP…",
            subtitle="Procesando en tandas para evitar demoras. No cierres esta pestaña."
        )

        batch_progress = st.progress(0)
        with st.spinner("Consultando AFIP..."):
            for idx, batch in enumerate(batches, start=1):
                # update overlay subtitle con “tanda X / N”
                show_loading_overlay(
                    overlay,
                    title="Consultando AFIP…",
                    subtitle=f"Tanda {idx}/{len(batches)} en proceso…"
                )

                result = backend_verify(
                    base_url=BASE_URL,
                    api_key=st.session_state.auth["api_key"],
                    access_token=st.session_state.auth["access_token"],
                    pdf_items=batch,
                    timeout_s=180,
                )
                backend_rows = result.get("rows", [])
                all_rows.extend(backend_rows)
                batch_progress.progress(idx / len(batches))

        hide_loading_overlay(overlay)

        if all_rows:
            df = pd.DataFrame(all_rows)
            st.success("Validación completada.")
            st.dataframe(df, use_container_width=True)
        else:
            st.warning("No pudimos obtener resultados del servidor. Probá de nuevo en unos segundos.")
    except Exception as e:
        hide_loading_overlay(overlay)
        st.error(str(e))

# ===================== EXPORTS (CSV + XLSX) =====================
if not df.empty:
    # CAE como texto (evitar notación científica en Excel)
    if "CAE" in df.columns:
        df["CAE"] = df["CAE"].astype(str).apply(lambda x: f"'{x}" if x and x != "nan" else "")

    # limpiar saltos
    if "Estado" in df.columns:
        df["Estado"] = df["Estado"].astype(str).str.replace("\n", " ", regex=False).str.strip()

    st.subheader("Descargas")
    col1, col2 = st.columns(2)

    with col1:
        csv_bytes = df.to_csv(index=False, sep=";", encoding="utf-8-sig").encode("utf-8-sig")
        st.download_button(
            "Descargar CSV (.csv)",
            data=csv_bytes,
            file_name="resultado_verificacion_cae.csv",
            mime="text/csv",
            use_container_width=True,
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
            use_container_width=True,
        )
