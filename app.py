import os
import io
import zipfile
import re
from datetime import datetime

import pandas as pd
import streamlit as st
import pdfplumber
import requests
from PIL import Image

# ===================== BLOQUEAR ENTER EN PASSWORD =====================
def block_enter_on_password_inputs():
    st.markdown(
        """
        <script>
        (function() {
          function attach() {
            const pw = window.parent.document.querySelectorAll('input[type="password"]');
            pw.forEach((el) => {
              if (el.dataset.noenter === "1") return;
              el.dataset.noenter = "1";
              el.addEventListener('keydown', function(e) {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  e.stopPropagation();
                  return false;
                }
              }, true);
            });
          }

          attach();
          const obs = new MutationObserver(() => attach());
          obs.observe(window.parent.document.body, { childList: true, subtree: true });
        })();
        </script>
        """,
        unsafe_allow_html=True,
    )

# ===================== BRANDING + CONFIG =====================
icon = Image.open("assets/logo_Sitio.png")

st.set_page_config(
    page_title="LexaCAE | Verificador CAE",
    page_icon=icon,
    layout="wide",
)

# Header con logo + nombre
col1, col2 = st.columns([1, 2])
with col1:
    # Si en mobile se rompe, igual lo dejamos porque vos lo querías grande.
    st.image("assets/favicon.png", width=600)
with col2:
    st.markdown("## Validación en la nube.")
    st.caption("## Verificación oficial de CAE contra AFIP.")
    st.markdown("## Práctico. Seguro. Confiable.")

st.divider()

# ✅ activar bloqueo de Enter en password (una sola vez)
block_enter_on_password_inputs()

# ===================== CONFIG APP =====================
st.title("Verificador de CAE")

# ✅ Render ENV VARS (no st.secrets)
BASE_URL = os.getenv("BASE_URL", "").strip()
DEFAULT_BACKEND_API_KEY = os.getenv("BACKEND_API_KEY", "").strip()
LOGIN_CUIT_DEFAULT = os.getenv("LOGIN_CUIT_DEFAULT", "").strip()

# Límite opcional por seguridad (si está vacío o no existe => ilimitado)
MAX_FILES_RAW = os.getenv("MAX_FILES", None)
BATCH_SIZE_RAW = os.getenv("BATCH_SIZE", "50")

# (Opcional) WhatsApp para renovación (si no lo seteás, usa el tuyo por defecto)
RENEW_WHATSAPP = (os.getenv("RENEW_WHATSAPP", "5491131433906") or "").strip()
RENEW_TEXT = (os.getenv("RENEW_TEXT", "Hola! Quiero renovar mi plan de LexaCAE. ¿Me ayudan?") or "").strip()

# ===================== WHATSAPP FLOTANTE (GLOBAL) =====================
def inject_whatsapp_floating_button(phone: str, default_text: str, bubble_text: str = "Soporte técnico"):
    """
    Botón flotante WhatsApp (fijo abajo a la derecha) + mini tooltip.
    Funciona en Streamlit porque inyecta HTML/CSS en el DOM del parent.
    """
    import urllib.parse

    phone_digits = re.sub(r"\D+", "", phone or "")
    if not phone_digits:
        phone_digits = "5491131433906"

    msg = urllib.parse.quote((default_text or "").strip())
    wa_url = f"https://wa.me/{phone_digits}?text={msg}"

    bubble_text_safe = (bubble_text or "Soporte técnico").replace("<", "&lt;").replace(">", "&gt;")

    st.markdown(
        f"""
        <style>
          .wa-float {{
            position: fixed;
            right: 18px;
            bottom: 18px;
            z-index: 999999;
            display: flex;
            align-items: center;
            gap: 10px;
            font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji";
          }}

          .wa-bubble {{
            background: rgba(15, 23, 42, 0.92);
            color: #fff;
            padding: 10px 12px;
            border-radius: 999px;
            font-size: 13px;
            line-height: 1;
            box-shadow: 0 12px 28px rgba(0,0,0,.25);
            border: 1px solid rgba(255,255,255,.12);
            white-space: nowrap;
          }}

          .wa-btn {{
            width: 56px;
            height: 56px;
            border-radius: 999px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            text-decoration: none !important;
            background: #25D366;
            box-shadow: 0 14px 32px rgba(0,0,0,.25);
            border: 1px solid rgba(255,255,255,.25);
            transition: transform .15s ease, box-shadow .15s ease;
          }}
          .wa-btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 18px 36px rgba(0,0,0,.32);
          }}

          .wa-icon {{
            width: 28px;
            height: 28px;
            fill: white;
          }}

          @media (max-width: 720px) {{
            .wa-bubble {{ display: none; }}
            .wa-btn {{ width: 54px; height: 54px; }}
          }}
        </style>

        <div class="wa-float">
          <div class="wa-bubble">{bubble_text_safe}</div>
          <a class="wa-btn" href="{wa_url}" target="_blank" rel="noopener noreferrer" aria-label="WhatsApp Soporte">
            <svg class="wa-icon" viewBox="0 0 32 32" aria-hidden="true">
              <path d="M19.11 17.44c-.27-.13-1.6-.79-1.85-.88-.25-.09-.43-.13-.61.13-.18.27-.7.88-.86 1.06-.16.18-.32.2-.59.07-.27-.13-1.14-.42-2.17-1.33-.8-.71-1.34-1.58-1.5-1.85-.16-.27-.02-.42.12-.55.12-.12.27-.32.4-.48.13-.16.18-.27.27-.45.09-.18.04-.34-.02-.48-.07-.13-.61-1.47-.84-2.01-.22-.53-.45-.46-.61-.47h-.52c-.18 0-.48.07-.73.34-.25.27-.95.93-.95 2.27 0 1.34.98 2.63 1.12 2.81.13.18 1.93 2.95 4.68 4.13.66.28 1.18.45 1.58.58.66.21 1.26.18 1.74.11.53-.08 1.6-.65 1.83-1.28.23-.63.23-1.17.16-1.28-.07-.11-.25-.18-.52-.32z"/>
              <path d="M26.67 5.33A13.3 13.3 0 0 0 16 1.33C8.82 1.33 3 7.15 3 14.33c0 2.3.6 4.56 1.74 6.55L3 30.67l10-1.63A13.2 13.2 0 0 0 16 27.33c7.18 0 13-5.82 13-13 0-3.47-1.35-6.73-3.33-9zM16 25.33c-2.03 0-4.01-.55-5.74-1.6l-.41-.24-5.94.97.99-5.79-.26-.42A10.9 10.9 0 0 1 5 14.33C5 8.25 9.92 3.33 16 3.33c2.91 0 5.65 1.13 7.71 3.2A10.84 10.84 0 0 1 27 14.33c0 6.08-4.92 11-11 11z"/>
            </svg>
          </a>
        </div>
        """,
        unsafe_allow_html=True,
    )

# ✅ WhatsApp soporte (configurable por ENV; por defecto usa el mismo que renovación)
SUPPORT_WHATSAPP = (os.getenv("SUPPORT_WHATSAPP", RENEW_WHATSAPP) or "5491131433906").strip()
SUPPORT_TEXT = (os.getenv(
    "SUPPORT_TEXT",
    "Hola! Necesito soporte con LexaCAE. Mi CUIT es: ____ . Detalle/Problema: ____ ."
) or "").strip()
SUPPORT_BUBBLE = (os.getenv("SUPPORT_BUBBLE", "Soporte técnico") or "Soporte técnico").strip()

inject_whatsapp_floating_button(SUPPORT_WHATSAPP, SUPPORT_TEXT, SUPPORT_BUBBLE)


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

try:
    BATCH_SIZE = int(BATCH_SIZE_RAW)
except Exception:
    BATCH_SIZE = 50

if BATCH_SIZE <= 0:
    BATCH_SIZE = 50

# Normalizar BASE_URL sin trailing slash
BASE_URL = BASE_URL.rstrip("/")

if not BASE_URL:
    st.error("Falta BASE_URL en Render (Environment Variables). Ej: https://tu-backend.onrender.com")
    st.stop()

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
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:Fecha\s+de\s+)?(?:Vto\.?\s*de\s*CAE|Vto\.?\s*CAE|Vencimiento\s*CAE|CAE\s*Vto\.?)\D{0,30}(\d{4}[/-]\d{2}[/-]\d{2})",
        re.IGNORECASE,
    ),
]


def find_first(patterns, text: str):
    for pat in patterns:
        m = pat.search(text)
        if m:
            return m.group(1)
    idx = text.lower().find("cae")
    if idx != -1:
        window = text[idx : idx + 250]
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


@st.cache_data(show_spinner=False)
def extract_text_pdf_cached(file_bytes: bytes, max_pages: int = 5) -> str:
    # Cachea la extracción para no recalcular en cada rerun
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
            "cuit": "",
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
        # Intentar parsear JSON para error semántico del backend (PLAN_LIMIT_REACHED u otros)
        try:
            j = r.json()
            detail = j.get("detail", j)
            if isinstance(detail, dict) and detail.get("code") == "PLAN_LIMIT_REACHED":
                used = detail.get("used")
                limit = detail.get("limit")
                msg = detail.get("message") or "Ha alcanzado el límite de su plan."
                raise RuntimeError(f"{msg} (Usadas: {used} / Límite: {limit})")
            # Si hay JSON pero no es ese code, lo devolvemos igual (mejor debug)
            raise RuntimeError(f"Verify falló ({r.status_code}): {detail}")
        except ValueError:
            # No es JSON
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


def backend_usage_total(base_url: str, api_key: str, access_token: str):
    headers = {"Authorization": f"Bearer {access_token}"}
    if api_key:
        headers["X-API-Key"] = api_key
    r = requests.get(f"{base_url}/usage/total", headers=headers, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Usage total falló ({r.status_code}): {r.text}")
    return r.json()


def backend_send_usage_email(base_url: str, api_key: str, access_token: str):
    headers = {"Authorization": f"Bearer {access_token}"}
    if api_key:
        headers["X-API-Key"] = api_key
    r = requests.post(f"{base_url}/usage/email", headers=headers, timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f"Enviar email falló ({r.status_code}): {r.text}")
    return r.json()


# ===================== WSFEv1 (FRONT CALLS) =====================
def backend_tenant_upsert(
    base_url: str,
    api_key: str,
    access_token: str,
    cuit: str,
    cert_b64: str,
    key_b64: str,
    enabled: bool = True,
):
    headers = {"Authorization": f"Bearer {access_token}"}
    if api_key:
        headers["X-API-Key"] = api_key

    payload = {"cuit": cuit, "cert_b64": cert_b64, "key_b64": key_b64, "enabled": bool(enabled)}
    r = requests.post(f"{base_url}/tenants/upsert", headers=headers, json=payload, timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f"Tenant upsert falló ({r.status_code}): {r.text}")
    return r.json()


def backend_wsfe_last(base_url: str, api_key: str, access_token: str, cuit: str, pto_vta: int, cbte_tipo: int):
    headers = {"Authorization": f"Bearer {access_token}"}
    if api_key:
        headers["X-API-Key"] = api_key

    payload = {"cuit": cuit, "pto_vta": int(pto_vta), "cbte_tipo": int(cbte_tipo)}
    r = requests.post(f"{base_url}/wsfe/last", headers=headers, json=payload, timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f"WSFE last falló ({r.status_code}): {r.text}")
    return r.json()


def backend_wsfe_cae(base_url: str, api_key: str, access_token: str, payload: dict):
    headers = {"Authorization": f"Bearer {access_token}"}
    if api_key:
        headers["X-API-Key"] = api_key

    r = requests.post(f"{base_url}/wsfe/cae", headers=headers, json=payload, timeout=90)
    if r.status_code != 200:
        raise RuntimeError(f"WSFE CAE falló ({r.status_code}): {r.text}")
    return r.json()


def backend_wsfe_pdf(base_url: str, api_key: str, access_token: str, payload: dict, timeout_s: int = 60) -> bytes:
    headers = {"Authorization": f"Bearer {access_token}"}
    if api_key:
        headers["X-API-Key"] = api_key

    r = requests.post(f"{base_url}/wsfe/pdf", headers=headers, json=payload, timeout=timeout_s)
    if r.status_code != 200:
        raise RuntimeError(f"WSFE PDF falló ({r.status_code}): {r.text}")
    return r.content


def backend_wsfe_send_email(base_url: str, api_key: str, access_token: str, payload: dict, timeout_s: int = 60) -> dict:
    headers = {"Authorization": f"Bearer {access_token}"}
    if api_key:
        headers["X-API-Key"] = api_key

    r = requests.post(f"{base_url}/wsfe/email", headers=headers, json=payload, timeout=timeout_s)
    if r.status_code != 200:
        raise RuntimeError(f"WSFE email falló ({r.status_code}): {r.text}")
    return r.json()


def chunk_list(items, size: int):
    if size <= 0:
        return [items]
    return [items[i : i + size] for i in range(0, len(items), size)]


def _wa_renew_url() -> str:
    import urllib.parse
    phone = re.sub(r"\D+", "", RENEW_WHATSAPP or "")
    if not phone:
        phone = "5491131433906"
    txt = urllib.parse.quote(RENEW_TEXT or "")
    return f"https://wa.me/{phone}?text={txt}"


# ===================== SIDEBAR: LOGIN + NAV =====================
with st.sidebar:
    st.subheader("Acceso")

    api_key = st.session_state.auth["api_key"]

    cuit_login = st.text_input(
        "CUIT (sin guiones)",
        value=st.session_state.auth["cuit"] or LOGIN_CUIT_DEFAULT,
    )
    password = st.text_input("Contraseña", type="password")

    colA, colB = st.columns(2)
    with colA:
        if st.button("Ingresar", use_container_width=True):
            try:
                token = backend_login(BASE_URL, api_key, cuit_login, password)
                st.session_state.auth = {
                    "logged": True,
                    "api_key": api_key,
                    "access_token": token,
                    "cuit": cuit_login,
                }
                st.success("Sesión iniciada.")
                st.rerun()
            except Exception as e:
                st.error(str(e))

    with colB:
        if st.button("Salir", use_container_width=True):
            st.session_state.auth = {
                "logged": False,
                "api_key": DEFAULT_BACKEND_API_KEY,
                "access_token": "",
                "cuit": "",
            }
            st.rerun()

    st.divider()

    if st.session_state.auth["logged"]:
        page = st.radio("Secciones", ["Validación", "Facturación (WSFEv1)"], horizontal=False)
    else:
        page = "Validación"


# ===================== HOME (NO LOGUEADO) =====================
if not st.session_state.auth["logged"]:
    st.info("Iniciá sesión para comenzar.")

    st.subheader("Cómo funciona")
    st.write("Seguí estos pasos para validar tus facturas:")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown("**1) Ingresá**\n\nAccedé con tu CUIT y contraseña.")
    with c2:
        st.markdown("**2) Subí tus PDF**\n\nCargá tus facturas en PDF.")
    with c3:
        st.markdown("**3) Vista previa**\n\nDetectamos CAE y vencimiento desde el PDF.")
    with c4:
        st.markdown("**4) Validación AFIP**\n\nConfirmamos contra AFIP vía WSCDC.")

    st.caption("Consejo: si subís muchos archivos, la validación se procesa automáticamente en tandas para evitar demoras.")
    st.stop()


# ===================== PÁGINA: VALIDACIÓN =====================
def render_validacion():
    st.info(
        "En una primera instancia detectamos el CAE y su vencimiento directamente desde el PDF cargado. "
        "Luego, validamos la información contra AFIP utilizando el servicio oficial WSCDC (ComprobanteConstatar)."
    )

    st.subheader("Uso del plan")

    plan_used = None
    plan_limit = None
    plan_remaining = None
    plan_blocked = False

    def _fmt_yyyy_mm_from_iso(s: str) -> str:
        s = (s or "").strip()
        if not s:
            return ""
        if len(s) >= 7 and s[4] == "-":
            return s[:7]
        return s

    try:
        usage_total = backend_usage_total(
            base_url=BASE_URL,
            api_key=st.session_state.auth["api_key"],
            access_token=st.session_state.auth["access_token"],
        )
        total_files = int(usage_total.get("files_count", 0) or 0)
        total_requests = int(usage_total.get("requests_count", 0) or 0)

        total_updated_at_raw = usage_total.get("updated_at", "") or ""
        total_updated_at = _fmt_yyyy_mm_from_iso(total_updated_at_raw)

        FRONT_PLAN_LIMIT = _parse_int_or_none(os.getenv("PLAN_LIMIT", ""))
        plan_used = total_files
        plan_limit = FRONT_PLAN_LIMIT
        if plan_limit is not None:
            plan_remaining = max(0, int(plan_limit) - int(plan_used))
            plan_blocked = plan_used >= plan_limit

        colm1, colm2, colm3 = st.columns(3)
        with colm1:
            st.metric("PDF consumidos (total)", total_files)
        with colm2:
            st.metric("Requests (total)", total_requests)
        with colm3:
            st.metric("Mes", total_updated_at or "-")

        if plan_limit is not None:
            st.caption(f"Plan: **{plan_used} / {plan_limit}** PDF usados · Restantes: **{plan_remaining}**")
            if plan_blocked:
                st.error("🚫 Llegaste al límite de tu plan. Renovalo para seguir validando.")
                st.link_button("Renovar por WhatsApp", _wa_renew_url(), use_container_width=True)

    except Exception:
        st.warning("No pudimos obtener el uso TOTAL en este momento. Probá nuevamente en unos segundos.")

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
            st.metric("PDF procesados (mes)", files_count)
        with colm2:
            st.metric("Solicitudes (mes)", requests_count)
        with colm3:
            st.metric("Mes", ym or "-")

        cbtn1, _ = st.columns([1, 3])
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
        st.warning("No pudimos obtener el resumen mensual en este momento. Probá nuevamente en unos segundos.")

    st.divider()

    st.subheader("Carga de facturas")

    help_text = "sin límite" if MAX_FILES is None else f"hasta {MAX_FILES}"
    mode = st.radio(
        "Modo de carga",
        [f"PDF ({help_text})", f"ZIP ({help_text})"],
        horizontal=True,
        key="mode_upload",
    )

    pdf_files = []

    if mode.startswith("PDF"):
        uploaded = st.file_uploader("Subí tus facturas en PDF", type=["pdf"], accept_multiple_files=True, key="uploader_pdf")
        if uploaded:
            if MAX_FILES is not None and len(uploaded) > MAX_FILES:
                st.warning(f"Subiste {len(uploaded)} PDF. Por configuración se procesarán solo los primeros {MAX_FILES}.")
                uploaded = uploaded[:MAX_FILES]
            pdf_files = [{"name": f.name, "bytes": f.getvalue()} for f in uploaded]
    else:
        zip_up = st.file_uploader("Subí 1 archivo ZIP", type=["zip"], key="uploader_zip")
        if zip_up:
            try:
                with zipfile.ZipFile(io.BytesIO(zip_up.getvalue())) as z:
                    names = [n for n in z.namelist() if n.lower().endswith(".pdf") and not n.endswith("/")]
                    if not names:
                        st.error("No encontramos PDF dentro del ZIP.")
                    else:
                        if MAX_FILES is not None and len(names) > MAX_FILES:
                            st.warning(f"El ZIP tiene {len(names)} PDF. Por configuración se procesarán solo {MAX_FILES}.")
                            names = names[:MAX_FILES]
                        pdf_files = [{"name": n.split("/")[-1], "bytes": z.read(n)} for n in names]
                        st.success(f"PDF detectados: {len(pdf_files)}")
            except zipfile.BadZipFile:
                st.error("ZIP inválido o dañado.")

    rows = []
    if pdf_files:
        today = datetime.now().date()
        progress = st.progress(0)

        for i, f in enumerate(pdf_files, start=1):
            try:
                text = extract_text_pdf_cached(f["bytes"], max_pages=5)
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

                rows.append(
                    {
                        "Archivo": f["name"],
                        "CAE": cae or "",
                        "Vto CAE": vto_date.strftime("%d/%m/%Y") if vto_date else "",
                        "Estado": " | ".join(status),
                        "AFIP": "",
                        "Detalle AFIP": "",
                    }
                )
            except Exception as e:
                rows.append(
                    {
                        "Archivo": f["name"],
                        "CAE": "",
                        "Vto CAE": "",
                        "Estado": f"Error al leer el PDF: {e}",
                        "AFIP": "",
                        "Detalle AFIP": "",
                    }
                )

            progress.progress(i / len(pdf_files))

    df = pd.DataFrame(rows) if rows else pd.DataFrame(columns=["Archivo", "CAE", "Vto CAE", "Estado", "AFIP", "Detalle AFIP"])

    st.subheader("Vista previa PDF cargados")
    st.dataframe(df, use_container_width=True)

    st.subheader("Validación contra AFIP")
    st.caption("Validamos contra AFIP y devolvemos el estado por archivo.")
    st.caption(f"Para evitar demoras, procesamos los archivos en tandas de {BATCH_SIZE} PDF (ajustable).")

    button_disabled = bool(plan_blocked)

    if st.button("Validar ahora", use_container_width=True, disabled=button_disabled, key="btn_validar"):
        if not pdf_files:
            st.error("Primero cargá PDF o un ZIP")
            st.stop()

        try:
            all_rows = []
            batches = chunk_list(pdf_files, BATCH_SIZE)

            batch_progress = st.progress(0)
            with st.spinner("Consultando AFIP..."):
                for idx, batch in enumerate(batches, start=1):
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

            if all_rows:
                df = pd.DataFrame(all_rows)
                st.success("Validación completada.")
                st.dataframe(df, use_container_width=True)
            else:
                st.warning("No pudimos obtener resultados del servidor. Probá de nuevo en unos segundos.")
        except Exception as e:
            st.error(str(e))
            if "límite de su plan" in str(e).lower() or "plan_limit_reached" in str(e).lower():
                st.link_button("Renovar por WhatsApp", _wa_renew_url(), use_container_width=True)

    if not df.empty:
        if "CAE" in df.columns:
            df["CAE"] = df["CAE"].astype(str).apply(lambda x: f"'{x}" if x and x != "nan" else "")

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


# ===================== PÁGINA: FACTURACIÓN WSFEv1 =====================
def render_facturacion():
    st.info(
        "Facturación (WSFEv1): emisión de comprobantes con CAE. "
        "Cada cliente emite con su CUIT y certificado. (El PDF lo generás vos; WSFE autoriza y devuelve CAE)."
    )

    st.subheader("1) Configurar emisor (CUIT + Certificado)")
    st.caption("Esto guarda/actualiza credenciales del cliente en el backend (tenant). Recomendado: que lo haga un admin/soporte.")

    cuit_tenant = st.text_input("CUIT emisor (11 dígitos, sin guiones)", key="ten_cuit")
    cert_b64 = st.text_area("CERT_B64 (base64 PEM o DER)", height=140, key="ten_cert")
    key_b64 = st.text_area("KEY_B64 (base64 PEM o DER)", height=140, key="ten_key")
    enabled = st.checkbox("Habilitado", value=True, key="ten_enabled")

    colx1, colx2 = st.columns(2)
    with colx1:
        if st.button("Guardar emisor", use_container_width=True, key="btn_tenant_save"):
            try:
                resp = backend_tenant_upsert(
                    base_url=BASE_URL,
                    api_key=st.session_state.auth["api_key"],
                    access_token=st.session_state.auth["access_token"],
                    cuit=cuit_tenant,
                    cert_b64=cert_b64,
                    key_b64=key_b64,
                    enabled=enabled,
                )
                st.success("Emisor guardado correctamente.")
                st.json(resp)
            except Exception as e:
                st.error(str(e))

    with colx2:
        st.caption("Tip: podés pegar el base64 entero. Si viene con saltos de línea, no pasa nada.")

    st.divider()

    st.subheader("2) Emitir comprobante (FECAESolicitar)")
    st.caption("MVP: se envían importes + receptor. Para productos/ítems, los manejás internamente (WSFEv1 trabaja por totales).")

    cuit_emit = st.text_input("CUIT emisor (tenant)", value=cuit_tenant or "", key="emit_cuit")
    pto_vta = st.number_input("Punto de venta", min_value=1, max_value=99999, value=1, step=1, key="emit_ptovta")
    cbte_tipo = st.number_input("Tipo comprobante (ej: 11=Factura C / 1=Factura A / 6=Factura B)", min_value=1, max_value=999, value=11, step=1, key="emit_tipo")
    concepto = st.selectbox(
        "Concepto",
        options=[1, 2, 3],
        index=0,
        format_func=lambda x: {1: "1 - Productos", 2: "2 - Servicios", 3: "3 - Prod y Serv"}[x],
        key="emit_conc",
    )

    colr1, colr2 = st.columns(2)
    with colr1:
        doc_tipo = st.selectbox("DocTipo receptor", options=[80, 96], index=0, format_func=lambda x: {80: "80 - CUIT", 96: "96 - DNI"}[x], key="emit_doct")
    with colr2:
        doc_nro = st.text_input("DocNro receptor (CUIT 11 / DNI 7-8)", key="emit_docn")

    cbte_fch = st.text_input("Fecha comprobante (YYYYMMDD)", value=datetime.now().strftime("%Y%m%d"), key="emit_fch")

    st.markdown("**Importes**")
    colm1, colm2, colm3 = st.columns(3)
    with colm1:
        imp_total = st.number_input("ImpTotal", min_value=0.0, value=0.0, step=1.0, key="emit_total")
    with colm2:
        imp_neto = st.number_input("ImpNeto", min_value=0.0, value=0.0, step=1.0, key="emit_neto")
    with colm3:
        imp_iva = st.number_input("ImpIVA", min_value=0.0, value=0.0, step=1.0, key="emit_iva")

    colm4, colm5, colm6 = st.columns(3)
    with colm4:
        imp_trib = st.number_input("ImpTrib", min_value=0.0, value=0.0, step=1.0, key="emit_trib")
    with colm5:
        imp_op_ex = st.number_input("ImpOpEx", min_value=0.0, value=0.0, step=1.0, key="emit_opex")
    with colm6:
        imp_tot_conc = st.number_input("ImpTotConc", min_value=0.0, value=0.0, step=1.0, key="emit_concimp")

    st.markdown("**Moneda**")
    colmo1, colmo2 = st.columns(2)
    with colmo1:
        mon_id = st.text_input("MonId", value="PES", key="emit_monid")
    with colmo2:
        mon_ctz = st.number_input("MonCotiz", min_value=0.000001, value=1.0, step=0.1, key="emit_monctz")

    st.markdown("**IVA (opcional)**")
    st.caption("Si usás Factura A/B normalmente cargás alícuotas. Si emitís C, suele ir 0.")
    use_iva = st.checkbox("Cargar alícuotas de IVA", value=False, key="emit_use_iva")

    iva_items = []
    if use_iva:
        coliv1, coliv2, coliv3 = st.columns(3)
        with coliv1:
            iva_id = st.number_input("Id alícuota (ej: 5=21%, 4=10.5%, 3=0%)", min_value=1, max_value=999, value=5, step=1, key="emit_iva_id")
        with coliv2:
            iva_base = st.number_input("BaseImp", min_value=0.0, value=0.0, step=1.0, key="emit_iva_base")
        with coliv3:
            iva_imp = st.number_input("Importe IVA", min_value=0.0, value=0.0, step=1.0, key="emit_iva_imp")

        if st.button("Agregar alícuota", use_container_width=True, key="btn_add_iva"):
            if "iva_list" not in st.session_state:
                st.session_state.iva_list = []
            st.session_state.iva_list.append({"id": int(iva_id), "base_imp": float(iva_base), "importe": float(iva_imp)})
            st.rerun()

        iva_items = st.session_state.get("iva_list", [])
        if iva_items:
            st.write("Alícuotas cargadas:")
            st.dataframe(pd.DataFrame(iva_items), use_container_width=True)
            if st.button("Limpiar IVA", use_container_width=True, key="btn_clear_iva"):
                st.session_state.iva_list = []
                st.rerun()

    st.divider()

    colb1, colb2 = st.columns(2)
    with colb1:
        if st.button("Consultar último autorizado", use_container_width=True, key="btn_last"):
            try:
                resp = backend_wsfe_last(
                    base_url=BASE_URL,
                    api_key=st.session_state.auth["api_key"],
                    access_token=st.session_state.auth["access_token"],
                    cuit=cuit_emit,
                    pto_vta=int(pto_vta),
                    cbte_tipo=int(cbte_tipo),
                )
                st.success("OK")
                st.json(resp)
            except Exception as e:
                st.error(str(e))

    with colb2:
        if st.button("Emitir (obtener CAE)", use_container_width=True, key="btn_emit"):
            try:
                payload = {
                    "cuit": str(cuit_emit).strip(),
                    "pto_vta": int(pto_vta),
                    "cbte_tipo": int(cbte_tipo),
                    "concepto": int(concepto),
                    "doc_tipo": int(doc_tipo),
                    "doc_nro": str(doc_nro).strip(),
                    "cbte_fch": str(cbte_fch).strip(),
                    "imp_total": float(imp_total),
                    "imp_tot_conc": float(imp_tot_conc),
                    "imp_neto": float(imp_neto),
                    "imp_op_ex": float(imp_op_ex),
                    "imp_trib": float(imp_trib),
                    "imp_iva": float(imp_iva),
                    "mon_id": str(mon_id).strip(),
                    "mon_ctz": float(mon_ctz),
                    "iva": iva_items or [],
                }

                resp = backend_wsfe_cae(
                    base_url=BASE_URL,
                    api_key=st.session_state.auth["api_key"],
                    access_token=st.session_state.auth["access_token"],
                    payload=payload,
                )

                st.success("Respuesta WSFE recibida.")
                st.json(resp)

                cae = (resp.get("cae") or "").strip()
                cae_vto = (resp.get("cae_vto") or "").strip()
                cbtenro = resp.get("cbte_nro")

                if cae:
                    st.metric("CAE", cae)
                if cae_vto:
                    st.metric("Vto CAE", cae_vto)
                if cbtenro is not None:
                    st.metric("Nro Comprobante", cbtenro)

                raw_json = (pd.Series(resp).to_json(orient="index", force_ascii=False)).encode("utf-8")
                st.download_button(
                    "Descargar respuesta (JSON)",
                    data=raw_json,
                    file_name="wsfe_respuesta.json",
                    mime="application/json",
                    use_container_width=True,
                )

                if cae:
                    st.divider()
                    st.subheader("Comprobante (PDF)")

                    pdf_name = (
                        f"comprobante_{str(cuit_emit).strip()}_{int(pto_vta)}_{int(cbte_tipo)}_"
                        f"{int(cbtenro) if cbtenro is not None else 'sinnro'}.pdf"
                    )

                    pdf_payload = dict(payload)
                    pdf_payload.update({
                        "cbte_nro": cbtenro,
                        "cae": cae,
                        "cae_vto": cae_vto,
                        "resultado": resp.get("resultado"),
                    })

                    colpdf1, colpdf2 = st.columns(2)
                    with colpdf1:
                        if st.button("Generar PDF", use_container_width=True, key="btn_wsfe_gen_pdf"):
                            try:
                                pdf_bytes = backend_wsfe_pdf(
                                    base_url=BASE_URL,
                                    api_key=st.session_state.auth["api_key"],
                                    access_token=st.session_state.auth["access_token"],
                                    payload=pdf_payload,
                                    timeout_s=60,
                                )
                                st.session_state.wsfe_pdf_bytes = pdf_bytes
                                st.session_state.wsfe_pdf_name = pdf_name
                                st.success("PDF generado.")
                            except Exception as e:
                                st.error(str(e))

                    with colpdf2:
                        pdf_bytes_ss = st.session_state.get("wsfe_pdf_bytes")
                        pdf_name_ss = st.session_state.get("wsfe_pdf_name") or pdf_name
                        if pdf_bytes_ss:
                            st.download_button(
                                "Descargar PDF",
                                data=pdf_bytes_ss,
                                file_name=pdf_name_ss,
                                mime="application/pdf",
                                use_container_width=True,
                                key="btn_wsfe_dl_pdf",
                            )
                        else:
                            st.caption("Primero generá el PDF para habilitar la descarga.")

                    st.subheader("Enviar al cliente")
                    to_email = st.text_input("Email destinatario", placeholder="cliente@dominio.com", key="wsfe_to_email")

                    colmail1, colmail2 = st.columns(2)
                    with colmail1:
                        if st.button("Enviar PDF por email", use_container_width=True, key="btn_wsfe_send_email"):
                            try:
                                if not (to_email or "").strip():
                                    raise RuntimeError("Ingresá un email destinatario.")
                                mail_payload = {"to_email": to_email.strip(), "pdf_payload": pdf_payload}
                                resp_mail = backend_wsfe_send_email(
                                    base_url=BASE_URL,
                                    api_key=st.session_state.auth["api_key"],
                                    access_token=st.session_state.auth["access_token"],
                                    payload=mail_payload,
                                    timeout_s=60,
                                )
                                st.success("Email enviado (backend).")
                                st.json(resp_mail)
                            except Exception as e:
                                st.error(str(e))
                    with colmail2:
                        st.caption("Requiere endpoint backend **POST /wsfe/email** + SMTP configurado en el backend.")

            except Exception as e:
                st.error(str(e))


# ===================== ROUTER =====================
if page == "Facturación (WSFEv1)":
    render_facturacion()
else:
    render_validacion()