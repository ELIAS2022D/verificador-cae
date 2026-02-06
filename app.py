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
    page_icon=icon,   # ✅ así sí se ve
    layout="wide",
)

# Header con logo + nombre
col1, col2 = st.columns([1, 2])
with col1:
    st.image("assets/favicon.png", width=600)
with col2:
    st.markdown("## LexaCAE AFIP – Validación en la nube.")
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
    # 🔥 Si el backend bloquea por plan, devolvemos un error más amigable
    if r.status_code != 200:
        # Intentar parsear JSON con code PLAN_LIMIT_REACHED
        try:
            j = r.json()
            detail = j.get("detail", j)
            if isinstance(detail, dict) and detail.get("code") == "PLAN_LIMIT_REACHED":
                used = detail.get("used")
                limit = detail.get("limit")
                msg = detail.get("message") or "Ha alcanzado el límite de su plan."
                raise RuntimeError(f"{msg} (Usadas: {used} / Límite: {limit})")
        except Exception:
            pass

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


# ✅ NUEVO: total real (bolsa) desde el backend
def backend_usage_total(base_url: str, api_key: str, access_token: str):
    headers = {"Authorization": f"Bearer {access_token}"}
    if api_key:
        headers["X-API-Key"] = api_key
    r = requests.get(f"{base_url}/usage/total", headers=headers, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Usage total falló ({r.status_code}): {r.text}")
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
    return [items[i : i + size] for i in range(0, len(items), size)]


def _wa_renew_url() -> str:
    import urllib.parse
    phone = re.sub(r"\D+", "", RENEW_WHATSAPP or "")
    if not phone:
        phone = "5491131433906"
    txt = urllib.parse.quote(RENEW_TEXT or "")
    return f"https://wa.me/{phone}?text={txt}"


# ===================== SIDEBAR: LOGIN =====================
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

# ===================== INFO GENERAL =====================
st.info(
    "Flujo: detectamos CAE/Vto desde el PDF localmente. "
    "La validación AFIP se realiza del lado servidor utilizando el servicio oficial WSCDC (ComprobanteConstatar)."
)

# ===================== PANEL: TOTAL REAL + EMAIL MENSUAL =====================
st.subheader("Uso del plan")

plan_used = None
plan_limit = None
plan_remaining = None
plan_blocked = False

def _fmt_yyyy_mm_from_iso(s: str) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    # ISO típico: 2026-02-05T20:07:49.025060+00:00  ->  2026-02
    if len(s) >= 7 and s[4] == "-":
        return s[:7]
    return s

try:
    # ✅ TOTAL REAL (bolsa)
    usage_total = backend_usage_total(
        base_url=BASE_URL,
        api_key=st.session_state.auth["api_key"],
        access_token=st.session_state.auth["access_token"],
    )
    total_files = int(usage_total.get("files_count", 0) or 0)
    total_requests = int(usage_total.get("requests_count", 0) or 0)

    total_updated_at_raw = usage_total.get("updated_at", "") or ""
    total_updated_at = _fmt_yyyy_mm_from_iso(total_updated_at_raw)

    # Límite del plan (solo para UI; el bloqueo real lo hace el backend)
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
        # ✅ queda igual que el mensual (YYYY-MM)
        st.metric("Mes", total_updated_at or "-")

    if plan_limit is not None:
        st.caption(f"Plan: **{plan_used} / {plan_limit}** PDF usados · Restantes: **{plan_remaining}**")
        if plan_blocked:
            st.error("🚫 Llegaste al límite de tu plan. Renovalo para seguir validando.")
            st.link_button("Renovar por WhatsApp", _wa_renew_url(), use_container_width=True)

except Exception:
    st.warning("No pudimos obtener el uso TOTAL en este momento. Probá nuevamente en unos segundos.")

# ✅ Mantengo tu sección de email mensual (sin tocar lógica)
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
    st.warning("No pudimos obtener el resumen mensual en este momento. Probá nuevamente en unos segundos.")

st.divider()

# ===================== CARGA ARCHIVOS =====================
st.subheader("Carga de facturas")

help_text = "sin límite" if MAX_FILES is None else f"hasta {MAX_FILES}"
mode = st.radio(
    "Modo de carga",
    [f"PDF ({help_text})", f"ZIP ({help_text})"],
    horizontal=True,
)

pdf_files = []

if mode.startswith("PDF"):
    uploaded = st.file_uploader("Subí tus facturas en PDF", type=["pdf"], accept_multiple_files=True)
    if uploaded:
        if MAX_FILES is not None and len(uploaded) > MAX_FILES:
            st.warning(f"Subiste {len(uploaded)} PDF. Por configuración se procesarán solo los primeros {MAX_FILES}.")
            uploaded = uploaded[:MAX_FILES]
        pdf_files = [{"name": f.name, "bytes": f.getvalue()} for f in uploaded]
else:
    zip_up = st.file_uploader("Subí 1 archivo ZIP", type=["zip"])
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

# ===================== VALIDACIÓN AFIP VIA BACKEND =====================
st.subheader("Validación contra AFIP")
st.caption("Validamos contra AFIP y devolvemos el estado por archivo.")
st.caption(f"Para evitar demoras, procesamos los archivos en tandas de {BATCH_SIZE} PDF (ajustable).")

# ✅ Bloqueo visual: si el front conoce el plan y está vencido, deshabilita el botón.
button_disabled = bool(plan_blocked)

if st.button("Validar ahora", use_container_width=True, disabled=button_disabled):
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
        # Si el error fue plan límite, mostrar CTA directo
        if "límite de su plan" in str(e).lower() or "plan_limit_reached" in str(e).lower():
            st.link_button("Renovar por WhatsApp", _wa_renew_url(), use_container_width=True)

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
