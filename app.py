# app.py
import os
import io
import zipfile
import re
import logging
import traceback
import base64
from datetime import datetime

import pandas as pd
import streamlit as st
import pdfplumber
import requests
from PIL import Image

# ===================== STREAMLIT: NO MOSTRAR DETALLES DE ERRORES (UI) =====================
try:
    st.set_option("client.showErrorDetails", False)
except Exception:
    pass

# ===================== LOGGING (solo servidor) =====================
logger = logging.getLogger("lexacae_front")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")

# ===================== UI HELPERS (enterprise + errores prolijos) =====================
def inject_enterprise_theme_light():
    """
    Tema claro enterprise (default white) combinando acentos tipo LexaCAE:
    - fondo blanco / gris muy claro
    - cards blancas con borde suave
    - acentos azul/cian
    """
    st.markdown(
        """
        <style>
          :root{
            --lx-bg: #f7f9fc;
            --lx-surface: rgba(255,255,255,.92);
            --lx-surface2: #ffffff;
            --lx-border: rgba(15,23,42,.12);
            --lx-text: rgba(15,23,42,.92);
            --lx-muted: rgba(15,23,42,.62);
            --lx-accent: #2563eb;
            --lx-accent2: #06b6d4;
            --lx-accent3: #4f46e5;
            --lx-shadow: 0 18px 50px rgba(15,23,42,.10);
          }

          .stApp {
            background:
              radial-gradient(1200px 600px at 15% 0%, rgba(6,182,212,.16), transparent 60%),
              radial-gradient(1000px 600px at 95% 5%, rgba(37,99,235,.14), transparent 55%),
              linear-gradient(180deg, var(--lx-bg) 0%, var(--lx-bg) 100%);
            color: var(--lx-text);
          }

          section.main > div { padding-top: 1.15rem; }
          .block-container { max-width: 1200px; }

          html, body, [class*="css"] {
            font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji","Segoe UI Emoji";
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            color: var(--lx-text);
          }

          .lex-card {
            background: var(--lx-surface);
            border: 1px solid var(--lx-border);
            border-radius: 18px;
            padding: 16px 16px;
            box-shadow: var(--lx-shadow);
            backdrop-filter: blur(8px);
          }

          .lex-muted { color: var(--lx-muted); }
          .lex-title { font-size: 1.7rem; font-weight: 780; letter-spacing: .2px; margin: 0; color: var(--lx-text); }
          .lex-sub { font-size: .98rem; color: var(--lx-muted); margin-top: 6px; }

          .lex-badge {
            display:inline-flex; gap:8px; align-items:center;
            padding: 6px 10px; border-radius: 999px;
            border: 1px solid rgba(37,99,235,.18);
            background: linear-gradient(180deg, rgba(37,99,235,.10), rgba(6,182,212,.08));
            font-size: 12px; color: rgba(15,23,42,.80);
          }

          div[data-baseweb="input"] input, div[data-baseweb="textarea"] textarea {
            background: var(--lx-surface2) !important;
            border: 1px solid rgba(15,23,42,.14) !important;
            border-radius: 12px !important;
            color: var(--lx-text) !important;
          }
          div[data-baseweb="input"] input:focus, div[data-baseweb="textarea"] textarea:focus {
            outline: none !important;
            box-shadow: 0 0 0 3px rgba(37,99,235,.18) !important;
            border-color: rgba(37,99,235,.45) !important;
          }

          .stButton > button, .stDownloadButton > button {
            border-radius: 12px !important;
            border: 1px solid rgba(37,99,235,.20) !important;
            background: linear-gradient(180deg, rgba(37,99,235,.10), rgba(6,182,212,.08)) !important;
            color: rgba(15,23,42,.92) !important;
            box-shadow: 0 12px 26px rgba(15,23,42,.10) !important;
            transition: transform .12s ease, box-shadow .12s ease, filter .12s ease;
          }
          .stButton > button:hover, .stDownloadButton > button:hover {
            transform: translateY(-1px);
            box-shadow: 0 16px 34px rgba(15,23,42,.14) !important;
            filter: brightness(1.03);
          }

          .stLinkButton > a {
            border-radius: 12px !important;
            border: 1px solid rgba(37,99,235,.20) !important;
            background: linear-gradient(180deg, rgba(37,99,235,.10), rgba(6,182,212,.08)) !important;
            color: rgba(15,23,42,.92) !important;
            box-shadow: 0 12px 26px rgba(15,23,42,.10) !important;
            transition: transform .12s ease, box-shadow .12s ease, filter .12s ease;
            text-decoration: none !important;
          }
          .stLinkButton > a:hover {
            transform: translateY(-1px);
            box-shadow: 0 16px 34px rgba(15,23,42,.14) !important;
            filter: brightness(1.03);
          }

          .stDataFrame { border-radius: 14px; overflow: hidden; border: 1px solid rgba(15,23,42,.10); }

          @keyframes fadeUp { from { opacity: 0; transform: translateY(6px);} to { opacity: 1; transform: translateY(0);} }
          .lex-anim { animation: fadeUp .28s ease both; }

          section[data-testid="stSidebar"] {
            background: rgba(255,255,255,.82);
            border-right: 1px solid rgba(15,23,42,.10);
          }
          section[data-testid="stSidebar"] * { color: rgba(15,23,42,.92); }
        </style>
        """,
        unsafe_allow_html=True,
    )

def lex_card_open(extra_class=""):
    st.markdown(f'<div class="lex-card lex-anim {extra_class}">', unsafe_allow_html=True)

def lex_card_close():
    st.markdown("</div>", unsafe_allow_html=True)

def safe_call(user_msg: str, fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        logger.error("%s | %s\n%s", user_msg, str(e), traceback.format_exc())
        st.error(user_msg)
        st.caption(f"Detalle: {(str(e) or '')[:240]}")
        return None

def toast_ok(msg: str):
    try:
        st.toast(msg, icon="✅")
    except Exception:
        st.success(msg)

def toast_warn(msg: str):
    try:
        st.toast(msg, icon="⚠️")
    except Exception:
        st.warning(msg)

def toast_err(msg: str):
    try:
        st.toast(msg, icon="❌")
    except Exception:
        st.error(msg)

# ===================== TOP NAV TICKER (GLOBAL) =====================
def ensure_ticker_state():
    if "top_ticker" not in st.session_state:
        st.session_state.top_ticker = {
            "text": "",      # ✅ vacío por defecto (solo mostramos estado de cuenta)
            "tone": "info",  # info | warn | danger
        }

ensure_ticker_state()

def set_top_ticker(text: str, tone: str = "info"):
    st.session_state.top_ticker = {
        "text": (text or "").strip(),
        "tone": (tone or "info").strip().lower(),
    }

# ✅ placeholder para re-render del ticker dentro del mismo run
_TICKER_SLOT = None

def render_top_ticker():
    global _TICKER_SLOT
    data = st.session_state.get("top_ticker") or {}
    text = (data.get("text") or "").strip()
    tone = (data.get("tone") or "info").strip().lower()

    # ✅ si no hay texto, no renderiza (no aparece “LexaCAE...” por default)
    if not text:
        return

    tone_border = {
        "info": "rgba(37,99,235,.22)",
        "warn": "rgba(245,158,11,.26)",
        "danger": "rgba(239,68,68,.28)",
    }.get(tone, "rgba(37,99,235,.22)")

    tone_bg = {
        "info": "linear-gradient(180deg, rgba(255,255,255,.72), rgba(255,255,255,.52))",
        "warn": "linear-gradient(180deg, rgba(255,247,237,.75), rgba(255,255,255,.50))",
        "danger": "linear-gradient(180deg, rgba(254,242,242,.78), rgba(255,255,255,.50))",
    }.get(tone, "linear-gradient(180deg, rgba(255,255,255,.72), rgba(255,255,255,.52))")

    safe_text = (
        (text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )

    html = f"""
    <style>
      /* ✅ ancho "de la página" (igual al block-container) */
      :root {{
        --lx-page-width: 1200px;       /* <- cambiá esto si tocás tu max-width */
        --lx-page-pad-x: 0px;          /* opcional si querés sumar un poquito */
        --lx-gutter-left: 72px;        /* para no tapar ⋮ / sidebar toggle */
        --lx-topbar-pad-y: 14px;       /* ✅ más alto */
      }}

      /* Reservar espacio arriba para que no tape el contenido */
      section.main > div {{ padding-top: 4.75rem !important; }}

      .lx-topbar {{
        position: fixed;
        top: 0;
        left: 50%;
        transform: translateX(-50%);
        width: calc(var(--lx-page-width) + var(--lx-page-pad-x));
        z-index: 999999;

        pointer-events: none;
        background: transparent !important;
        box-shadow: none !important;
        border: none !important;

        opacity: 1;
        transition: transform .22s ease, opacity .22s ease;
        will-change: transform, opacity;
      }}

      .lx-topbar.lx-hidden {{
        transform: translateX(-50%) translateY(-110%);
        opacity: 0;
        pointer-events: none;
      }}

      .lx-topbar::before {{
        content: "";
        position: absolute;
        top: 0;
        right: 0;
        bottom: 0;
        left: 0;
        margin-left: var(--lx-gutter-left);

        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        background: {tone_bg};
        border-bottom: 1px solid {tone_border};
        box-shadow: 0 12px 28px rgba(15,23,42,.10);
        border-radius: 0 0 14px 14px;
      }}

      .lx-topbar-inner {{
        position: relative;
        width: 100%;
        margin: 0 auto;
        padding: var(--lx-topbar-pad-y) 16px;
        padding-left: calc(16px + var(--lx-gutter-left));
        display: flex;
        align-items: center;
        gap: 12px;

        pointer-events: auto;
      }}

      .lx-topbar-dot {{
        width: 9px; height: 9px; border-radius: 999px;
        background: rgba(37,99,235,.90);
        box-shadow: 0 0 0 6px rgba(37,99,235,.12);
        flex: 0 0 auto;
      }}

      .lx-marquee {{
        position: relative;
        overflow: hidden;
        white-space: nowrap;
        flex: 1 1 auto;
      }}

      .lx-track {{
        display: inline-flex;
        gap: 24px;
        align-items: center;
        will-change: transform;
        animation: lx-scroll 22s linear infinite;
      }}

      .lx-item {{
        font-size: 13px;
        font-weight: 750;
        letter-spacing: .2px;
        color: rgba(15,23,42,.86);
      }}
      .lx-item b {{
        font-weight: 800;
        color: rgba(15,23,42,.92);
      }}

      @keyframes lx-scroll {{
        0%   {{ transform: translateX(0); }}
        100% {{ transform: translateX(-50%); }}
      }}

      .lx-topbar:hover .lx-track {{ animation-play-state: paused; }}

      @media (max-width: 1280px) {{
        :root {{ --lx-page-width: 100%; }}
        .lx-topbar {{
          width: 100%;
          left: 0;
          transform: none;
        }}
        .lx-topbar.lx-hidden {{
          transform: translateY(-110%);
        }}
      }}

      @media (max-width: 720px) {{
        :root {{
        --lx-gutter-left: 64px;
        --lx-topbar-pad-y: 13px;
        }}
        .lx-item {{ font-size: 12px; }}

        /* ✅ ocultar ticker en mobile */
        .lx-topbar {{ display: none !important; }}

        /* ✅ como no hay ticker, no reservamos espacio arriba */
        section.main > div {{ padding-top: 1.15rem !important; }}
        }}
    </style>

    <div id="lxTopbar" class="lx-topbar">
      <div class="lx-topbar-inner">
        <div class="lx-topbar-dot"></div>
        <div class="lx-marquee" aria-label="LexaCAE ticker">
          <div class="lx-track">
            <div class="lx-item">{safe_text}</div>
            <div class="lx-item">{safe_text}</div>
          </div>
        </div>
      </div>
    </div>

    <script>
    (function() {{
      const TOP_THRESHOLD = 8;
      const BAR_ID = "lxTopbar";

      function getScrollTop(doc) {{
        try {{
          return (doc.documentElement && doc.documentElement.scrollTop) || doc.body.scrollTop || 0;
        }} catch(e) {{
          return 0;
        }}
      }}

      function setHidden(hidden) {{
        try {{
          const bar = window.parent.document.getElementById(BAR_ID) || document.getElementById(BAR_ID);
          if (!bar) return;
          if (hidden) bar.classList.add("lx-hidden");
          else bar.classList.remove("lx-hidden");
        }} catch(e) {{}}
      }}

      function onScroll() {{
        let st = 0;
        try {{
          st = getScrollTop(window.parent.document);
        }} catch(e) {{
          st = getScrollTop(document);
        }}
        setHidden(st > TOP_THRESHOLD);
      }}

      try {{ window.parent.addEventListener("scroll", onScroll, {{ passive: true }}); }} catch(e) {{}}
      try {{ window.addEventListener("scroll", onScroll, {{ passive: true }}); }} catch(e) {{}}

      try {{
        const obs = new MutationObserver(() => onScroll());
        obs.observe(window.parent.document.body, {{ childList: true, subtree: true }});
      }} catch(e) {{}}

      setTimeout(onScroll, 50);
    }})();
    </script>
    """

    # ✅ render dentro del slot (para poder actualizar durante el mismo run)
    if _TICKER_SLOT is None:
        st.markdown(html, unsafe_allow_html=True)
    else:
        _TICKER_SLOT.markdown(html, unsafe_allow_html=True)

def set_ticker_and_refresh(text: str, tone: str = "info"):
    """Setea ticker y lo re-renderiza en el mismo run (sin depender de rerun)."""
    set_top_ticker(text, tone=tone)
    render_top_ticker()

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

# ===================== TRUST CARD (ANTES DE CARGA) =====================
AFIP_WSCDC_MANUAL_URL = "https://www.afip.gob.ar/ws/WSCDCV1/ManualDelDesarrolladorWSCDCV1.pdf"
AFIP_CAE_PUBLIC_URL = "https://servicioscf.afip.gob.ar/publico/comprobantes/cae.aspx"

def render_trust_wscdc_section():
    """
    Sección enterprise para reforzar confianza:
    - Explica que la validación final depende de AFIP (WSCDC)
    - Link a manual oficial WSCDC
    - Link a consulta pública CAE (AFIP)
    """
    lex_card_open()
    st.markdown(
        f"""
        <div class="lex-badge">🔒 Validación oficial • WSCDC (AFIP) • Trazabilidad</div>
        <p class="lex-title" style="margin-top:10px; font-size:1.35rem;">
          Verificación con fuente oficial (AFIP)
        </p>
        <p class="lex-sub" style="margin-top:6px;">
          Para que tengas tranquilidad: LexaCAE contrasta la información del comprobante contra
          <b>AFIP</b> usando el Web Service <b>WSCDC (ComprobanteConstatar)</b>.
          Acá tenés la guía oficial para auditar el proceso y entender qué se valida.
        </p>

        <div style="display:grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap:10px; margin-top:12px;">
          <div style="border:1px solid rgba(15,23,42,.10); border-radius:14px; padding:12px; background:rgba(255,255,255,.75);">
            <div style="font-weight:750;">🧾 Qué validamos</div>
            <div class="lex-muted" style="font-size:.92rem; margin-top:6px;">
              CAE, emisor/receptor, tipo y nro de comprobante, fecha y consistencia general (según respuesta WSCDC).
            </div>
          </div>

          <div style="border:1px solid rgba(15,23,42,.10); border-radius:14px; padding:12px; background:rgba(255,255,255,.75);">
            <div style="font-weight:750;">🛡️ Confiabilidad</div>
            <div class="lex-muted" style="font-size:.92rem; margin-top:6px;">
              La respuesta final se apoya en servicios oficiales. Si AFIP responde “Observado/Rechazado”, lo ves reflejado.
            </div>
          </div>

          <div style="border:1px solid rgba(15,23,42,.10); border-radius:14px; padding:12px; background:rgba(255,255,255,.75);">
            <div style="font-weight:750;">🔐 Privacidad</div>
            <div class="lex-muted" style="font-size:.92rem; margin-top:6px;">
              Primero hacemos lectura local del PDF (CAE/Vto). Luego consultamos AFIP para confirmar estado y autorización.
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2, c3 = st.columns([1.2, 1.2, 2.6])
    with c1:
        st.link_button("📘 Guía oficial WSCDC (AFIP)", AFIP_WSCDC_MANUAL_URL, use_container_width=True)
    with c2:
        st.link_button("🔎 Consulta pública CAE (AFIP)", AFIP_CAE_PUBLIC_URL, use_container_width=True)
    with c3:
        st.caption("Tip: abrí el manual y buscá “ComprobanteConstatar” para ver contrato, campos y códigos de error.")
    lex_card_close()

# ===================== BRANDING + CONFIG =====================
icon = Image.open("assets/logo_Sitio.png")

st.set_page_config(
    page_title="LexaCAE | Verificador CAE",
    page_icon=icon,
    layout="wide",
)

inject_enterprise_theme_light()

# ✅ slot fijo para que el ticker pueda actualizarse dentro del mismo run
_TICKER_SLOT = st.empty()
render_top_ticker()  # si está vacío, no imprime nada

# ===================== HERO / HEADER =====================
col1, col2 = st.columns([1, 2], vertical_alignment="center")
with col1:
    st.image("assets/favicon.png", width=260)
with col2:
    lex_card_open()
    st.markdown(
        """
        <div class="lex-badge">🛡️ Compliance • AFIP WSCDC • Auditoría</div>
        <p class="lex-title" style="margin-top:10px;">LexaCAE — Verificador CAE</p>
        <p class="lex-sub">Validación en la nube, con verificación oficial contra AFIP. Flujo simple, resultados exportables y control de plan.</p>
        """,
        unsafe_allow_html=True,
    )
    lex_card_close()

st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
block_enter_on_password_inputs()

# ===================== CONFIG APP =====================
st.title("Verificador de CAE")

BASE_URL = os.getenv("BASE_URL", "").strip()
DEFAULT_BACKEND_API_KEY = os.getenv("BACKEND_API_KEY", "").strip()
LOGIN_CUIT_DEFAULT = os.getenv("LOGIN_CUIT_DEFAULT", "").strip()

MAX_FILES_RAW = os.getenv("MAX_FILES", None)
BATCH_SIZE_RAW = os.getenv("BATCH_SIZE", "50")

RENEW_WHATSAPP = (os.getenv("RENEW_WHATSAPP", "5491131433906") or "").strip()
RENEW_TEXT = (os.getenv("RENEW_TEXT", "Hola! Quiero renovar mi plan de LexaCAE. ¿Me ayudan?") or "").strip()

# ===================== WHATSAPP FLOTANTE (GLOBAL) =====================
def inject_whatsapp_floating_button(phone: str, default_text: str, bubble_text: str = "Soporte técnico"):
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
            box-shadow: 0 12px 28px rgba(0,0,0,.18);
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
            box-shadow: 0 14px 32px rgba(0,0,0,.18);
            border: 1px solid rgba(255,255,255,.25);
            transition: transform .15s ease, box-shadow .15s ease;
          }}
          .wa-btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 18px 36px rgba(0,0,0,.22);
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

def ensure_wsfe_items_state():
    if "wsfe_items_df" not in st.session_state:
        st.session_state.wsfe_items_df = pd.DataFrame(
            columns=["Descripción", "Cantidad", "Precio Unit.", "Subtotal"]
        )

ensure_wsfe_items_state()

def ensure_wsfe_secrets_state():
    if "wsfe_secrets" not in st.session_state:
        st.session_state.wsfe_secrets = {
            "cert_b64": "",
            "key_b64": "",
            "show_cert": False,
            "show_key": False,
            "cert_loaded": False,
            "key_loaded": False,
            "cert_source": "",
            "key_source": "",
            "cert_len": 0,
            "key_len": 0,
            "cert_file_sig": "",
            "key_file_sig": "",
        }

ensure_wsfe_secrets_state()

def ensure_results_state():
    if "df_results" not in st.session_state:
        st.session_state.df_results = pd.DataFrame(
            columns=["Archivo", "CAE", "Vto CAE", "Estado", "AFIP", "Detalle AFIP"]
        )

ensure_results_state()

def _clean_b64(s: str) -> str:
    return re.sub(r"\s+", "", (s or "").strip())

def _mask_b64(s: str, keep: int = 6) -> str:
    s = _clean_b64(s)
    if not s:
        return ""
    if len(s) <= keep * 2:
        return "•" * len(s)
    return f"{s[:keep]}{'•' * 14}{s[-keep:]}"

def _load_file_to_b64(uploaded_file) -> str:
    if not uploaded_file:
        return ""
    raw = uploaded_file.getvalue()
    try:
        txt = raw.decode("utf-8", errors="ignore").strip()
        if len(txt) > 80 and re.fullmatch(r"[A-Za-z0-9+/=\s\r\n]+", txt):
            return _clean_b64(txt)
    except Exception:
        pass
    return base64.b64encode(raw).decode("utf-8")

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

def _auth_headers(api_key: str, access_token: str) -> dict:
    h = {"Authorization": f"Bearer {access_token}"}
    if api_key:
        h["X-API-Key"] = api_key
    return h

def backend_me_get(base_url: str, api_key: str, access_token: str) -> dict:
    r = requests.get(f"{base_url}/me", headers=_auth_headers(api_key, access_token), timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Perfil falló ({r.status_code}): {r.text}")
    return r.json()

def backend_me_update(base_url: str, api_key: str, access_token: str, payload: dict) -> dict:
    r = requests.put(f"{base_url}/me", headers=_auth_headers(api_key, access_token), json=payload, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Actualizar perfil falló ({r.status_code}): {r.text}")
    return r.json()

def backend_change_password(base_url: str, api_key: str, access_token: str, payload: dict) -> dict:
    r = requests.post(f"{base_url}/me/change-password", headers=_auth_headers(api_key, access_token), json=payload, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Cambiar contraseña falló ({r.status_code}): {r.text}")
    return r.json()

def backend_verify(base_url: str, api_key: str, access_token: str, pdf_items: list, timeout_s: int = 180):
    headers = _auth_headers(api_key, access_token)
    files = [("files", (it["name"], it["bytes"], "application/pdf")) for it in pdf_items]

    r = requests.post(
        f"{base_url}/verify",
        headers=headers,
        files=files,
        timeout=timeout_s,
    )
    if r.status_code != 200:
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
    r = requests.get(f"{base_url}/usage/current", headers=_auth_headers(api_key, access_token), timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Usage falló ({r.status_code}): {r.text}")
    return r.json()

def backend_usage_total(base_url: str, api_key: str, access_token: str):
    r = requests.get(f"{base_url}/usage/total", headers=_auth_headers(api_key, access_token), timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Usage total falló ({r.status_code}): {r.text}")
    return r.json()

def backend_send_usage_email(base_url: str, api_key: str, access_token: str):
    r = requests.post(f"{base_url}/usage/email", headers=_auth_headers(api_key, access_token), timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f"Enviar email falló ({r.status_code}): {r.text}")
    return r.json()

# ===================== WSFEv1 (FRONT CALLS) =====================
def backend_tenant_upsert(base_url: str, api_key: str, access_token: str, cuit: str, cert_b64: str, key_b64: str, enabled: bool = True):
    payload = {"cuit": cuit, "cert_b64": cert_b64, "key_b64": key_b64, "enabled": bool(enabled)}
    r = requests.post(f"{base_url}/tenants/upsert", headers=_auth_headers(api_key, access_token), json=payload, timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f"Tenant upsert falló ({r.status_code}): {r.text}")
    return r.json()

def backend_wsfe_last(base_url: str, api_key: str, access_token: str, cuit: str, pto_vta: int, cbte_tipo: int):
    payload = {"cuit": cuit, "pto_vta": int(pto_vta), "cbte_tipo": int(cbte_tipo)}
    r = requests.post(f"{base_url}/wsfe/last", headers=_auth_headers(api_key, access_token), json=payload, timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f"WSFE last falló ({r.status_code}): {r.text}")
    return r.json()

def backend_wsfe_cae(base_url: str, api_key: str, access_token: str, payload: dict):
    r = requests.post(f"{base_url}/wsfe/cae", headers=_auth_headers(api_key, access_token), json=payload, timeout=90)
    if r.status_code != 200:
        raise RuntimeError(f"WSFE CAE falló ({r.status_code}): {r.text}")
    return r.json()

def backend_wsfe_pdf(base_url: str, api_key: str, access_token: str, payload: dict, timeout_s: int = 60) -> bytes:
    r = requests.post(f"{base_url}/wsfe/pdf", headers=_auth_headers(api_key, access_token), json=payload, timeout=timeout_s)
    if r.status_code != 200:
        raise RuntimeError(f"WSFE PDF falló ({r.status_code}): {r.text}")
    return r.content

def backend_wsfe_send_email(base_url: str, api_key: str, access_token: str, payload: dict, timeout_s: int = 60) -> dict:
    r = requests.post(f"{base_url}/wsfe/email", headers=_auth_headers(api_key, access_token), json=payload, timeout=timeout_s)
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

# ===================== KPI / FILTER HELPERS (VALIDACIÓN) =====================
def _as_str(x) -> str:
    try:
        if x is None:
            return ""
        if isinstance(x, float) and pd.isna(x):
            return ""
        return str(x)
    except Exception:
        return ""

def _infer_afip_bucket(row: dict) -> str:
    afip = _as_str(row.get("AFIP", "")).strip()
    det = _as_str(row.get("Detalle AFIP", "")).strip()
    estado = _as_str(row.get("Estado", "")).strip()
    blob = f"{afip} {det} {estado}".lower()

    if any(k in blob for k in ["rechaz", "rejected", "error", "inval", "no autorizado"]):
        return "RECHAZADA"
    if "observ" in blob:
        return "OBSERVADA"
    if any(k in blob for k in ["ok", "aprob", "autoriz", "valid", "aprobada", "autorizada"]):
        return "OK"
    if afip:
        if afip.upper() in ["A", "APROBADO", "APROBADA", "AUTORIZADO", "AUTORIZADA"]:
            return "OK"
        if afip.upper() in ["O", "OBS", "OBSERVADO", "OBSERVADA"]:
            return "OBSERVADA"
        if afip.upper() in ["R", "RECHAZADO", "RECHAZADA"]:
            return "RECHAZADA"
    return "SIN_DATOS"

def _render_exec_summary(df: pd.DataFrame):
    if df is None or df.empty:
        return

    work = df.copy()
    for col in ["Archivo", "CAE", "Estado", "AFIP", "Detalle AFIP"]:
        if col not in work.columns:
            work[col] = ""

    buckets = work.apply(lambda r: _infer_afip_bucket(r.to_dict()), axis=1)
    work["_bucket"] = buckets

    total = int(len(work))
    ok = int((work["_bucket"] == "OK").sum())
    obs = int((work["_bucket"] == "OBSERVADA").sum())
    rej = int((work["_bucket"] == "RECHAZADA").sum())
    other = total - ok - obs - rej

    ok_pct = int(round((ok / total) * 100)) if total else 0
    obs_pct = int(round((obs / total) * 100)) if total else 0
    rej_pct = int(round((rej / total) * 100)) if total else 0

    lex_card_open()
    st.markdown(
        """
        <div class="lex-badge">📊 Resumen ejecutivo • KPIs</div>
        <p class="lex-title" style="margin-top:10px; font-size:1.25rem;">Estado general de validación</p>
        """,
        unsafe_allow_html=True,
    )

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("% OK", f"{ok_pct}%")
        st.caption(f"{ok} de {total}")
    with c2:
        st.metric("% Observadas", f"{obs_pct}%")
        st.caption(f"{obs} de {total}")
    with c3:
        st.metric("% Rechazadas", f"{rej_pct}%")
        st.caption(f"{rej} de {total}")
    with c4:
        st.metric("Total", f"{total}")
        st.caption(f"Sin clasificar: {other}")

    ratio_ok = min(1.0, max(0.0, (ok / total) if total else 0.0))
    st.caption("Progreso de OK (sobre total):")
    st.progress(ratio_ok)

    lex_card_close()

def _apply_filters(df: pd.DataFrame, q: str, buckets: list):
    if df is None:
        return df

    work = df.copy()

    for col in ["Archivo", "CAE", "Vto CAE", "Estado", "AFIP", "Detalle AFIP"]:
        if col not in work.columns:
            work[col] = ""

    work["_bucket"] = work.apply(lambda r: _infer_afip_bucket(r.to_dict()), axis=1)

    if buckets:
        work = work[work["_bucket"].isin(buckets)].copy()

    q = (q or "").strip().lower()
    if q:
        cols = ["Archivo", "CAE", "Estado", "AFIP", "Detalle AFIP"]
        mask = None
        for c in cols:
            s = work[c].astype(str).fillna("").str.lower()
            m = s.str.contains(re.escape(q), regex=True)
            mask = m if mask is None else (mask | m)
        work = work[mask].copy()

    if "_bucket" in work.columns:
        work = work.drop(columns=["_bucket"], errors="ignore")

    return work

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
            with st.spinner("Verificando credenciales..."):
                token = safe_call(
                    "No pudimos iniciar sesión. Revisá CUIT/contraseña e intentá de nuevo.",
                    backend_login,
                    BASE_URL, api_key, cuit_login, password
                )
            if token:
                st.session_state.auth = {
                    "logged": True,
                    "api_key": api_key,
                    "access_token": token,
                    "cuit": cuit_login,
                }
                toast_ok("Sesión iniciada.")
                st.rerun()

    with colB:
        if st.button("Salir", use_container_width=True):
            st.session_state.auth = {
                "logged": False,
                "api_key": DEFAULT_BACKEND_API_KEY,
                "access_token": "",
                "cuit": "",
            }
            toast_warn("Sesión cerrada.")
            st.rerun()

    st.divider()

    if st.session_state.auth["logged"]:
        page = st.radio("Secciones", ["Validación", "Facturación (WSFEv1)", "Perfil"], horizontal=False)
    else:
        page = "Validación"

    st.divider()
    compact = st.toggle("Modo compacto", value=True)
    if compact:
        st.markdown(
            "<style>section.main .block-container{padding-top:.8rem;} .stDataFrame{font-size: 0.92rem;}</style>",
            unsafe_allow_html=True
        )

# ===================== HOME (NO LOGUEADO) =====================
if not st.session_state.auth["logged"]:
    set_ticker_and_refresh("", "info")  # ✅ sin ticker si no está logueado
    lex_card_open()
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
    lex_card_close()
    st.stop()

# ===================== PERFIL =====================
def render_perfil():
    set_ticker_and_refresh("", "info")  # ✅ no ticker en perfil

    st.subheader("Mi perfil")
    st.caption("Acá podés ver y actualizar tus datos. Los cambios se guardan en el sistema.")

    me = safe_call(
        "No pudimos cargar tu perfil ahora mismo. Probá de nuevo en unos segundos.",
        backend_me_get,
        BASE_URL, st.session_state.auth["api_key"], st.session_state.auth["access_token"]
    )
    if not me:
        return

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("CUIT", me.get("cuit", st.session_state.auth.get("cuit", "")))
    with c2:
        st.metric("Rol", me.get("role", "user"))
    with c3:
        st.metric("Creado", (me.get("created_at", "") or "")[:10] or "-")
    with c4:
        st.metric("Actualizado", (me.get("updated_at", "") or "")[:10] or "-")

    st.divider()

    st.markdown("### Datos de contacto")
    with st.form("form_profile", clear_on_submit=False):
        full_name = st.text_input("Nombre y apellido", value=me.get("full_name", "") or "", placeholder="Ej: Elías Derrico")
        company = st.text_input("Empresa / Estudio", value=me.get("company", "") or "", placeholder="Ej: Estudio Contable X")
        email = st.text_input("Email", value=me.get("email", "") or "", placeholder="Ej: contacto@dominio.com")
        phone = st.text_input("Teléfono", value=me.get("phone", "") or "", placeholder="Ej: 11 1234 5678")

        colx1, colx2 = st.columns([1, 2])
        with colx1:
            save = st.form_submit_button("Guardar cambios", use_container_width=True)
        with colx2:
            st.caption("Tip: si el email está vacío, no se pueden enviar reportes por correo (según tu backend).")

        if save:
            with st.spinner("Guardando cambios..."):
                updated = safe_call(
                    "No pudimos actualizar tu perfil. Probá nuevamente.",
                    backend_me_update,
                    BASE_URL, st.session_state.auth["api_key"], st.session_state.auth["access_token"],
                    {
                        "full_name": full_name,
                        "company": company,
                        "email": email,
                        "phone": phone,
                    },
                )
            if updated:
                toast_ok("Listo. Datos actualizados.")
                st.rerun()

    st.divider()

    st.markdown("### Seguridad")
    with st.form("form_pass", clear_on_submit=True):
        current_password = st.text_input("Contraseña actual", type="password")
        new_password = st.text_input("Nueva contraseña (mín. 6)", type="password")
        new_password2 = st.text_input("Repetir nueva contraseña", type="password")

        ch = st.form_submit_button("Cambiar contraseña", use_container_width=True)
        if ch:
            try:
                if new_password != new_password2:
                    raise RuntimeError("Las contraseñas nuevas no coinciden.")
                with st.spinner("Actualizando contraseña..."):
                    ok = safe_call(
                        "No pudimos cambiar la contraseña. Revisá los datos e intentá de nuevo.",
                        backend_change_password,
                        BASE_URL, st.session_state.auth["api_key"], st.session_state.auth["access_token"],
                        {"current_password": current_password, "new_password": new_password},
                    )
                if ok is not None:
                    toast_ok("Contraseña actualizada.")
            except Exception as e:
                toast_err("No pudimos cambiar la contraseña.")
                st.caption(f"Detalle: {(str(e) or '')[:240]}")

# ===================== PÁGINA: VALIDACIÓN =====================
def render_validacion():
    lex_card_open()
    st.info(
        "En una primera instancia detectamos el CAE y su vencimiento directamente desde el PDF cargado. "
        "Luego, validamos la información contra AFIP utilizando el servicio oficial WSCDC (ComprobanteConstatar)."
    )
    lex_card_close()

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

    usage_total = safe_call(
        "No pudimos obtener el uso TOTAL en este momento. Probá nuevamente en unos segundos.",
        backend_usage_total,
        BASE_URL, st.session_state.auth["api_key"], st.session_state.auth["access_token"]
    )

    if usage_total:
        total_files = int(usage_total.get("files_count", 0) or 0)
        total_requests = int(usage_total.get("requests_count", 0) or 0)
        total_updated_at_raw = usage_total.get("updated_at", "") or ""
        total_updated_at = _fmt_yyyy_mm_from_iso(total_updated_at_raw)

        # ✅ plan_limit por env (default 30 si no está seteada)
        FRONT_PLAN_LIMIT = _parse_int_or_none(os.getenv("PLAN_LIMIT", "30"))
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

        # ✅ TICKER = SOLO estado de cuenta (en vivo)
        if plan_limit and plan_limit > 0:
            ratio = min(1.0, max(0.0, float(plan_used) / float(plan_limit)))
            pct = int(ratio * 100)

            # ✅ umbrales ajustables por env
            # - a 20/30 (66%) con default WARN_AT=0.60 ya entra en precaución
            WARN_AT = float(os.getenv("PLAN_WARN_AT", "0.60"))
            DANGER_AT = float(os.getenv("PLAN_DANGER_AT", "0.90"))

            if ratio >= 1.0 or ratio >= DANGER_AT:
                tone = "danger" if ratio >= 1.0 else "warn"
            else:
                tone = "warn" if ratio >= WARN_AT else "info"

            if ratio >= 1.0:
                prefix = "🚫 Plan agotado"
            elif ratio >= WARN_AT:
                prefix = "⚠️ Plan en uso"
            else:
                prefix = "✅ Plan OK"

            set_ticker_and_refresh(
                f"{prefix} — {plan_used}/{plan_limit} usados • {plan_remaining} restantes ({pct}%)",
                tone=tone
            )
        else:
            set_ticker_and_refresh(f"📌 Consumo — {plan_used} PDF usados", tone="info")

        if plan_limit is not None:
            st.caption(f"Plan: **{plan_used} / {plan_limit}** PDF usados · Restantes: **{plan_remaining}**")

            if plan_limit and plan_limit > 0:
                ratio = min(1.0, max(0.0, float(plan_used) / float(plan_limit)))
                st.progress(ratio)

                if ratio >= 1.0:
                    st.error("🚫 Plan agotado. Renovalo para seguir validando.")
                elif ratio >= float(os.getenv("PLAN_WARN_AT", "0.60")):
                    st.warning("⚠️ Ojo: estás consumiendo una buena parte del plan. Recomendado renovar antes del límite.")
                else:
                    st.caption(f"Consumo: **{plan_used}** / **{plan_limit}** ({int(ratio * 100)}%)")

            if plan_blocked:
                st.link_button("Renovar por WhatsApp", _wa_renew_url(), use_container_width=True)

    st.subheader("Resumen de uso del mes")

    usage = safe_call(
        "No pudimos obtener el resumen mensual en este momento. Probá nuevamente en unos segundos.",
        backend_usage_current,
        BASE_URL, st.session_state.auth["api_key"], st.session_state.auth["access_token"]
    )

    if usage:
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
                with st.spinner("Enviando email..."):
                    ok = safe_call(
                        "No pudimos enviar el email de resumen. Verificá que tu perfil tenga email cargado.",
                        backend_send_usage_email,
                        BASE_URL, st.session_state.auth["api_key"], st.session_state.auth["access_token"]
                    )
                if ok is not None:
                    toast_ok("Email enviado correctamente.")

    st.divider()

    render_trust_wscdc_section()

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
                toast_warn(f"Subiste {len(uploaded)} PDF. Se procesarán solo los primeros {MAX_FILES}.")
                uploaded = uploaded[:MAX_FILES]
            pdf_files = [{"name": f.name, "bytes": f.getvalue()} for f in uploaded]
    else:
        zip_up = st.file_uploader("Subí 1 archivo ZIP", type=["zip"], key="uploader_zip")
        if zip_up:
            try:
                with zipfile.ZipFile(io.BytesIO(zip_up.getvalue())) as z:
                    names = [n for n in z.namelist() if n.lower().endswith(".pdf") and not n.endswith("/")]
                    if not names:
                        toast_err("No encontramos PDF dentro del ZIP.")
                    else:
                        if MAX_FILES is not None and len(names) > MAX_FILES:
                            toast_warn(f"El ZIP tiene {len(names)} PDF. Se procesarán solo {MAX_FILES}.")
                            names = names[:MAX_FILES]
                        pdf_files = [{"name": n.split("/")[-1], "bytes": z.read(n)} for n in names]
                        toast_ok(f"PDF detectados: {len(pdf_files)}")
            except zipfile.BadZipFile:
                toast_err("ZIP inválido o dañado.")

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

    df_preview = pd.DataFrame(rows) if rows else pd.DataFrame(columns=["Archivo", "CAE", "Vto CAE", "Estado", "AFIP", "Detalle AFIP"])

    if pdf_files:
        st.session_state.df_results = df_preview

    st.subheader("Vista previa PDF cargados")
    st.dataframe(df_preview, use_container_width=True)

    st.subheader("Validación contra AFIP")
    st.caption("Validamos contra AFIP y devolvemos el estado por archivo.")
    st.caption(f"Para evitar demoras, procesamos los archivos en tandas de {BATCH_SIZE} PDF (ajustable).")

    button_disabled = False

    if st.button("Validar ahora", use_container_width=True, disabled=button_disabled, key="btn_validar"):
        if not pdf_files:
            toast_err("Primero cargá PDF o un ZIP.")
            st.stop()

        with st.status("Consultando AFIP (WSCDC)...", expanded=True) as status:
            all_rows = []
            batches = chunk_list(pdf_files, BATCH_SIZE)
            batch_progress = st.progress(0)

            for idx, batch in enumerate(batches, start=1):
                st.write(f"• Lote {idx}/{len(batches)} — {len(batch)} PDFs")

                try:
                    result = backend_verify(
                        base_url=BASE_URL,
                        api_key=st.session_state.auth["api_key"],
                        access_token=st.session_state.auth["access_token"],
                        pdf_items=batch,
                        timeout_s=180,
                    )
                except Exception as e:
                    msg = str(e) or "Falló la validación contra AFIP."
                    logger.error("verify error: %s\n%s", msg, traceback.format_exc())
                    status.update(label="Validación incompleta (hubo errores).", state="error")
                    st.error("Falló la validación con AFIP para uno de los lotes.")
                    st.caption(f"Detalle: {msg[:240]}")

                    # ✅ si es plan_limit, forzamos ticker a danger + botón
                    if "límite de su plan" in msg.lower() or "plan_limit_reached" in msg.lower():
                        set_ticker_and_refresh("🚫 Plan agotado — Renovación por WhatsApp disponible", tone="danger")
                        st.link_button("Renovar por WhatsApp", _wa_renew_url(), use_container_width=True)
                    break

                backend_rows = (result or {}).get("rows", []) if isinstance(result, dict) else []
                all_rows.extend(backend_rows)
                batch_progress.progress(idx / len(batches))

            if all_rows:
                status.update(label="Validación completada.", state="complete")
                toast_ok("AFIP OK — resultados listos.")

                df_backend = pd.DataFrame(all_rows)
                st.session_state.df_results = df_backend
                st.dataframe(df_backend, use_container_width=True)
            else:
                if getattr(status, "_state", "") != "error":
                    status.update(label="Sin resultados para mostrar.", state="complete")
                toast_warn("No hubo resultados para mostrar (probá de nuevo).")

    df = st.session_state.get("df_results")
    if df is None:
        df = pd.DataFrame(columns=["Archivo", "CAE", "Vto CAE", "Estado", "AFIP", "Detalle AFIP"])

    if not df.empty:
        st.divider()

        _render_exec_summary(df)

        st.subheader("Filtro / Buscador (Pro)")
        st.caption("Buscá por **CUIT / CAE / archivo / estado** y filtrá por resultado AFIP.")

        cF1, cF2 = st.columns([2, 1])
        with cF1:
            q = st.text_input("Buscar", placeholder="Ej: 3071... / 7439... / Factura_001 / observado", key="filter_q")
        with cF2:
            buckets = st.multiselect(
                "Resultado",
                options=["OK", "OBSERVADA", "RECHAZADA", "SIN_DATOS"],
                default=[],
                key="filter_bucket",
            )

        df_show = _apply_filters(df, q, buckets)

        st.subheader("Resultados (filtrados)")
        st.dataframe(df_show, use_container_width=True)

        if "CAE" in df_show.columns:
            df_show = df_show.copy()
            df_show["CAE"] = df_show["CAE"].astype(str).apply(lambda x: f"'{x}" if x and x != "nan" else "")
        if "Estado" in df_show.columns:
            df_show["Estado"] = df_show["Estado"].astype(str).str.replace("\n", " ", regex=False).str.strip()

        st.subheader("Descargas")
        col1, col2 = st.columns(2)

        with col1:
            csv_bytes = df_show.to_csv(index=False, sep=";", encoding="utf-8-sig").encode("utf-8-sig")
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
                df_show.to_excel(writer, index=False, sheet_name="Resultados")
            st.download_button(
                "Descargar Excel (.xlsx)",
                data=xlsx_buffer.getvalue(),
                file_name="resultado_verificacion_cae.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True,
            )

# ===================== HELPERS ITEMS (PDF) =====================
def _safe_float(x, default=0.0):
    try:
        if x is None:
            return default
        if isinstance(x, str):
            x = x.strip().replace(",", ".")
            if x == "":
                return default
        return float(x)
    except Exception:
        return default

def _items_df_normalize(df_items: pd.DataFrame) -> pd.DataFrame:
    if df_items is None or df_items.empty:
        return pd.DataFrame(columns=["Descripción", "Cantidad", "Precio Unit.", "Subtotal"])
    df2 = df_items.copy()
    for col in ["Descripción", "Cantidad", "Precio Unit.", "Subtotal"]:
        if col not in df2.columns:
            df2[col] = ""
    df2["Descripción"] = df2["Descripción"].astype(str).fillna("").str.strip()
    df2["Cantidad"] = df2["Cantidad"].apply(lambda v: _safe_float(v, 0.0))
    df2["Precio Unit."] = df2["Precio Unit."].apply(lambda v: _safe_float(v, 0.0))
    df2["Subtotal"] = df2.apply(lambda r: round(_safe_float(r.get("Cantidad"), 0.0) * _safe_float(r.get("Precio Unit."), 0.0), 2), axis=1)
    df2 = df2[(df2["Descripción"] != "") | (df2["Cantidad"] != 0) | (df2["Precio Unit."] != 0)]
    df2 = df2.reset_index(drop=True)
    return df2

def _items_to_payload(df_items: pd.DataFrame) -> list:
    df2 = _items_df_normalize(df_items)
    items = []
    for _, r in df2.iterrows():
        items.append({
            "description": str(r.get("Descripción", "") or "").strip(),
            "qty": float(r.get("Cantidad", 0.0) or 0.0),
            "unit_price": float(r.get("Precio Unit.", 0.0) or 0.0),
            "subtotal": float(r.get("Subtotal", 0.0) or 0.0),
        })
    return items

def _items_sum(df_items: pd.DataFrame) -> float:
    df2 = _items_df_normalize(df_items)
    if df2.empty:
        return 0.0
    return float(df2["Subtotal"].sum())

def _money_fmt(x: float) -> str:
    try:
        return f"{x:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    except Exception:
        return str(x)

# ===================== PÁGINA: FACTURACIÓN WSFEv1 =====================
def render_facturacion():
    # ✅ ticker default en páginas no-validación
    set_ticker_and_refresh(
        "🛡️ LexaCAE • Validación oficial AFIP (WSCDC) • Trazabilidad y auditoría • Soporte por WhatsApp",
        "info"
    )

    lex_card_open()
    st.info(
        "Facturación (WSFEv1): emisión de comprobantes con CAE. "
        "Cada cliente emite con su CUIT y certificado. (El PDF lo generás vos; WSFE autoriza y devuelve CAE)."
    )
    lex_card_close()

    st.subheader("1) Configurar emisor (CUIT + Certificado)")
    st.caption("Esto guarda/actualiza credenciales del cliente en el backend (tenant). Recomendado: que lo haga un admin/soporte.")

    cuit_tenant = st.text_input("CUIT emisor (11 dígitos, sin guiones)", key="ten_cuit")
    enabled = st.checkbox("Habilitado", value=True, key="ten_enabled")

    sec = st.session_state.wsfe_secrets

    st.markdown("### Credenciales (seguras)")
    st.caption("Por defecto quedan ocultas. Podés subir archivos o pegar base64, con toggle para mostrar/ocultar.")

    tab1, tab2 = st.tabs(["Certificado (CERT_B64)", "Clave privada (KEY_B64)"])

    with tab1:
        st.markdown("**CERT_B64**")
        colA, colB, colC = st.columns([2, 1, 1])

        with colA:
            cert_file = st.file_uploader(
                "Subir certificado (.pem / .crt / .cer / .der / .txt)",
                type=["pem", "crt", "cer", "der", "txt"],
                key="cert_file"
            )
        with colB:
            sec["show_cert"] = st.toggle(
                "Mostrar",
                value=bool(sec.get("show_cert")),
                key="toggle_show_cert"
            )
        with colC:
            if st.button("Eliminar", use_container_width=True, key="btn_del_cert"):
                sec["cert_b64"] = ""
                sec["cert_loaded"] = False
                sec["cert_source"] = ""
                sec["cert_len"] = 0
                sec["cert_file_sig"] = ""
                toast_warn("Certificado eliminado.")
                st.rerun()

    file_sig = None
    if cert_file is not None:
        try:
            file_sig = f"{cert_file.name}:{cert_file.size}"
        except Exception:
            file_sig = f"{cert_file.name}"

    if cert_file is not None and sec.get("cert_file_sig") != file_sig:
        b64 = _clean_b64(_load_file_to_b64(cert_file))
        if b64:
            sec["cert_b64"] = b64
            sec["cert_loaded"] = True
            sec["cert_source"] = f"archivo: {cert_file.name}"
            sec["cert_len"] = len(b64)
            sec["cert_file_sig"] = file_sig or ""
            toast_ok("Certificado cargado desde archivo.")
        else:
            toast_err("No pudimos leer el certificado o quedó vacío.")

    if not sec.get("cert_loaded") and not sec.get("cert_b64"):
        st.info("No hay certificado cargado.")
    else:
        st.success(f"Certificado cargado ✅ ({sec.get('cert_source') or 'manual'})")
        st.caption(
            f"Largo: {sec.get('cert_len') or len(_clean_b64(sec.get('cert_b64')))} chars · "
            f"Vista: `{_mask_b64(sec.get('cert_b64'))}`"
        )

    if sec.get("show_cert"):
        st.text_area(
            "CERT_B64 (visible)",
            value=sec.get("cert_b64", ""),
            height=140,
            key="cert_b64_visible",
            help="Pegá el base64 completo. Se limpia automáticamente.",
        )
        newv = _clean_b64(st.session_state.get("cert_b64_visible", ""))
        sec["cert_b64"] = newv
        sec["cert_loaded"] = bool(newv)
        sec["cert_source"] = ("manual" if newv else sec.get("cert_source", ""))
        sec["cert_len"] = len(newv)
        if newv:
            sec["cert_file_sig"] = sec.get("cert_file_sig") or ""
    else:
        st.text_input(
            "CERT_B64",
            value="••••••••••••••••••••••",
            disabled=True,
            help="Oculto por seguridad (toggle 'Mostrar' para ver/editar)."
        )

    st.caption("Tip: si pegás base64 con saltos de línea, lo limpiamos automáticamente.")

    with tab2:
        st.markdown("**KEY_B64**")
        colA, colB, colC = st.columns([2, 1, 1])

        with colA:
            key_file = st.file_uploader(
                "Subir key (.key / .pem / .der / .txt)",
                type=["key", "pem", "der", "txt"],
                key="key_file"
            )
        with colB:
            sec["show_key"] = st.toggle(
                "Mostrar",
                value=bool(sec.get("show_key")),
                key="toggle_show_key"
            )
        with colC:
            if st.button("Eliminar", use_container_width=True, key="btn_del_key"):
                sec["key_b64"] = ""
                sec["key_loaded"] = False
                sec["key_source"] = ""
                sec["key_len"] = 0
                sec["key_file_sig"] = ""
                toast_warn("Clave eliminada.")
                st.rerun()

    file_sig = None
    if key_file is not None:
        try:
            file_sig = f"{key_file.name}:{key_file.size}"
        except Exception:
            file_sig = f"{key_file.name}"

    if key_file is not None and sec.get("key_file_sig") != file_sig:
        b64 = _clean_b64(_load_file_to_b64(key_file))
        if b64:
            sec["key_b64"] = b64
            sec["key_loaded"] = True
            sec["key_source"] = f"archivo: {key_file.name}"
            sec["key_len"] = len(b64)
            sec["key_file_sig"] = file_sig or ""
            toast_ok("Clave cargada desde archivo.")
        else:
            toast_err("No pudimos leer la clave o quedó vacía.")

    if not sec.get("key_loaded") and not sec.get("key_b64"):
        st.info("No hay clave cargada.")
    else:
        st.success(f"Clave cargada ✅ ({sec.get('key_source') or 'manual'})")
        st.caption(
            f"Largo: {sec.get('key_len') or len(_clean_b64(sec.get('key_b64')))} chars · "
            f"Vista: `{_mask_b64(sec.get('key_b64'))}`"
        )

    if sec.get("show_key"):
        st.text_area(
            "KEY_B64 (visible)",
            value=sec.get("key_b64", ""),
            height=140,
            key="key_b64_visible",
            help="Pegá el base64 completo. Se limpia automáticamente.",
        )
        newv = _clean_b64(st.session_state.get("key_b64_visible", ""))
        sec["key_b64"] = newv
        sec["key_loaded"] = bool(newv)
        sec["key_source"] = ("manual" if newv else sec.get("key_source", ""))
        sec["key_len"] = len(newv)
        if newv:
            sec["key_file_sig"] = sec.get("key_file_sig") or ""
    else:
        st.text_input(
            "KEY_B64",
            value="••••••••••••••••••••••",
            disabled=True,
            help="Oculto por seguridad (toggle 'Mostrar' para ver/editar)."
        )

    st.caption("Tip: evitá compartir esta clave. Guardala como secreto en el backend siempre que puedas.")
    st.session_state.wsfe_secrets = sec

    colx1, colx2 = st.columns(2)
    with colx1:
        if st.button("Guardar emisor", use_container_width=True, key="btn_tenant_save"):
            cert_b64 = _clean_b64(sec.get("cert_b64", ""))
            key_b64 = _clean_b64(sec.get("key_b64", ""))

            if not (cuit_tenant or "").strip():
                toast_err("Ingresá el CUIT emisor.")
                st.stop()
            if not cert_b64 or not key_b64:
                toast_err("Falta cargar CERT_B64 y/o KEY_B64.")
                st.stop()

            with st.spinner("Guardando emisor..."):
                resp = safe_call(
                    "No pudimos guardar el emisor (tenant). Verificá los datos e intentá de nuevo.",
                    backend_tenant_upsert,
                    BASE_URL, st.session_state.auth["api_key"], st.session_state.auth["access_token"],
                    str(cuit_tenant).strip(), cert_b64, key_b64, enabled
                )
            if resp:
                toast_ok("Emisor guardado correctamente.")
                st.json(resp)

    with colx2:
        st.caption("Tip: podés subir archivos PEM/DER. Si pegás base64, queda oculto por defecto (toggle para mostrar).")

    st.divider()

    st.subheader("2) Emitir comprobante (FECAESolicitar)")
    st.caption("WSFEv1 autoriza por totales. El detalle de ítems lo usamos para que el PDF quede profesional (no se envía a AFIP).")

    cuit_emit = st.text_input("CUIT emisor (tenant)", value=cuit_tenant or "", key="emit_cuit")
    pto_vta = st.number_input("Punto de venta", min_value=1, max_value=99999, value=1, step=1, key="emit_ptovta")
    cbte_tipo = st.number_input("Tipo comprobante (ej: 11=Factura C / 1=Factura A / 6=Factura B)", min_value=1, max_value=999, value=11, step=1, key="emit_tipo")
    concepto = st.selectbox(
        "Concepto",
        options=[1, 2, 3],
        index=0,
        format_func=lambda x: {1: "1 - Productos", 2: "2 - Servicios", 3: "3 - Prod y Serv"}[x],
        key="emit_conc"
    )

    colr1, colr2 = st.columns(2)
    with colr1:
        doc_tipo = st.selectbox("DocTipo receptor", options=[80, 96], index=0, format_func=lambda x: {80: "80 - CUIT", 96: "96 - DNI"}[x], key="emit_doct")
    with colr2:
        doc_nro = st.text_input("DocNro receptor (CUIT 11 / DNI 7-8)", key="emit_docn")

    cbte_fch = st.text_input("Fecha comprobante (YYYYMMDD)", value=datetime.now().strftime("%Y%m%d"), key="emit_fch")

    st.markdown("### Detalle (ítems) — para el PDF (opcional)")
    st.caption("Esto NO impacta el CAE. Se incluye en el PDF para que la factura salga con detalle.")

    st.session_state.wsfe_items_df = _items_df_normalize(st.session_state.wsfe_items_df)

    colit1, colit2 = st.columns([3, 1])
    with colit1:
        edited_items = st.data_editor(
            st.session_state.wsfe_items_df,
            use_container_width=True,
            num_rows="dynamic",
            key="wsfe_items_editor",
            column_config={
                "Descripción": st.column_config.TextColumn("Descripción", help="Detalle del producto/servicio", required=False),
                "Cantidad": st.column_config.NumberColumn("Cantidad", min_value=0.0, step=1.0, format="%.2f"),
                "Precio Unit.": st.column_config.NumberColumn("Precio Unit.", min_value=0.0, step=1.0, format="%.2f"),
                "Subtotal": st.column_config.NumberColumn("Subtotal", help="Se recalcula automáticamente", disabled=True, format="%.2f"),
            },
        )
    with colit2:
        st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
        if st.button("Recalcular", use_container_width=True, key="btn_items_recalc"):
            st.session_state.wsfe_items_df = _items_df_normalize(edited_items)
            toast_ok("Subtotales recalculados.")
            st.rerun()
        if st.button("Limpiar ítems", use_container_width=True, key="btn_items_clear"):
            st.session_state.wsfe_items_df = pd.DataFrame(columns=["Descripción", "Cantidad", "Precio Unit.", "Subtotal"])
            toast_warn("Ítems limpiados.")
            st.rerun()

    st.session_state.wsfe_items_df = _items_df_normalize(edited_items)
    items_sum = _items_sum(st.session_state.wsfe_items_df)

    colmA, colmB, colmC = st.columns(3)
    with colmA:
        st.metric("Subtotal ítems", _money_fmt(items_sum))
    with colmB:
        st.caption("Tip: si no cargás ítems, el PDF saldrá con un detalle genérico.")
    with colmC:
        auto_fill = st.checkbox("Autocompletar ImpNeto/ImpTotal desde ítems", value=False, key="items_auto_fill")

    st.divider()

    st.markdown("### Importes (totales para AFIP)")
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

    if auto_fill and items_sum > 0:
        if float(imp_neto) == 0.0:
            st.session_state["emit_neto"] = float(items_sum)
        if float(imp_total) == 0.0:
            st.session_state["emit_total"] = float(items_sum)
        imp_neto = float(st.session_state.get("emit_neto", imp_neto))
        imp_total = float(st.session_state.get("emit_total", imp_total))

    compare_target = float(imp_neto) if float(imp_neto) > 0 else float(imp_total)
    mismatch = False
    if items_sum > 0 and compare_target > 0:
        if abs(items_sum - compare_target) > 0.02:
            mismatch = True
            st.warning(
                f"Los ítems suman **{_money_fmt(items_sum)}** pero tu total (referencia) es **{_money_fmt(compare_target)}**. "
                "Podés emitir igual el CAE, pero para generar/enviar el PDF conviene que coincida."
            )

    st.markdown("### Moneda")
    colmo1, colmo2 = st.columns(2)
    with colmo1:
        mon_id = st.text_input("MonId", value="PES", key="emit_monid")
    with colmo2:
        mon_ctz = st.number_input("MonCotiz", min_value=0.000001, value=1.0, step=0.1, key="emit_monctz")

    st.markdown("### IVA (opcional)")
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
            with st.spinner("Consultando..."):
                resp = safe_call(
                    "No pudimos consultar el último autorizado.",
                    backend_wsfe_last,
                    BASE_URL, st.session_state.auth["api_key"], st.session_state.auth["access_token"],
                    cuit_emit, int(pto_vta), int(cbte_tipo)
                )
            if resp:
                toast_ok("OK")
                st.json(resp)

    with colb2:
        if st.button("Emitir (obtener CAE)", use_container_width=True, key="btn_emit"):
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

            with st.spinner("Solicitando CAE (WSFE)..."):
                resp = safe_call(
                    "No pudimos emitir el comprobante (WSFE). Revisá los datos e intentá de nuevo.",
                    backend_wsfe_cae,
                    BASE_URL, st.session_state.auth["api_key"], st.session_state.auth["access_token"],
                    payload
                )

            if resp:
                toast_ok("Respuesta WSFE recibida.")
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

                    items_payload = _items_to_payload(st.session_state.wsfe_items_df)

                    pdf_payload = dict(payload)
                    pdf_payload.update({
                        "cbte_nro": cbtenro,
                        "cae": cae,
                        "cae_vto": cae_vto,
                        "resultado": resp.get("resultado"),
                        "items": items_payload,
                    })

                    colpdf1, colpdf2 = st.columns(2)
                    with colpdf1:
                        if st.button("Generar PDF", use_container_width=True, key="btn_wsfe_gen_pdf"):
                            if mismatch:
                                toast_err("Ajustá los totales o los ítems antes de generar el PDF (no coinciden).")
                                st.stop()

                            with st.spinner("Generando PDF..."):
                                pdf_bytes = safe_call(
                                    "No pudimos generar el PDF.",
                                    backend_wsfe_pdf,
                                    BASE_URL, st.session_state.auth["api_key"], st.session_state.auth["access_token"],
                                    pdf_payload, 60
                                )
                            if pdf_bytes:
                                st.session_state.wsfe_pdf_bytes = pdf_bytes
                                st.session_state.wsfe_pdf_name = pdf_name
                                toast_ok("PDF generado.")

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
                            if mismatch:
                                toast_err("Ajustá los totales o los ítems antes de enviar el PDF (no coinciden).")
                                st.stop()

                            if not (to_email or "").strip():
                                toast_err("Ingresá un email destinatario.")
                            else:
                                mail_payload = {"to_email": to_email.strip(), "pdf_payload": pdf_payload}
                                with st.spinner("Enviando email..."):
                                    resp_mail = safe_call(
                                        "No pudimos enviar el email (backend).",
                                        backend_wsfe_send_email,
                                        BASE_URL, st.session_state.auth["api_key"], st.session_state.auth["access_token"],
                                        mail_payload, 60
                                    )
                                if resp_mail:
                                    toast_ok("Email enviado (backend).")
                                    st.json(resp_mail)

                    with colmail2:
                        st.caption("Requiere endpoint backend **POST /wsfe/email** + SMTP configurado en el backend.")
                        st.caption("El detalle de ítems se envía dentro de `pdf_payload.items`.")

# ===================== ROUTER =====================
if page == "Perfil":
    render_perfil()
elif page == "Facturación (WSFEv1)":
    render_facturacion()
else:
    render_validacion()