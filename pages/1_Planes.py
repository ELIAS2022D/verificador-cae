import os
import streamlit as st

st.set_page_config(
    page_title="Tarifas | lexaCAE",
    layout="wide",
    initial_sidebar_state="expanded",
)

# =========================================================
# Config resolver: Render ENV first, then Streamlit secrets
# =========================================================
def cfg(key: str, default: str = "") -> str:
    v = os.getenv(key)
    if v is not None and str(v).strip() != "":
        return v
    try:
        return st.secrets.get(key, default)
    except Exception:
        return default

# =========================================================
# Helpers
# =========================================================
def money_ar(n: int) -> str:
    return f"{n:,}".replace(",", ".")

def soft_redirect(url: str):
    st.markdown(f"<meta http-equiv='refresh' content='0; url={url}'>", unsafe_allow_html=True)

# =========================================================
# Config (URLs)
# =========================================================
MP_LINKS = {
    "pack_50_m":  (cfg("MP_PACK_50_M_URL",  "") or "").strip(),
    "pack_150_m": (cfg("MP_PACK_150_M_URL", "") or "").strip(),
    "pack_300_m": (cfg("MP_PACK_300_M_URL", "") or "").strip(),
    "pack_500_m": (cfg("MP_PACK_500_M_URL", "") or "").strip(),
    "pack_50_a":  (cfg("MP_PACK_50_A_URL",  "") or "").strip(),
    "pack_150_a": (cfg("MP_PACK_150_A_URL", "") or "").strip(),
    "pack_300_a": (cfg("MP_PACK_300_A_URL", "") or "").strip(),
    "pack_500_a": (cfg("MP_PACK_500_A_URL", "") or "").strip(),
}
MP_EMBED_HTML = (cfg("MP_EMBED_HTML", "") or "").strip()

LOGIN_URL = (cfg("LOGIN_URL", "/") or "/").strip()
APP_URL = (cfg("APP_URL", "") or "").strip() or LOGIN_URL

HERO_IMAGE_PATH = (cfg("HERO_IMAGE_PATH", "assets/mujerAdmin.jpeg") or "assets/mujerAdmin.jpeg").strip()

# =========================================================
# CSS (moderno + sidebar fija)
# =========================================================
st.markdown(
    """
<style>
/* ====== ANCHO sidebar fijo ====== */
:root{
  --sidebar-w: 22rem; /* <-- ajustá acá (ej 20rem / 24rem) */
  --blue:#0b4fb3;
  --blue-dark:#083a86;
  --card:#ffffff;
  --text:#0f172a;
  --muted:#475569;
  --border: rgba(15, 23, 42, 0.12);
}

/* ====== Base ====== */
header[data-testid="stHeader"]{ background: transparent; }
div[data-testid="stToolbar"]{ display:none; }

/* ✅ Mostrar botón de colapsar (<<) */
button[data-testid="collapsedControl"]{
  display: block !important;
  opacity: 1 !important;
  visibility: visible !important;
}

/* ====== Sidebar fija ====== */
section[data-testid="stSidebar"]{
  position: fixed !important;
  top: 0;
  left: 0;
  height: 100vh !important;
  width: var(--sidebar-w) !important;
  min-width: var(--sidebar-w) !important;
  max-width: var(--sidebar-w) !important;
  background: #f6f8fc;
  border-right: 1px solid rgba(15,23,42,.08);
  overflow-y: auto !important;
  z-index: 999 !important;
}
section[data-testid="stSidebar"] .stSidebarContent{
  padding-top: 18px;
}

/* ====== Main: corrimiento para no tapar contenido ====== */
div[data-testid="stAppViewContainer"]{
  margin-left: var(--sidebar-w) !important;
}
.block-container{
  padding-top: 14px !important;
  padding-bottom: 26px !important;
  max-width: 1200px !important;
}

/* En mobile: volvemos a comportamiento normal (sidebar overlay) */
@media (max-width: 900px){
  section[data-testid="stSidebar"]{
    position: relative !important;
    width: auto !important;
    min-width: unset !important;
    max-width: unset !important;
    height: auto !important;
  }
  div[data-testid="stAppViewContainer"]{
    margin-left: 0 !important;
  }
}

/* ====== Sidebar moderno ====== */
.sidebar-brand{
  font-weight: 900;
  font-size: 18px;
  color: var(--blue);
  letter-spacing: .2px;
  margin-bottom: 10px;
}
.sidebar-sub{
  font-size: 12px;
  color: rgba(15,23,42,.55);
  margin-top: -8px;
  margin-bottom: 14px;
}

/* Pills del radio (App / Planes) */
div[role="radiogroup"] > label{ width: 100%; }
div[role="radiogroup"] label{
  padding: 10px 10px !important;
  border-radius: 12px !important;
  border: 1px solid rgba(15,23,42,.10) !important;
  background: white !important;
  margin: 6px 0 !important;
  transition: all .15s ease;
}
div[role="radiogroup"] label:hover{
  border-color: rgba(11,79,179,.25) !important;
  box-shadow: 0 8px 18px rgba(2,6,23,.06);
}

/* Card login */
.sidebar-card{
  background: white;
  border: 1px solid rgba(15,23,42,.10);
  border-radius: 16px;
  padding: 14px;
  box-shadow: 0 10px 22px rgba(2,6,23,.06);
}
.sidebar-title{
  font-size: 16px;
  font-weight: 900;
  color: var(--text);
  margin: 0 0 8px 0;
}
.sidebar-help{
  font-size: 12px;
  color: rgba(15,23,42,.55);
  margin: 0 0 12px 0;
}

/* ====== Hero ====== */
.hero-wrap{
  background: linear-gradient(180deg, rgba(11,79,179,.06), rgba(11,79,179,0));
  border: 1px solid rgba(15,23,42,.08);
  border-radius: 18px;
  padding: 18px 18px;
  box-shadow: 0 14px 32px rgba(2,6,23,.06);
}
.hero-title{
  font-size: 30px;
  font-weight: 950;
  color: var(--text);
  margin: 2px 0 6px 0;
}
.hero-sub{
  font-size: 14px;
  font-weight: 900;
  color: var(--blue);
  margin: 0 0 10px 0;
}
.hero-p{
  color: var(--muted);
  line-height: 1.65;
  font-size: 13.5px;
  max-width: 680px;
}
.how h4{
  margin: 12px 0 8px 0;
  font-size: 13px;
  color: var(--text);
  font-weight: 950;
}
.how ol{
  margin: 0 0 10px 18px;
  color: var(--text);
  font-size: 13px;
}
.hero-note{
  font-size: 12.5px;
  color: var(--text);
  font-weight: 800;
}
.hero-img-wrap img{
  border-radius: 16px !important;
  object-fit: cover;
  box-shadow: 0 18px 45px rgba(2, 6, 23, 0.10);
  border: 1px solid rgba(2, 6, 23, 0.08);
  max-width: 280px !important;
  margin-left: auto;
  display: block;
}

/* ====== Planes ====== */
.section-title{
  text-align:center;
  font-size: 24px;
  font-weight: 950;
  color: var(--text);
  margin: 18px 0 10px 0;
}
.plan-card{
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 18px 18px 16px 18px;
  box-shadow: 0 14px 35px rgba(2, 6, 23, 0.08);
  position: relative;
}
.plan-topline{
  height: 3px;
  background: rgba(11,79,179,.18);
  margin: 8px 0 14px 0;
}
.plan-name{
  font-size: 18px;
  font-weight: 950;
  color: var(--blue-dark);
  margin: 0 0 4px 0;
}
.plan-price{
  font-size: 24px;
  font-weight: 950;
  margin: 8px 0 6px 0;
  color: #111827;
}
.plan-muted{
  font-size: 12.5px;
  color: #334155;
  font-weight: 800;
}
.plan-meta{
  margin-top: 10px;
  font-size: 12.5px;
  color: #111827;
  font-weight: 900;
}
.popular-ribbon{
  position:absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 26px;
  border-top-left-radius: 16px;
  border-top-right-radius: 16px;
  background: #0b2d57;
  color:#fff;
  font-weight: 950;
  font-size: 12px;
  display:flex;
  align-items:center;
  justify-content:center;
}
.popular{
  border: 2px solid rgba(11,79,179,.30);
}
.checkout{
  margin-top: 16px;
  padding: 0 2px;
}

@media (max-width: 1020px){
  .hero-title{ font-size: 26px; }
  .hero-img-wrap img{ max-width: 100% !important; }
}
</style>
""",
    unsafe_allow_html=True,
)

# =========================================================
# Sidebar: navegación + login
# =========================================================
with st.sidebar:
    st.markdown("<div class='sidebar-brand'>lexaCAE</div>", unsafe_allow_html=True)
    st.markdown("<div class='sidebar-sub'>Verificación de CAE (AFIP) · WSCDC</div>", unsafe_allow_html=True)

    if "nav" not in st.session_state:
        st.session_state["nav"] = "Planes"

    nav = st.radio(
        label="",
        options=["app", "Planes"],
        index=1 if st.session_state["nav"] == "Planes" else 0,
        key="nav_radio",
        label_visibility="collapsed",
    )
    st.session_state["nav"] = nav

    if nav == "app":
        soft_redirect(APP_URL)

    st.markdown("<hr style='border:none;height:1px;background:rgba(15,23,42,.10);margin:14px 0;'>", unsafe_allow_html=True)

    st.markdown("<div class='sidebar-card'>", unsafe_allow_html=True)
    st.markdown("<div class='sidebar-title'>Acceso</div>", unsafe_allow_html=True)
    st.markdown("<div class='sidebar-help'>Ingresá tus credenciales para usar la app.</div>", unsafe_allow_html=True)

    cuit = st.text_input("CUIT (sin guiones)", value=st.session_state.get("cuit", ""), key="sidebar_cuit")
    _pwd = st.text_input("Contraseña", type="password", value="", key="sidebar_pwd")

    b1, b2 = st.columns(2)
    with b1:
        if st.button("Ingresar", use_container_width=True):
            st.session_state["cuit"] = cuit.strip()
            soft_redirect(LOGIN_URL)

    with b2:
        if st.button("Salir", use_container_width=True):
            st.session_state.pop("cuit", None)
            st.session_state.pop("mp_plan", None)
            st.session_state.pop("mp_is_annual", None)
            st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)

# =========================================================
# MAIN: HERO + PLANES + CHECKOUT
# =========================================================
st.markdown("<div class='hero-wrap'>", unsafe_allow_html=True)

hero_l, hero_r = st.columns([1.45, 0.55], gap="large")

with hero_l:
    st.markdown(
        """
        <div class="hero-title">Verificación de CAE de Facturas AFIP en segundos.</div>
        <div class="hero-sub">Servicio de validación de CAE para facturas electrónicas</div>
        <div class="hero-p">
          Nuestro sistema permite verificar CAE de facturas AFIP, confirmando que el comprobante fue autorizado correctamente.
          Ideal para empresas que necesitan validar facturas recibidas, evitar comprobantes apócrifos y reducir riesgos impositivos.
        </div>

        <div class="how">
          <h4>¿Cómo funciona?</h4>
          <ol>
            <li>Subí una o varias facturas electrónicas</li>
            <li>El sistema lee los datos fiscales (CUIT, punto de venta, número, CAE)</li>
            <li>Se consulta automáticamente a AFIP</li>
            <li>Obtenés el resultado de <b>CAE válido</b> o <b>inválido</b></li>
          </ol>
          <div class="hero-note">Proceso rápido, automático y online.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with hero_r:
    st.markdown("<div class='hero-img-wrap'>", unsafe_allow_html=True)
    st.image(HERO_IMAGE_PATH, use_container_width=False)
    st.markdown("</div>", unsafe_allow_html=True)

st.markdown("</div>", unsafe_allow_html=True)

# Anchor
st.markdown('<div id="planes"></div>', unsafe_allow_html=True)

# Planes header + toggle
st.markdown("<div class='section-title'>Una solución para cada necesidad</div>", unsafe_allow_html=True)
ct1, ct2, ct3 = st.columns([3, 2.2, 3])
with ct2:
    anual = st.toggle("Planes anuales (Ahorrá 25%)", value=False)

plans = [
    {"id": "pack_50",  "title": "Starter",    "monthly": 12041, "annual": 9031,  "qty": "50 facturas",   "featured": False},
    {"id": "pack_150", "title": "Pro",        "monthly": 24423, "annual": 18317, "qty": "150 facturas",  "featured": False},
    {"id": "pack_300", "title": "Advance",    "monthly": 32987, "annual": 24740, "qty": "300 facturas",  "featured": True},
    {"id": "pack_500", "title": "Enterprise", "monthly": 40614, "annual": 30460, "qty": "500+ facturas", "featured": False, "enterprise": True},
]

cols = st.columns(4, gap="large")

for idx, p in enumerate(plans):
    with cols[idx]:
        period = "año" if anual else "mes"
        is_enterprise = bool(p.get("enterprise", False))

        if is_enterprise:
            st.markdown(
                f"""
<div class="plan-card">
  <div class="plan-name">{p["title"]}</div>
  <div class="plan-topline"></div>
  <div class="plan-meta">Solución a medida</div>
  <div style="height: 10px;"></div>
</div>
""",
                unsafe_allow_html=True,
            )
            if st.button("Obtené una cotización", use_container_width=True, key="quote_enterprise"):
                st.session_state["mp_plan"] = p["id"]
                st.session_state["mp_is_annual"] = bool(anual)
        else:
            price = p["annual"] if anual else p["monthly"]
            popular = "popular" if p["featured"] else ""

            st.markdown(
                f"""
<div class="plan-card {popular}">
  {"<div class='popular-ribbon'>Más popular</div>" if p["featured"] else ""}
  <div style="height:{'22px' if p["featured"] else '0px'};"></div>
  <div class="plan-name">{p["title"]}</div>
  <div class="plan-topline"></div>
  <div class="plan-price">$ {money_ar(price)} / {period}</div>
  <div class="plan-muted">{p["qty"]}</div>
</div>
""",
                unsafe_allow_html=True,
            )

            if st.button("Conseguir", use_container_width=True, key=f"buy_{p['id']}_{'a' if anual else 'm'}"):
                st.session_state["mp_plan"] = p["id"]
                st.session_state["mp_is_annual"] = bool(anual)

# Checkout
st.markdown("<div class='checkout'>", unsafe_allow_html=True)

if st.session_state.get("mp_plan"):
    plan_id = st.session_state["mp_plan"]
    is_annual = st.session_state.get("mp_is_annual", False)

    st.subheader("Continuar con el pago")
    st.write("Vas a ser redirigido a Mercado Pago para finalizar la compra.")

    suffix = "a" if is_annual else "m"
    link_key = f"{plan_id}_{suffix}"
    mp_url = (MP_LINKS.get(link_key) or "").strip()

    if mp_url:
        st.markdown(
            f"""
            <a href="{mp_url}" target="_blank" style="text-decoration:none;">
              <div style="padding:14px 16px;border-radius:14px;border:1px solid rgba(148,163,184,.35);
                          background: rgba(34,197,94,.12); display:inline-block; font-weight:900;">
                Ir a Mercado Pago →
              </div>
            </a>
            """,
            unsafe_allow_html=True,
        )
        st.caption("Si no se abre, habilitá pop-ups o abrilo desde otra pestaña.")
    else:
        if MP_EMBED_HTML:
            st.info("Cargando checkout embebido…")
            st.components.v1.html(MP_EMBED_HTML, height=650, scrolling=True)
        else:
            st.warning(
                "No encontré el link/HTML de Mercado Pago para este plan.\n\n"
                "Solución rápida: cargá en Render (UI service) las ENV:\n"
                "MP_PACK_50_M_URL, MP_PACK_150_M_URL, MP_PACK_300_M_URL, MP_PACK_500_M_URL\n"
                "y (si usás anual) MP_PACK_50_A_URL, etc."
            )

    st.write("")
    if st.button("Cambiar de plan", use_container_width=False):
        st.session_state.pop("mp_plan", None)
        st.session_state.pop("mp_is_annual", None)
        st.rerun()

st.markdown("</div>", unsafe_allow_html=True)
