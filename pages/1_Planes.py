import os
import streamlit as st

st.set_page_config(page_title="Tarifas | lexaCAE", layout="wide")

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

# Opción B (si ya tenés HTML/JS y querés embed)
MP_EMBED_HTML = (cfg("MP_EMBED_HTML", "") or "").strip()

# URL de tu login (si usás multipage de Streamlit, esto suele ser "/")
LOGIN_URL = (cfg("LOGIN_URL", "/") or "/").strip()

# Anchor / Links del navbar
TARIFAS_URL = (cfg("TARIFAS_URL", "#planes") or "#planes").strip()

# Path dentro del repo (NO usar D:\... en producción)
HERO_IMAGE_PATH = (cfg("HERO_IMAGE_PATH", "assets/mujerAdmin.jpeg") or "assets/mujerAdmin.jpeg").strip()

# =========================================================
# CSS (consistente con Streamlit + estilo mock)
# =========================================================
st.markdown(
    """
<style>
/* ========= Streamlit base cleanup (sin romper consistencia) ========= */
.block-container{
  padding: 0 !important;
  max-width: 100% !important;
}
section[data-testid="stSidebar"]{ display:none; }
header[data-testid="stHeader"]{ background: transparent; }
div[data-testid="stToolbar"]{ display:none; }

/* ========= Colores ========= */
:root{
  --blue:#0b4fb3;
  --blue-dark:#083a86;
  --bg-soft:#eaf4ff;
  --card:#ffffff;
  --text:#0f172a;
  --muted:#475569;
  --border: rgba(15, 23, 42, 0.12);
}

/* ========= Navbar ========= */
.navbar{
  width:100%;
  background: var(--blue);
  padding: 10px 22px; /* ajustado para evitar "aire" */
  display:flex;
  justify-content:space-between;
  align-items:center;
}
.brand{
  color:#fff;
  font-weight:800;
  font-size: 22px;
  letter-spacing: 0.2px;
}
.navlinks{
  display:flex;
  gap:18px;
  align-items:center;
}
.navlinks a{
  color:#dbeafe;
  text-decoration:none;
  font-weight:600;
  font-size: 14px;
}
.navlinks a:hover{ color:#fff; }
.loginbtn{
  color:#fff !important;
  border: 2px solid rgba(255,255,255,.75);
  padding: 6px 14px;
  border-radius: 999px;
  font-weight: 800;
}

/* ========= Hero ========= */
.hero-wrap{
  width:100%;
  background: #ffffff;
  padding: 18px 22px 10px 22px; /* ajustado, elimina franja blanca grande */
}
.hero-inner{
  max-width: 1200px;
  margin: 0 auto;
}
.hero-title{
  font-size: 34px;
  font-weight: 900;
  color: var(--text);
  margin: 4px 0 8px 0;
}
.hero-sub{
  font-size: 16px;
  font-weight: 800;
  color: var(--blue);
  margin: 0 0 12px 0;
}
.hero-p{
  color: var(--muted);
  line-height: 1.6;
  font-size: 14px;
  max-width: 650px;
}
.how{
  margin-top: 16px;
}
.how h4{
  margin: 0 0 10px 0;
  font-size: 14px;
  color: var(--text);
  font-weight: 900;
}
.how ol{
  margin: 0 0 10px 18px;
  color: var(--text);
  font-size: 13px;
}
.hero-note{
  font-size: 13px;
  color: var(--text);
  font-weight: 700;
}
.cta{
  margin-top: 16px;
  display:inline-block;
  padding: 11px 18px;
  border-radius: 999px;
  border: 2px solid rgba(11,79,179,.35);
  background: #fff;
  color: var(--blue-dark);
  font-weight: 900;
  text-decoration:none;
}
.cta:hover{
  background: rgba(11,79,179,.06);
}

/* Imagen del hero (st.image) más chica y prolija */
.hero-img-wrap img{
  border-radius: 16px !important;
  object-fit: cover;
  box-shadow: 0 18px 45px rgba(2, 6, 23, 0.12);
  border: 1px solid rgba(2, 6, 23, 0.08);
  max-width: 320px !important; /* clave: imagen más chica */
  margin-left: auto;
  display: block;
}

/* ========= Sección planes ========= */
.plans-wrap{
  width:100%;
  background: var(--bg-soft);
  padding: 40px 26px 46px 26px;
  border-top: 6px solid rgba(11,79,179,.20);
}
.plans-inner{
  max-width: 1200px;
  margin: 0 auto;
}
.plans-title{
  text-align:center;
  font-size: 30px;
  font-weight: 900;
  color: var(--text);
  margin: 0 0 10px 0;
}

/* ========= Cards ========= */
.plan-card{
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 14px;
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
  font-size: 20px;
  font-weight: 900;
  color: var(--blue-dark);
  margin: 0 0 4px 0;
}
.plan-price{
  font-size: 26px;
  font-weight: 950;
  margin: 8px 0 6px 0;
  color: #111827;
}
.plan-muted{
  font-size: 13px;
  color: #334155;
  font-weight: 700;
}
.plan-meta{
  margin-top: 12px;
  font-size: 13px;
  color: #111827;
  font-weight: 800;
}

.popular-ribbon{
  position:absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 26px;
  border-top-left-radius: 14px;
  border-top-right-radius: 14px;
  background: #0b2d57;
  color:#fff;
  font-weight: 900;
  font-size: 12px;
  display:flex;
  align-items:center;
  justify-content:center;
}
.popular{
  border: 2px solid rgba(11,79,179,.35);
}

/* ========= Checkout ========= */
.checkout{
  max-width: 1200px;
  margin: 26px auto 0 auto;
  padding: 0 2px;
}

/* responsive */
@media (max-width: 1020px){
  .hero-title{ font-size: 28px; }
  .hero-img-wrap img{ max-width: 100% !important; }
}
</style>
""",
    unsafe_allow_html=True,
)

# =========================================================
# Navbar
# =========================================================
st.markdown(
    f"""
<div class="navbar">
  <div class="brand">lexaCAE</div>
  <div class="navlinks">
    <a href="{TARIFAS_URL}">Tarifas</a>
    <a class="loginbtn" href="{LOGIN_URL}">LOGIN</a>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

# =========================================================
# HERO (Streamlit nativo + imagen chica)
# =========================================================
with st.container():
    st.markdown("<div class='hero-wrap'><div class='hero-inner'>", unsafe_allow_html=True)

    hero_l, hero_r = st.columns([1.35, 0.65], gap="large")  # imagen más chica

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

            <a class="cta" href="#planes">Conocé nuestros Planes</a>
            """,
            unsafe_allow_html=True,
        )

    with hero_r:
        st.markdown("<div class='hero-img-wrap'>", unsafe_allow_html=True)
        st.image(HERO_IMAGE_PATH, use_container_width=False)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("</div></div>", unsafe_allow_html=True)

# =========================================================
# PLANES (sección celeste + título)
# =========================================================
st.markdown('<div id="planes"></div>', unsafe_allow_html=True)

st.markdown(
    """
<div class="plans-wrap">
  <div class="plans-inner">
    <div class="plans-title">Una solución para cada necesidad</div>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

# Para que el contenido quede sobre el fondo celeste
st.markdown("<div class='plans-wrap'><div class='plans-inner'>", unsafe_allow_html=True)

c1, c2, c3 = st.columns([3, 2.2, 3])
with c2:
    anual = st.toggle("Planes anuales (Ahorrá 25%)", value=False)

# Planes (manteniendo tu pricing + lógica MP)
plans = [
    {"id": "pack_50",  "title": "Starter",   "monthly": 12041, "annual": 9031,  "qty": "50 facturas",   "featured": False},
    {"id": "pack_150", "title": "Pro",       "monthly": 24423, "annual": 18317, "qty": "150 facturas",  "featured": False},
    {"id": "pack_300", "title": "Advance",   "monthly": 32987, "annual": 24740, "qty": "300 facturas",  "featured": True},   # Más popular
    {"id": "pack_500", "title": "Enterprise","monthly": 40614, "annual": 30460, "qty": "500+ facturas", "featured": False, "enterprise": True},
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

st.markdown("</div></div>", unsafe_allow_html=True)

# =========================================================
# Checkout Mercado Pago
# =========================================================
st.markdown("<div class='checkout'>", unsafe_allow_html=True)

if st.session_state.get("mp_plan"):
    plan_id = st.session_state["mp_plan"]
    is_annual = st.session_state.get("mp_is_annual", False)

    st.subheader("Continuar con el pago")
    st.write("Vas a ser redirigido a Mercado Pago para finalizar la compra.")

    suffix = "a" if is_annual else "m"
    link_key = f"{plan_id}_{suffix}"
    mp_url = (MP_LINKS.get(link_key) or "").strip()

    # -------- Opción A: Link directo (recomendada) --------
    if mp_url:
        st.markdown(
            f"""
            <a href="{mp_url}" target="_blank" style="text-decoration:none;">
              <div style="padding:14px 16px;border-radius:14px;border:1px solid rgba(148,163,184,.35);
                          background: rgba(34,197,94,.12); display:inline-block; font-weight:800;">
                Ir a Mercado Pago →
              </div>
            </a>
            """,
            unsafe_allow_html=True,
        )
        st.caption("Si no se abre, habilitá pop-ups o abrilo desde otra pestaña.")
    else:
        # -------- Opción B: Embed HTML/JS (si lo tenés) --------
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
