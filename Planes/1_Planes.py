import streamlit as st
from urllib.parse import quote

st.set_page_config(page_title="Planes | Verificador CAE", layout="wide")

# =========================================================
# Helpers
# =========================================================
def money_ar(n: int) -> str:
    # 12041 -> "12.041"
    return f"{n:,}".replace(",", ".")

def go(url: str):
    # navegación simple (Streamlit multipage o external)
    st.markdown(f"<meta http-equiv='refresh' content='0; url={url}'>", unsafe_allow_html=True)

# =========================================================
# Config (enchufás tus URLs o HTML)
# =========================================================
# Opción A (recomendada): links directos a MP por plan (Checkout Pro)
MP_LINKS = {
    "pack_50_m":  st.secrets.get("MP_PACK_50_M_URL",  ""),
    "pack_150_m": st.secrets.get("MP_PACK_150_M_URL", ""),
    "pack_300_m": st.secrets.get("MP_PACK_300_M_URL", ""),
    "pack_500_m": st.secrets.get("MP_PACK_500_M_URL", ""),
    "pack_50_a":  st.secrets.get("MP_PACK_50_A_URL",  ""),
    "pack_150_a": st.secrets.get("MP_PACK_150_A_URL", ""),
    "pack_300_a": st.secrets.get("MP_PACK_300_A_URL", ""),
    "pack_500_a": st.secrets.get("MP_PACK_500_A_URL", ""),
}

# Opción B (si ya tenés HTML/JS y querés embed): lo podés guardar en secrets o pegarlo acá
MP_EMBED_HTML = st.secrets.get("MP_EMBED_HTML", "")

# URL de tu login (si usás multipage de Streamlit, esto suele ser "/")
LOGIN_URL = st.secrets.get("LOGIN_URL", "/")

# =========================================================
# Estilos
# =========================================================
st.markdown(
    """
<style>
/* ancho y padding */
.block-container { padding-top: 2.2rem; padding-bottom: 2.5rem; max-width: 1200px; }

/* header */
h1.title { text-align:center; font-size: 2.4rem; margin-bottom: 0.2rem; }
p.subtitle { text-align:center; color: #6b7280; margin-top: 0; }

/* cards */
.plan-card{
  border: 1px solid rgba(148, 163, 184, 0.30);
  border-radius: 18px;
  padding: 18px 18px 14px 18px;
  background: rgba(255,255,255,0.03);
  box-shadow: 0 10px 30px rgba(0,0,0,0.10);
  min-height: 385px;
}
.badge{
  display:inline-block;
  font-size: 12px;
  padding: 6px 10px;
  border-radius: 999px;
  background: rgba(34, 197, 94, 0.14);
  color: rgb(34, 197, 94);
  border: 1px solid rgba(34, 197, 94, 0.25);
  margin-bottom: 8px;
}
.badge-star{
  background: rgba(168, 85, 247, 0.14);
  color: rgb(168, 85, 247);
  border: 1px solid rgba(168, 85, 247, 0.25);
}
.price{
  font-size: 2.2rem;
  font-weight: 800;
  margin: 10px 0 0 0;
}
.muted{ color: #6b7280; margin-top: 2px; }
.hr{ height: 1px; background: rgba(148, 163, 184, 0.25); margin: 14px 0; }
.feature{ margin: 8px 0; }
.small{ font-size: 0.92rem; color: #9ca3af; }

/* boton top-right */
.topbar{
  display:flex;
  justify-content: space-between;
  align-items:center;
  margin-bottom: 0.6rem;
}
.topbar a{
  text-decoration:none;
}
.topbar .backbtn{
  padding: 8px 12px;
  border-radius: 12px;
  border: 1px solid rgba(148,163,184,0.35);
  background: rgba(255,255,255,0.04);
  color: #e5e7eb;
  font-weight: 600;
  display:inline-block;
}
</style>
""",
    unsafe_allow_html=True,
)

# =========================================================
# Top bar
# =========================================================
st.markdown(
    f"""
<div class="topbar">
  <div></div>
  <a href="{LOGIN_URL}">
    <span class="backbtn">← Volver al login</span>
  </a>
</div>
""",
    unsafe_allow_html=True,
)

# =========================================================
# Header
# =========================================================
st.markdown("<h1 class='title'>Elegí el plan ideal para tu negocio</h1>", unsafe_allow_html=True)
st.markdown(
    "<p class='subtitle'>Planes mensuales y anuales. Validación oficial AFIP (WSCDC). Soporte incluido.</p>",
    unsafe_allow_html=True,
)

st.write("")
col_t1, col_t2, col_t3 = st.columns([4, 2, 4])
with col_t2:
    anual = st.toggle("Planes anuales (Ahorrá 25%)", value=False)

st.write("")
st.divider()

# =========================================================
# Planes
# =========================================================
plans = [
    {
        "id": "pack_50",
        "title": "Pack 50",
        "monthly": 12041,
        "annual": 9031,
        "badge": "Ideal para empezar",
        "featured": False,
        "features": [
            "50 comprobantes / mes",
            "3 usuarios",
            "Asistencia en trámite AFIP",
            "Reportes + Libro IVA",
        ],
    },
    {
        "id": "pack_150",
        "title": "Pack 150",
        "monthly": 24423,
        "annual": 18317,
        "badge": "Más elegido",
        "featured": False,
        "features": [
            "150 comprobantes / mes",
            "Usuarios ilimitados",
            "Soporte email y teléfono",
            "Integraciones e-commerce",
        ],
    },
    {
        "id": "pack_300",
        "title": "Pack 300",
        "monthly": 32987,
        "annual": 24740,
        "badge": "Recomendado ⭐",
        "featured": True,
        "features": [
            "300 comprobantes / mes",
            "Usuarios ilimitados",
            "Prioridad en soporte",
            "Facturación masiva por lote",
        ],
    },
    {
        "id": "pack_500",
        "title": "Pack 500",
        "monthly": 40614,
        "annual": 30460,
        "badge": "Para alto volumen",
        "featured": False,
        "features": [
            "500 comprobantes / mes",
            "Usuarios ilimitados",
            "Soporte dedicado",
            "Integración API",
        ],
    },
]

cols = st.columns(4)

for idx, p in enumerate(plans):
    with cols[idx]:
        price = p["annual"] if anual else p["monthly"]
        period = "año" if anual else "mes"
        badge_class = "badge badge-star" if p["featured"] else "badge"

        st.markdown("<div class='plan-card'>", unsafe_allow_html=True)
        st.markdown(f"<div class='{badge_class}'>{p['badge']}</div>", unsafe_allow_html=True)
        st.markdown(f"### {p['title']}")
        st.markdown(f"<div class='price'>$ {money_ar(price)}</div>", unsafe_allow_html=True)
        st.markdown(f"<div class='muted'>+ IVA / {period}</div>", unsafe_allow_html=True)
        st.markdown("<div class='hr'></div>", unsafe_allow_html=True)

        for feat in p["features"]:
            st.markdown(f"<div class='feature'>✅ {feat}</div>", unsafe_allow_html=True)

        st.markdown("<div class='hr'></div>", unsafe_allow_html=True)
        st.caption("Pago seguro con Mercado Pago. Activación inmediata.")
        buy_label = "Comprar anual" if anual else "Comprar mensual"

        if st.button(buy_label, use_container_width=True, key=f"buy_{p['id']}_{'a' if anual else 'm'}"):
            st.session_state["mp_plan"] = p["id"]
            st.session_state["mp_is_annual"] = bool(anual)

        st.markdown("</div>", unsafe_allow_html=True)

st.divider()

# =========================================================
# Checkout Mercado Pago
# =========================================================
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
                          background: rgba(34,197,94,.12); display:inline-block; font-weight:700;">
                Ir a Mercado Pago →
              </div>
            </a>
            """,
            unsafe_allow_html=True,
        )
        st.caption("Si no se abre, habilitá pop-ups o abrilo desde otra pestaña.")
    else:
        # -------- Opción B: Embed HTML/JS (si lo tenés funcionando) --------
        if MP_EMBED_HTML:
            st.info("Cargando checkout embebido…")
            st.components.v1.html(MP_EMBED_HTML, height=650, scrolling=True)
        else:
            st.warning(
                "No encontré el link/HTML de Mercado Pago para este plan.\n\n"
                "Solución rápida: cargá en Streamlit Secrets las URLs:\n"
                "MP_PACK_50_M_URL, MP_PACK_150_M_URL, MP_PACK_300_M_URL, MP_PACK_500_M_URL\n"
                "y (si usás anual) MP_PACK_50_A_URL, etc."
            )

    st.write("")
    if st.button("Cambiar de plan", use_container_width=False):
        st.session_state.pop("mp_plan", None)
        st.session_state.pop("mp_is_annual", None)
        st.rerun()
