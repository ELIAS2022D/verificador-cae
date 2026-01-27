import streamlit as st

st.set_page_config(
    page_title="Planes | Verificador CAE",
    layout="wide",
)

# ===================== HEADER =====================
st.markdown(
    """
    <h1 style='text-align:center;'>Elegí el plan ideal para tu negocio</h1>
    <p style='text-align:center; color: #6b7280;'>
        Planes mensuales y anuales. Validación oficial AFIP.
    </p>
    """,
    unsafe_allow_html=True,
)

st.divider()

# ===================== TOGGLE MENSUAL / ANUAL =====================
col_toggle_1, col_toggle_2, col_toggle_3 = st.columns([3, 2, 3])
with col_toggle_2:
    anual = st.toggle("Planes anuales (Ahorrá 25%)", value=False)

st.divider()

# ===================== PRICES =====================
def precio(mensual, anual):
    return anual if anual else mensual

# ===================== PLANS =====================
c1, c2, c3, c4 = st.columns(4)

with c1:
    st.subheader("Pack 50")
    st.markdown(f"## ${precio(12041, 9031):,}".replace(",", "."))
    st.caption("+ IVA / mes")
    st.write("✔ 50 comprobantes / mes")
    st.write("✔ 3 usuarios")
    st.write("✔ Soporte AFIP")
    st.write("✔ Reportes + Libro IVA")
    st.button(
        "Comprar",
        use_container_width=True,
        key="buy_50",
        on_click=lambda: st.session_state.update(
            {"mp_plan": "pack_50"}
        ),
    )

with c2:
    st.subheader("Pack 150")
    st.markdown(f"## ${precio(24423, 18317):,}".replace(",", "."))
    st.caption("+ IVA / mes")
    st.write("✔ 150 comprobantes / mes")
    st.write("✔ Usuarios ilimitados")
    st.write("✔ Soporte email y teléfono")
    st.write("✔ Integraciones e-commerce")
    st.button(
        "Comprar",
        use_container_width=True,
        key="buy_150",
        on_click=lambda: st.session_state.update(
            {"mp_plan": "pack_150"}
        ),
    )

with c3:
    st.subheader("Pack 300 ⭐")
    st.markdown(f"## ${precio(32987, 24740):,}".replace(",", "."))
    st.caption("+ IVA / mes")
    st.write("✔ 300 comprobantes / mes")
    st.write("✔ Usuarios ilimitados")
    st.write("✔ Prioridad en soporte")
    st.write("✔ Facturación masiva")
    st.button(
        "Comprar",
        use_container_width=True,
        key="buy_300",
        on_click=lambda: st.session_state.update(
            {"mp_plan": "pack_300"}
        ),
    )

with c4:
    st.subheader("Pack 500")
    st.markdown(f"## ${precio(40614, 30460):,}".replace(",", "."))
    st.caption("+ IVA / mes")
    st.write("✔ 500 comprobantes / mes")
    st.write("✔ Usuarios ilimitados")
    st.write("✔ Soporte dedicado")
    st.write("✔ Integración API")
    st.button(
        "Comprar",
        use_container_width=True,
        key="buy_500",
        on_click=lambda: st.session_state.update(
            {"mp_plan": "pack_500"}
        ),
    )

st.divider()

# ===================== MERCADO PAGO =====================
if "mp_plan" in st.session_state:
    st.success(f"Plan seleccionado: {st.session_state['mp_plan']}")

    st.markdown(
        """
        ### Continuar con el pago
        Serás redirigido a Mercado Pago para finalizar la compra.
        """
    )

    # 👇 ACÁ enchufás TU código ya funcional de Mercado Pago
    # ejemplo:
    # st.components.v1.html(mp_checkout_html, height=600)

    st.info("Integración Mercado Pago lista. Conectando checkout…")
