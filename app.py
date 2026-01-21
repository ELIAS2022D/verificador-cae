import io
import re
from datetime import datetime
import pandas as pd
import streamlit as st
import pdfplumber

# --------- Reglas de extracción (robustas para facturas argentinas) ----------
CAE_PATTERNS = [
    re.compile(r"\bCAE\b\D{0,30}(\d{14})\b", re.IGNORECASE),
    re.compile(r"\bC\.?A\.?E\.?\b\D{0,30}(\d{14})\b", re.IGNORECASE),
    re.compile(r"\bCAE\s*N[º°o]?\b\D{0,30}(\d{14})\b", re.IGNORECASE),
    re.compile(r"\bCAE\s*NRO\.?\b\D{0,30}(\d{14})\b", re.IGNORECASE),
]

# Abarca: "Vto. CAE", "Vto. de CAE", "Fecha de Vto. de CAE", etc.
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

def find_cae(text: str):
    for pat in CAE_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(1)
    # fallback: buscar cualquier 14 dígitos cerca de "CAE"
    idx = text.lower().find("cae")
    if idx != -1:
        window = text[idx: idx + 250]
        m2 = re.search(r"(\d{14})", window)
        if m2:
            return m2.group(1)
    return None

def find_vto(text: str):
    for pat in VTO_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(1)
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

# ------------------------------ UI -----------------------------------------
st.set_page_config(page_title="Verificador CAE", layout="wide")
st.title("Verificador de CAE")

st.info(
    "Esta demo extrae CAE y vencimiento desde PDF. "
    "La verificación 'real' contra AFIP (existencia/correspondencia) se integra en la siguiente fase."
)

uploaded = st.file_uploader("Subí hasta 20 facturas en PDF", type=["pdf"], accept_multiple_files=True)

if uploaded:
    if len(uploaded) > 20:
        st.warning("Subiste más de 20. Para la demo, procesaré solo las primeras 20.")
        uploaded = uploaded[:20]

    rows = []
    today = datetime.now().date()

    progress = st.progress(0)
    for i, f in enumerate(uploaded, start=1):
        try:
            file_bytes = f.getvalue()

            with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
                texts = []
                for page in pdf.pages[:5]:
                    texts.append(page.extract_text() or "")
                text = "\n".join(texts)

            cae = find_cae(text)
            vto_raw = find_vto(text)
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
            status.append("AFIP: Pendiente integración")

            rows.append({
                "Archivo": f.name,
                "CAE": cae or "",
                "Vto CAE": vto_date.strftime("%d/%m/%Y") if vto_date else "",
                "Estado": " | ".join(status),
            })

        except Exception as e:
            rows.append({
                "Archivo": f.name,
                "CAE": "",
                "Vto CAE": "",
                "Estado": f"Error procesando PDF: {e}",
            })

        progress.progress(i / len(uploaded))

    df = pd.DataFrame(rows)

    # ✅ Excel: evitar notación científica y mantener CAE como identificador
    df["CAE"] = df["CAE"].astype(str)

    st.subheader("Resultados")
    st.dataframe(df, use_container_width=True)

    # ✅ Excel AR: separador ; y encoding con BOM para acentos correctos
    csv_data = df.to_csv(index=False, sep=";", encoding="utf-8-sig")

    st.download_button(
        "Descargar CSV (Excel)",
        data=csv_data,
        file_name="resultado_verificacion_cae_demo.csv",
        mime="text/csv",
    )
