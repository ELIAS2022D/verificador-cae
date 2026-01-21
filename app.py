import io
import zipfile
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

st.subheader("Carga de archivos")
mode = st.radio("Modo de carga", ["PDFs (hasta 20)", "ZIP (contiene PDFs)"], horizontal=True)

pdf_files = []  # lista de dicts: {"name": str, "bytes": bytes}

if mode == "PDFs (hasta 20)":
    uploaded = st.file_uploader("Subí hasta 20 facturas en PDF", type=["pdf"], accept_multiple_files=True)

    if uploaded:
        if len(uploaded) > 20:
            st.warning("Subiste más de 20. Para la demo, procesaré solo las primeras 20.")
            uploaded = uploaded[:20]

        pdf_files = [{"name": f.name, "bytes": f.getvalue()} for f in uploaded]

else:
    zip_up = st.file_uploader(
        "Subí 1 archivo ZIP (con PDFs adentro). Para la demo se procesan hasta 20 PDFs.",
        type=["zip"],
        accept_multiple_files=False
    )

    if zip_up:
        zip_bytes = zip_up.getvalue()

        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
                pdf_names = [
                    n for n in z.namelist()
                    if n.lower().endswith(".pdf") and not n.endswith("/")
                ]

                if not pdf_names:
                    st.error("El ZIP no contiene archivos .pdf.")
                else:
                    if len(pdf_names) > 20:
                        st.warning(f"El ZIP tiene {len(pdf_names)} PDFs. Para la demo, procesaré solo 20.")
                        pdf_names = pdf_names[:20]

                    for n in pdf_names:
                        pdf_files.append({
                            "name": n.split("/")[-1],   # nombre sin carpetas
                            "bytes": z.read(n)
                        })

                    st.success(f"ZIP cargado. PDFs detectados para procesar: {len(pdf_files)}")

        except zipfile.BadZipFile:
            st.error("El archivo ZIP está dañado o no es un ZIP válido.")
        except Exception as e:
            st.error(f"Error leyendo ZIP: {e}")

# ------------------------------ Procesamiento -----------------------------------------
if pdf_files:
    rows = []
    today = datetime.now().date()

    progress = st.progress(0)
    for i, f in enumerate(pdf_files, start=1):
        try:
            file_bytes = f["bytes"]

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
                "Archivo": f["name"],
                "CAE": cae or "",
                "Vto CAE": vto_date.strftime("%d/%m/%Y") if vto_date else "",
                "Estado": " | ".join(status),
            })

        except Exception as e:
            rows.append({
                "Archivo": f["name"],
                "CAE": "",
                "Vto CAE": "",
                "Estado": f"Error procesando PDF: {e}",
            })

        progress.progress(i / len(pdf_files))

    df = pd.DataFrame(rows)

    # ✅ Excel: forzar CAE como texto para evitar notación científica al abrir CSV
    df["CAE"] = df["CAE"].astype(str).apply(lambda x: f"'{x}" if x and x != "nan" else "")

    # ✅ Limpiar saltos de línea
    df["Estado"] = df["Estado"].astype(str).str.replace("\n", " ", regex=False).str.strip()

    st.subheader("Resultados")
    st.dataframe(df, use_container_width=True)

    # ✅ CSV compatible Excel AR: separador ; + UTF-8 con BOM (en bytes)
    csv_bytes = df.to_csv(index=False, sep=";", encoding="utf-8-sig").encode("utf-8-sig")

    col1, col2 = st.columns(2)

    with col1:
        st.download_button(
            "Descargar CSV (Excel)",
            data=csv_bytes,
            file_name="resultado_verificacion_cae_demo.csv",
            mime="text/csv",
        )

    # ✅ Excel real (.xlsx): evita cualquier problema de separadores/encoding
    with col2:
        xlsx_buffer = io.BytesIO()
        with pd.ExcelWriter(xlsx_buffer, engine="xlsxwriter") as writer:
            df.to_excel(writer, index=False, sheet_name="Resultados")
        st.download_button(
            "Descargar Excel (.xlsx)",
            data=xlsx_buffer.getvalue(),
            file_name="resultado_verificacion_cae_demo.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
