import os
import base64
import tempfile
import subprocess
import requests
import xml.etree.ElementTree as ET
from afip_utils import afip_time_now, afip_time_fmt

AFIP_ENV = os.getenv("AFIP_ENV", "prod")

WSAA_URL = {
    "prod": "https://wsaa.afip.gov.ar/ws/services/LoginCms",
    "homo": "https://wsaahomo.afip.gov.ar/ws/services/LoginCms",
}

def wsaa_login(service: str):
    cert_b64 = os.getenv("AFIP_CERT_B64")
    key_b64 = os.getenv("AFIP_KEY_B64")

    if not cert_b64 or not key_b64:
        raise RuntimeError("Faltan AFIP_CERT_B64 o AFIP_KEY_B64")

    cert = base64.b64decode(cert_b64)
    key = base64.b64decode(key_b64)

    now = afip_time_now()
    tra = f"""
    <loginTicketRequest version="1.0">
      <header>
        <uniqueId>{int(now.timestamp())}</uniqueId>
        <generationTime>{afip_time_fmt(now)}</generationTime>
        <expirationTime>{afip_time_fmt(now)}</expirationTime>
      </header>
      <service>{service}</service>
    </loginTicketRequest>
    """.strip()

    with tempfile.NamedTemporaryFile(delete=False) as tra_f, \
         tempfile.NamedTemporaryFile(delete=False) as cert_f, \
         tempfile.NamedTemporaryFile(delete=False) as key_f, \
         tempfile.NamedTemporaryFile(delete=False) as cms_f:

        tra_f.write(tra.encode())
        cert_f.write(cert)
        key_f.write(key)

    subprocess.run([
        "openssl", "smime", "-sign",
        "-signer", cert_f.name,
        "-inkey", key_f.name,
        "-outform", "DER",
        "-nodetach",
        "-in", tra_f.name,
        "-out", cms_f.name
    ], check=True)

    cms = base64.b64encode(open(cms_f.name, "rb").read()).decode()

    r = requests.post(
        WSAA_URL[AFIP_ENV],
        data=cms,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30
    )
    r.raise_for_status()

    xml = ET.fromstring(r.text)
    token = xml.findtext(".//token")
    sign = xml.findtext(".//sign")

    if not token or not sign:
        raise RuntimeError("WSAA no devolvió token/sign")

    return token, sign
