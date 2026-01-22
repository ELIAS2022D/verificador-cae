import requests
from afip_wsaa import wsaa_login

WSCDC_URL = "https://serviciosjava.afip.gob.ar/wscdc/service.asmx"

def wsdc_consultar(cuit_emisor: str, tipo_cbte: int, pto_vta: int, nro_cbte: int):
    token, sign = wsaa_login("wsdc")

    soap = f"""
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Header/>
      <soap:Body>
        <consultarComprobante xmlns="http://ar.gov.afip.dif.facturaelectronica/">
          <authRequest>
            <token>{token}</token>
            <sign>{sign}</sign>
            <cuitRepresentada>{cuit_emisor}</cuitRepresentada>
          </authRequest>
          <comprobanteRequest>
            <cuitEmisor>{cuit_emisor}</cuitEmisor>
            <ptoVta>{pto_vta}</ptoVta>
            <tipoComprobante>{tipo_cbte}</tipoComprobante>
            <nroComprobante>{nro_cbte}</nroComprobante>
          </comprobanteRequest>
        </consultarComprobante>
      </soap:Body>
    </soap:Envelope>
    """.strip()

    r = requests.post(
        WSCDC_URL,
        data=soap,
        headers={"Content-Type": "text/xml; charset=utf-8"},
        timeout=30
    )
    r.raise_for_status()
    return r.text
