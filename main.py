import os
import re
import secrets
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

import requests
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")   # evita UnicodeEncodeError con ✅/⚠️/❌ en consolas no UTF-8

script_dir = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(script_dir, ".env")
if os.path.exists(env_path):
    with open(env_path, encoding="utf-8") as f:
        for linea in f:
            if "=" in linea and not linea.strip().startswith("#"):
                k, v = linea.split("=", 1)
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and not os.environ.get(k):
                    os.environ[k] = v

CORREOS_URL = os.getenv("CORREOS_SUPABASE_URL") or os.getenv("SUPABASE_URL", "")   # base donde caen los correos (solo lectura)
CORREOS_KEY = os.getenv("CORREOS_SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
API_KEY = os.getenv("CODIGOS2FA_API_KEY", "")
SIN_CLAVE = os.getenv("CODIGOS2FA_SIN_CLAVE", "false").strip().lower() in ("true", "1", "yes", "t")

SONDEO_S = 3
VENTANA_S = 600   # solo se miran correos de los últimos 10 min
ESPERA_DEFECTO_S = 270
ESPERA_MAXIMA_S = 300
MAX_FALLOS_BASE = 3
PATRON_CORREO = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")

# Una entrada por aseguradora con 2FA por correo: quién lo manda y cómo se ve el código.
REGLAS: Dict[str, dict] = {
    "allianz": {
        "remitente": "secure.token@allianz.com.mx",
        "patron": re.compile(r"minutos:(?:\s|&nbsp;)*(\d{5})", re.I),
    },
}

if not CORREOS_URL or not CORREOS_KEY:
    raise RuntimeError("Faltan CORREOS_SUPABASE_URL / CORREOS_SUPABASE_SERVICE_ROLE_KEY (o SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).")
if not API_KEY and not SIN_CLAVE:
    raise RuntimeError("Falta CODIGOS2FA_API_KEY. Solo para pruebas locales se puede arrancar sin clave con CODIGOS2FA_SIN_CLAVE=true.")

app = FastAPI(title="Códigos 2FA")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# =============================================================================
# HELPERS
# =============================================================================
def ahora_utc() -> datetime:
    return datetime.now(timezone.utc)


def escapar_like(valor: str) -> str:
    return re.sub(r"([\\%_])", r"\\\1", valor)


def enmascarar_correo(correo: str) -> str:
    usuario, _, dominio = correo.partition("@")
    return f"{usuario[:2]}***@{dominio}"


def verificar_clave(x_api_key: Optional[str]) -> None:
    if SIN_CLAVE and not API_KEY:
        return
    if not x_api_key or not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="Clave inválida o ausente en la cabecera X-API-Key.")


def regla_de(aseguradora: str) -> dict:
    regla = REGLAS.get(aseguradora.strip().lower())
    if regla is None:
        raise HTTPException(status_code=404, detail=f"Aseguradora sin reglas de 2FA: {aseguradora!r}. Disponibles: {', '.join(sorted(REGLAS))}.")
    return regla


def validar_destinatario(destinatario: str) -> str:
    destinatario = destinatario.strip()
    if not PATRON_CORREO.fullmatch(destinatario):
        raise HTTPException(status_code=422, detail="El destinatario no parece un correo (usuario@dominio).")
    return destinatario


def validar_linea_base(linea_base: Optional[str]) -> Optional[str]:
    if linea_base is None:
        return None
    try:
        datetime.fromisoformat(linea_base)
    except ValueError:
        raise HTTPException(status_code=422, detail="linea_base no es una fecha ISO válida (usa la que devolvió /api/linea-base).")
    return linea_base


def inicio_ventana(linea_base: Optional[str]) -> datetime:
    inicio = ahora_utc() - timedelta(seconds=VENTANA_S)
    return max(inicio, datetime.fromisoformat(linea_base)) if linea_base else inicio


def consultar_correos(remitente: str, destinatario: str, desde: datetime, columnas: str, limite: int) -> list:
    params = {
        "select": columnas,
        "metadata->>from": f"eq.{remitente}",
        "metadata->>to": f"ilike.*{escapar_like(destinatario)}*",
        "created_at": f"gt.{desde.isoformat()}",
        "order": "created_at.desc",
        "limit": str(limite),
    }
    headers = {"apikey": CORREOS_KEY, "Authorization": f"Bearer {CORREOS_KEY}"}
    r = requests.get(f"{CORREOS_URL.rstrip('/')}/rest/v1/conversation_messages", headers=headers, params=params, timeout=15)
    if r.status_code >= 400:
        raise RuntimeError(f"Supabase respondió HTTP {r.status_code}: {r.text[:200]}")
    return r.json()


# =============================================================================
# ENDPOINTS
# =============================================================================
class LineaBaseRequest(BaseModel):
    aseguradora: str = Field(examples=["allianz"])
    destinatario: str = Field(description="Correo del buzón al que la aseguradora manda el código.")


class EsperarCodigoRequest(BaseModel):
    aseguradora: str = Field(examples=["allianz"])
    destinatario: str = Field(description="Correo del buzón al que la aseguradora manda el código.")
    linea_base: Optional[str] = Field(default=None, description="Valor devuelto por /api/linea-base, leído ANTES de pedir el código al portal.")
    espera_s: Optional[int] = Field(default=None, ge=1, le=ESPERA_MAXIMA_S, description=f"Segundos máximos de espera (por defecto {ESPERA_DEFECTO_S}).")


@app.post("/api/linea-base")
def linea_base_endpoint(solicitud: LineaBaseRequest, x_api_key: Optional[str] = Header(default=None)):
    verificar_clave(x_api_key)
    regla = regla_de(solicitud.aseguradora)
    destinatario = validar_destinatario(solicitud.destinatario)
    try:
        filas = consultar_correos(regla["remitente"], destinatario, inicio_ventana(None), "created_at", 1)
    except (requests.RequestException, RuntimeError) as e:
        raise HTTPException(status_code=502, detail=f"No se pudo leer la base de correos: {e}")
    linea_base = filas[0]["created_at"] if filas else None
    print(f"[linea-base] {solicitud.aseguradora} -> {enmascarar_correo(destinatario)}: {linea_base or 'sin correos recientes'}")
    return {"linea_base": linea_base}


@app.post("/api/esperar-codigo")
def esperar_codigo_endpoint(solicitud: EsperarCodigoRequest, x_api_key: Optional[str] = Header(default=None)):
    verificar_clave(x_api_key)
    regla = regla_de(solicitud.aseguradora)
    destinatario = validar_destinatario(solicitud.destinatario)
    linea_base = validar_linea_base(solicitud.linea_base)
    espera_s = solicitud.espera_s or ESPERA_DEFECTO_S
    etiqueta = f"{solicitud.aseguradora} -> {enmascarar_correo(destinatario)}"
    inicio = time.monotonic()
    fin = inicio + espera_s
    fallos = 0
    while time.monotonic() < fin:
        try:
            filas = consultar_correos(regla["remitente"], destinatario, inicio_ventana(linea_base), "created_at,content,html:metadata->>html_body", 5)
            fallos = 0
        except (requests.RequestException, RuntimeError) as e:
            fallos += 1
            print(f"[esperar-codigo] {etiqueta}: falló la lectura de la base ({fallos}/{MAX_FALLOS_BASE}): {e}")
            if fallos >= MAX_FALLOS_BASE:
                raise HTTPException(status_code=502, detail=f"La base de correos no respondió tras {fallos} intentos seguidos: {e}")
            time.sleep(SONDEO_S)
            continue
        for fila in filas:
            for texto in (fila.get("content"), fila.get("html")):
                m = regla["patron"].search(texto or "")
                if m:
                    segundos = int(time.monotonic() - inicio)
                    print(f"[esperar-codigo] {etiqueta}: código recibido tras {segundos} s")
                    return {"codigo": m.group(1), "recibido_en": fila["created_at"], "segundos": segundos}
        time.sleep(SONDEO_S)
    print(f"[esperar-codigo] {etiqueta}: no llegó en {espera_s} s")
    raise HTTPException(status_code=408, detail=f"No llegó ningún correo de {regla['remitente']} para {enmascarar_correo(destinatario)} con código en {espera_s} s.")


@app.get("/health")
def health():
    return {"status": "ok", "service": "Códigos 2FA", "aseguradoras": sorted(REGLAS)}
