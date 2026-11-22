#!/usr/bin/env python3
"""
adb_triage.py - Triage forense de un celular Android por ADB, con acta automática.

Qué hace (siempre con comandos de SOLO LECTURA, ver COMANDOS_PERMITIDOS):
  1. Identifica el equipo: fabricante, modelo, Android, parche de seguridad, huella del build,
     cifrado, estado del bootloader y zona horaria.
  2. Registra el estado al momento de la extracción: batería, modo avión y la DIFERENCIA ENTRE
     EL RELOJ DEL TELÉFONO Y EL DE LA PC (clave para la línea de tiempo).
  3. Lista las apps instaladas con versión e instalador, y marca las de interés pericial
     (mensajería, billeteras y bancos, acceso remoto, VPN, ocultamiento de archivos).
  4. Opcional (--extraer): copia carpetas del almacenamiento compartido (/sdcard) y verifica
     la copia: el SHA-256 se calcula DENTRO del teléfono y otra vez en la PC; tienen que coincidir.
  5. Genera el acta (acta.md) con todo lo anterior y el registro de cada comando ejecutado:
     hora UTC, código de salida y SHA-256 de su salida, que queda guardada en raw/.

Uso:
  python adb_triage.py -o extraccion_01 --causa "Expte. 1234/2026" --perito "Nombre Apellido"
  python adb_triage.py -o extraccion_01 --extraer /sdcard/DCIM /sdcard/Download
  python adb_triage.py --listar                     # ver dispositivos conectados

Requisitos: Android platform-tools (adb) en el PATH o indicado con --adb, y la depuración USB
habilitada y autorizada en el teléfono. Probalo solo con TU teléfono o con autorización.
"""
import argparse
import csv
import hashlib
import json
import os
import platform
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0"

# Prefijos de comando que la herramienta puede ejecutar. Todo lo demás se rechaza: así es imposible
# que un error de programación instale, desinstale o cambie algo en el teléfono.
COMANDOS_PERMITIDOS = (
    ("devices",), ("version",), ("get-state",), ("pull", "-a"),
    ("shell", "getprop"), ("shell", "date"), ("shell", "dumpsys", "battery"),
    ("shell", "settings", "get"), ("shell", "pm", "list", "packages"),
    ("shell", "find"), ("shell", "id"),
)

PROPIEDADES = {
    "fabricante": "ro.product.manufacturer", "marca": "ro.product.brand", "modelo": "ro.product.model",
    "dispositivo": "ro.product.device", "android": "ro.build.version.release", "sdk": "ro.build.version.sdk",
    "parche_seguridad": "ro.build.version.security_patch", "build": "ro.build.display.id",
    "huella_build": "ro.build.fingerprint", "numero_serie": "ro.serialno",
    "zona_horaria": "persist.sys.timezone", "cifrado": "ro.crypto.state", "tipo_cifrado": "ro.crypto.type",
    "verified_boot": "ro.boot.verifiedbootstate", "bootloader_bloqueado": "ro.boot.flash.locked",
}

# Apps de interés pericial por nombre de paquete (lista orientativa, se completa en cada caso)
CATEGORIAS = {
    "Mensajería": ["com.whatsapp", "com.whatsapp.w4b", "org.telegram.messenger", "org.thoughtcrime.securesms",
                   "com.facebook.orca", "com.instagram.android", "com.discord", "com.viber.voip",
                   "com.snapchat.android", "com.google.android.apps.messaging"],
    "Billeteras / bancos": ["com.mercadopago.wallet", "ar.com.uala", "com.brubank", "com.naranjax.app",
                            "ar.com.bancogalicia", "com.santander.app", "ar.bapro", "com.bbva.nxt_argentina",
                            "com.lemoncash.lemon", "com.binance.dev", "io.metamask"],
    "Acceso remoto": ["com.anydesk.anydeskandroid", "com.teamviewer.quicksupport.market",
                      "com.teamviewer.teamviewer.market.mobile", "com.rustdesk.rustdesk"],
    "VPN / anonimato": ["org.torproject.torbrowser", "com.nordvpn.android", "com.protonvpn.android",
                        "free.vpn.unblock.proxy.turbovpn", "com.psiphon3"],
    "Ocultamiento / borrado": ["com.domobile.applockwatcher", "com.calculator.hide.photo.video",
                               "com.thinkyeah.galleryvault", "com.keepsafe.calculator", "com.shredder.app"],
}


class ErrorADB(Exception):
    pass


class Sesion:
    """Ejecuta adb, controla la lista blanca y deja registro de todo."""

    def __init__(self, adb, serial, carpeta, timeout=120):
        if isinstance(adb, str):
            # En Windows shlex en modo no-POSIX respeta las "\" de las rutas pero deja las comillas
            # pegadas: se quitan para que "C:\Program Files\...\adb.exe" funcione.
            partes = shlex.split(adb, posix=(os.name != "nt"))
            self.adb = [x[1:-1] if len(x) > 1 and x[0] == x[-1] and x[0] in "\"'" else x for x in partes]
        else:
            self.adb = list(adb)
        self.serial, self.carpeta, self.timeout = serial, carpeta, timeout
        self.registro = []
        if carpeta:
            (carpeta / "raw").mkdir(parents=True, exist_ok=True)

    def correr(self, *args, permitir_error=False):
        if not any(args[:len(p)] == p for p in COMANDOS_PERMITIDOS):
            raise ErrorADB(f"comando no permitido (no es de solo lectura): adb {' '.join(args)}")
        resto = list(args)
        if args[0] == "shell":
            # adb junta los argumentos y el shell DEL TELÉFONO los vuelve a interpretar: sin comillas,
            # el "|" de "stat -c %Y|%s|%n" se tomaría como una tubería. Se cita cada argumento.
            resto = ["shell", " ".join(shlex.quote(x) for x in args[1:])]
        cmd = self.adb + (["-s", self.serial] if self.serial and args[0] != "devices" else []) + resto
        inicio = datetime.now(timezone.utc)
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=self.timeout)
        except FileNotFoundError:
            raise ErrorADB(f"no se encontró adb ({self.adb[0]}). Instalá Android platform-tools o usá --adb")
        except subprocess.TimeoutExpired:
            raise ErrorADB(f"adb {' '.join(args)} no respondió en {self.timeout} s")
        salida = p.stdout.decode("utf-8", "replace").replace("\r\n", "\n")
        n = len(self.registro) + 1
        texto_cmd = "adb " + " ".join(args)
        if self.carpeta:  # en el acta, la carpeta de destino como referencia relativa
            texto_cmd = texto_cmd.replace(str(self.carpeta), "<carpeta de extracción>")
        entrada = {"n": n, "utc": inicio.isoformat(timespec="seconds"), "comando": texto_cmd,
                   "codigo": p.returncode, "sha256_salida": hashlib.sha256(p.stdout).hexdigest(),
                   "bytes_salida": len(p.stdout)}
        self.registro.append(entrada)
        if self.carpeta:
            nombre = re.sub(r"[^A-Za-z0-9_.-]+", "-", f"{n:02d}_{'_'.join(args[:3])}").strip("-")
            (self.carpeta / "raw" / f"{nombre}.txt").write_bytes(p.stdout + (b"\n--- stderr ---\n" + p.stderr if p.stderr else b""))
        if p.returncode != 0 and not permitir_error:
            raise ErrorADB(f"adb {' '.join(args)} terminó con código {p.returncode}: "
                           f"{p.stderr.decode('utf-8', 'replace').strip()[:300]}")
        return salida


# ----------------------------------------------------------------------------- pasos

def listar_dispositivos(s):
    disp = []
    for linea in s.correr("devices", "-l").splitlines()[1:]:
        partes = linea.split()
        if len(partes) >= 2:
            extra = dict(p.split(":", 1) for p in partes[2:] if ":" in p)
            disp.append({"serial": partes[0], "estado": partes[1], **extra})
    return disp


def elegir_dispositivo(s, serial):
    disp = listar_dispositivos(s)
    if serial:
        disp = [d for d in disp if d["serial"] == serial]
    if not disp:
        raise ErrorADB("no hay ningún dispositivo conectado (revisá el cable y que la depuración USB esté activa)")
    if len(disp) > 1:
        raise ErrorADB("hay más de un dispositivo: elegí uno con --serial " + " / ".join(d["serial"] for d in disp))
    d = disp[0]
    if d["estado"] == "unauthorized":
        raise ErrorADB("el teléfono no autorizó esta PC: desbloquealo y aceptá el aviso de depuración USB "
                       "(anotalo en el acta: es una interacción con el equipo)")
    if d["estado"] != "device":
        raise ErrorADB(f"el dispositivo está en estado '{d['estado']}'")
    return d


def leer_propiedades(s):
    props = {}
    for linea in s.correr("shell", "getprop").splitlines():
        if linea.startswith("[") and "]: [" in linea:
            k, v = linea[1:].split("]: [", 1)
            props[k] = v.rstrip("]")
    return props


def estado_al_extraer(s):
    antes = time.time()
    salida = s.correr("shell", "date", "+%s").strip()
    despues = time.time()
    try:
        reloj_tel = int(salida)
        desfase = reloj_tel - round((antes + despues) / 2)
    except ValueError:
        reloj_tel, desfase = None, None
    bateria = {}
    for linea in s.correr("shell", "dumpsys", "battery", permitir_error=True).splitlines():
        if ":" in linea:
            k, v = linea.split(":", 1)
            bateria[k.strip()] = v.strip()
    avion = s.correr("shell", "settings", "get", "global", "airplane_mode_on", permitir_error=True).strip()
    return {
        "hora_pc_utc": datetime.fromtimestamp(antes, timezone.utc).isoformat(timespec="seconds"),
        "hora_telefono_utc": datetime.fromtimestamp(reloj_tel, timezone.utc).isoformat(timespec="seconds")
        if reloj_tel else "no disponible",
        "desfase_reloj_s": desfase,
        "bateria_pct": bateria.get("level", "?"),
        "cargando": "sí" if bateria.get("USB powered") == "true" or bateria.get("AC powered") == "true" else "no",
        "modo_avion": {"1": "activado", "0": "DESACTIVADO"}.get(avion, avion or "?"),
    }


def listar_apps(s):
    salida = s.correr("shell", "pm", "list", "packages", "-f", "-i", "--show-versioncode", permitir_error=True)
    if "Unknown option" in salida or not salida.strip():  # Android viejo: sin versión
        salida = s.correr("shell", "pm", "list", "packages", "-f", "-i")
    terceros = {l.split(":", 1)[1].strip() for l in s.correr("shell", "pm", "list", "packages", "-3").splitlines()
                if l.startswith("package:")}
    por_paquete = {p: cat for cat, lista in CATEGORIAS.items() for p in lista}
    apps = []
    for linea in salida.splitlines():
        if not linea.startswith("package:"):
            continue
        resto = linea[len("package:"):]
        campos = {}
        for clave in (" installer=", " versionCode:", " uid:"):
            if clave in resto:
                resto, valor = resto.rsplit(clave, 1)
                campos[clave.strip(" =:")] = valor.strip()
        ruta, _, paquete = resto.rpartition("=")
        apps.append({"paquete": paquete, "version_code": campos.get("versionCode", ""),
                     "instalador": campos.get("installer", "") or "desconocido",
                     "origen": "usuario" if paquete in terceros else "sistema",
                     "categoria": por_paquete.get(paquete, ""), "apk": ruta})
    apps.sort(key=lambda a: (a["origen"] != "usuario", a["categoria"] == "", a["paquete"]))
    return apps


def hashes_en_telefono(s, ruta):
    """SHA-256 calculado por el propio teléfono (toybox sha256sum, Android 7+), con fecha y tamaño."""
    hashes = {}
    for linea in s.correr("shell", "find", ruta, "-type", "f", "-exec", "sha256sum", "{}", "+").splitlines():
        if len(linea) > 66 and linea[64:66] == "  ":
            hashes[linea[66:]] = linea[:64]
    datos = {}
    for linea in s.correr("shell", "find", ruta, "-type", "f", "-exec", "stat", "-c", "%Y|%s|%n", "{}", "+").splitlines():
        partes = linea.split("|", 2)
        if len(partes) == 3 and partes[0].isdigit():
            datos[partes[2]] = (int(partes[0]), int(partes[1]))
    return {r: {"sha256": h, "mtime": datos.get(r, (None, None))[0], "tamano": datos.get(r, (None, None))[1]}
            for r, h in hashes.items()}


def sha256_archivo(ruta):
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        while b := f.read(1 << 20):
            h.update(b)
    return h.hexdigest()


def extraer(s, rutas, carpeta):
    destino = carpeta / "archivos"
    destino.mkdir(exist_ok=True)
    resultado = []
    for ruta in rutas:
        ruta = ruta.rstrip("/")
        en_tel = hashes_en_telefono(s, ruta)
        s.correr("pull", "-a", ruta, str(destino))  # -a conserva fecha de modificación
        base = ruta.rsplit("/", 1)[0]
        for remoto, info in sorted(en_tel.items()):
            local = destino / remoto[len(base):].lstrip("/")
            local_hash = sha256_archivo(local) if local.is_file() else None
            resultado.append({"remoto": remoto, "local": local.relative_to(carpeta).as_posix(),
                              "tamano": info["tamano"], "mtime": info["mtime"],
                              "sha256_telefono": info["sha256"], "sha256_copia": local_hash or "FALTA",
                              "coincide": local_hash == info["sha256"]})
    return resultado


# ----------------------------------------------------------------------------- acta

def fmt_ts(ts):
    if ts is None:
        return "—"
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%d/%m/%Y %H:%M:%S UTC")


def sistema_operativo():
    nombre, version = platform.system(), platform.release()
    if nombre == "Windows":  # Python informa "10" también en Windows 11: se distingue por el build
        try:
            if int(platform.version().split(".")[2]) >= 22000:
                version = "11"
        except (IndexError, ValueError):
            pass
    return f"{nombre} {version} ({platform.version()})"


def escribir_lf(ruta, texto):
    Path(ruta).write_bytes(texto.encode("utf-8"))


def generar_acta(carpeta, a, disp, info, estado, apps, archivos, registro):
    md = lambda x: str(x).replace("|", "\\|").replace("\n", " ")  # los datos vienen del teléfono
    interes = [x for x in apps if x["categoria"]]
    usuario = [x for x in apps if x["origen"] == "usuario"]
    fuera_tienda = [x for x in usuario if x["instalador"] in ("desconocido", "null", "")]
    desf = estado["desfase_reloj_s"]
    l = [
        "# Acta de extracción lógica — dispositivo Android", "",
        f"**Causa:** {md(a.causa)}  ",
        f"**Perito / operador:** {md(a.perito)}  ",
        f"**Fecha y hora de inicio (PC, UTC):** {estado['hora_pc_utc']}  ",
        f"**Herramienta:** adb_triage.py v{VERSION} · Python {platform.python_version()} · "
        f"{md(a.adb_version)}  ",
        f"**Equipo de trabajo:** {sistema_operativo()} (su reloj debe estar sincronizado por NTP)", "",
        "## 1. Identificación del dispositivo", "",
        "| Dato | Valor |", "|---|---|",
    ]
    for etiqueta, clave in (("Fabricante / marca", None), ("Modelo", "modelo"), ("Nombre de dispositivo", "dispositivo"),
                            ("Número de serie (ADB)", None), ("Número de serie (ro.serialno)", "numero_serie"),
                            ("Android / SDK", None), ("Parche de seguridad", "parche_seguridad"),
                            ("Build", "build"), ("Huella del build", "huella_build"),
                            ("Zona horaria configurada", "zona_horaria"), ("Cifrado", None),
                            ("Verified boot / bootloader bloqueado", None)):
        if etiqueta == "Fabricante / marca":
            valor = f"{info['fabricante']} / {info['marca']}"
        elif etiqueta == "Número de serie (ADB)":
            valor = disp["serial"]
        elif etiqueta == "Android / SDK":
            valor = f"{info['android']} / {info['sdk']}"
        elif etiqueta == "Cifrado":
            valor = f"{info['cifrado']} ({info['tipo_cifrado']})" if info["tipo_cifrado"] else info["cifrado"]
        elif etiqueta.startswith("Verified"):
            bloqueado = {"1": "sí", "0": "NO (desbloqueado: el sistema pudo ser modificado)"}.get(
                info["bootloader_bloqueado"], info["bootloader_bloqueado"] or "—")
            valor = f"{info['verified_boot'] or '—'} / {bloqueado}"
        else:
            valor = info[clave]
        l.append(f"| {etiqueta} | {md(valor or '—')} |")

    l += ["", "## 2. Estado del equipo al momento de la extracción", "",
          "| Dato | Valor |", "|---|---|",
          f"| Hora del teléfono (UTC) | {estado['hora_telefono_utc']} |",
          f"| Hora de la PC (UTC) | {estado['hora_pc_utc']} |",
          f"| **Desfase del reloj del teléfono** | **{desf:+d} s** |" if desf is not None else "| Desfase del reloj | no disponible |",
          f"| Batería | {estado['bateria_pct']} % (cargando: {estado['cargando']}) |",
          f"| Modo avión | {estado['modo_avion']} |", ""]
    if desf is not None and abs(desf) > 60:
        sentido = "atrasado" if desf < 0 else "adelantado"
        l.append(f"> **Atención:** el reloj del teléfono está {abs(desf)} s {sentido} respecto de la PC. Las fechas "
                 "que registra el propio equipo (fotos, archivos, logs) pueden arrastrar este error y se corrigen "
                 "en la línea de tiempo. Los mensajes con hora del servidor (p. ej. WhatsApp) no siempre lo tienen.\n")
    if estado["modo_avion"] == "DESACTIVADO":
        l.append("> **Atención:** el modo avión estaba desactivado: el equipo podía recibir datos o un borrado "
                 "remoto durante la extracción. Corresponde aislarlo (modo avión o bolsa de Faraday).\n")
    l += ["Interacciones necesarias con el equipo (a completar por el operador): habilitar la depuración USB y "
          "autorizar esta PC. ADB guarda la clave pública de la PC en el teléfono; queda constancia aquí.", ""]

    l += ["## 3. Aplicaciones instaladas", "",
          f"Total: {len(apps)} paquetes ({len(usuario)} instaladas por el usuario, {len(apps) - len(usuario)} de sistema). "
          f"Listado completo: `apps.csv`.", ""]
    if interes:
        l += ["**De interés pericial:**", "", "| Categoría | Paquete | Versión | Instalador |", "|---|---|---|---|"]
        l += [f"| {md(x['categoria'])} | `{md(x['paquete'])}` | {md(x['version_code'])} | {md(x['instalador'])} |"
              for x in interes]
        l.append("")
    if fuera_tienda:
        l += [f"**Instaladas por el usuario sin tienda de origen registrada ({len(fuera_tienda)}):** "
              + ", ".join(f"`{md(x['paquete'])}`" for x in fuera_tienda)
              + ". Pueden ser APK instalados a mano: revisar.", ""]

    l += ["## 4. Archivos extraídos", ""]
    if archivos:
        ok = sum(x["coincide"] for x in archivos)
        l += [f"Se copiaron {len(archivos)} archivos de {', '.join(f'`{md(r)}`' for r in a.extraer)}. "
              f"El SHA-256 se calculó en el teléfono y luego sobre la copia: **{ok} de {len(archivos)} coinciden**.", "",
              "| Archivo en el teléfono | Tamaño | Modificado (teléfono) | SHA-256 | Copia |", "|---|---|---|---|---|"]
        for x in archivos:
            l.append(f"| `{md(x['remoto'])}` | {x['tamano'] or '—'} | {fmt_ts(x['mtime'])} | "
                     f"`{x['sha256_telefono']}` | {'OK' if x['coincide'] else '**NO COINCIDE**'} |")
        l.append("")
    else:
        l += ["No se extrajeron archivos (solo identificación y listado de apps).", ""]
    l += ["**Alcance:** extracción lógica por ADB. No incluye datos privados de las apps (`/data/data`), que "
          "requieren extracción de sistema de archivos o física con herramientas específicas.", ""]

    l += ["## 5. Registro de comandos", "",
          "Cada comando se ejecutó en este orden. Su salida completa está en `raw/` y su SHA-256 permite "
          "comprobar que no fue modificada.", "",
          "| # | Hora (UTC) | Comando | Código | SHA-256 de la salida |", "|---|---|---|---|---|"]
    l += [f"| {r['n']} | {r['utc']} | `{md(r['comando'])}` | {r['codigo']} | `{r['sha256_salida'][:16]}…` |"
          for r in registro]
    l += ["", "## 6. Cierre", "",
          f"Finalizado: {datetime.now(timezone.utc).isoformat(timespec='seconds')}. "
          "El SHA-256 de esta acta queda en `acta.md.sha256`.", "",
          "Firma del perito: ______________________     Testigos: ______________________", ""]
    texto = "\n".join(l)
    escribir_lf(carpeta / "acta.md", texto)
    h = hashlib.sha256(texto.encode("utf-8")).hexdigest()
    escribir_lf(carpeta / "acta.md.sha256", f"{h}  acta.md\n")
    return h


# ----------------------------------------------------------------------------- main

def main():
    for flujo in (sys.stdout, sys.stderr):  # la consola de Windows (cp1252) rompe los acentos
        if hasattr(flujo, "reconfigure"):
            flujo.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--salida", type=Path, help="carpeta de la extracción (no tiene que existir)")
    ap.add_argument("--adb", default="adb", help="ruta o comando de adb")
    ap.add_argument("--serial", help="serial del dispositivo si hay más de uno")
    ap.add_argument("--extraer", nargs="*", default=[], metavar="RUTA",
                    help="carpetas del teléfono a copiar (ej. /sdcard/DCIM /sdcard/Download)")
    ap.add_argument("--causa", default="(completar)")
    ap.add_argument("--perito", default="(completar)")
    ap.add_argument("--listar", action="store_true", help="solo listar dispositivos conectados")
    a = ap.parse_args()

    s = None
    try:
        if a.listar:
            s = Sesion(a.adb, None, None)
            for d in listar_dispositivos(s):
                print(f"{d['serial']:<20} {d['estado']:<14} {d.get('model', '')} {d.get('device', '')}")
            return
        if not a.salida:
            ap.error("falta -o/--salida")
        if a.salida.exists():
            sys.exit(f"{a.salida} ya existe: usá una carpeta nueva para cada extracción")
        for r in a.extraer:
            if not r.startswith(("/sdcard", "/storage/emulated")):
                sys.exit(f"{r}: solo se extrae del almacenamiento compartido (/sdcard)")

        s = Sesion(a.adb, None, a.salida)
        a.adb_version = (s.correr("version").splitlines() or ["adb (versión desconocida)"])[0]
        disp = elegir_dispositivo(s, a.serial)
        s.serial = disp["serial"]
        print(f"Dispositivo: {disp['serial']} ({disp.get('model', '?')})")

        props = leer_propiedades(s)
        info = {k: props.get(v, "") for k, v in PROPIEDADES.items()}
        print(f"  {info['fabricante']} {info['modelo']} · Android {info['android']} · parche {info['parche_seguridad']}")

        estado = estado_al_extraer(s)
        print(f"  Reloj del teléfono: {estado['desfase_reloj_s']:+d} s respecto de la PC · batería "
              f"{estado['bateria_pct']} % · modo avión {estado['modo_avion']}" if estado["desfase_reloj_s"] is not None
              else "  Reloj del teléfono: no disponible")

        apps = listar_apps(s)
        print(f"  {len(apps)} apps ({sum(x['origen'] == 'usuario' for x in apps)} del usuario, "
              f"{sum(bool(x['categoria']) for x in apps)} de interés pericial)")

        archivos = extraer(s, a.extraer, a.salida) if a.extraer else []
        if archivos:
            mal = [x for x in archivos if not x["coincide"]]
            print(f"  {len(archivos)} archivos copiados · hashes teléfono vs. copia: "
                  f"{'todos coinciden' if not mal else f'{len(mal)} NO coinciden'}")

        # salidas
        escribir_lf(a.salida / "dispositivo.json", json.dumps(
            {"adb": disp, "identificacion": info, "estado": estado, "propiedades": props}, ensure_ascii=False, indent=2))
        with open(a.salida / "apps.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["paquete", "version_code", "instalador", "origen", "categoria", "apk"])
            w.writeheader(); w.writerows(apps)
        if archivos:
            escribir_lf(a.salida / "manifiesto.sha256",
                        "".join(f"{x['sha256_copia']}  {x['local']}\n" for x in archivos if x["coincide"]))
        escribir_lf(a.salida / "comandos.log", "".join(
            f"{r['n']:02d} {r['utc']} codigo={r['codigo']} sha256={r['sha256_salida']} {r['comando']}\n" for r in s.registro))
        h = generar_acta(a.salida, a, disp, info, estado, apps, archivos, s.registro)
        print(f"\nActa: {a.salida / 'acta.md'}  (SHA-256 {h})")
        sys.exit(1 if any(not x["coincide"] for x in archivos) else 0)
    except ErrorADB as ex:
        if s is not None and s.carpeta and s.registro:
            # el intento fallido también se documenta: qué se ejecutó y qué devolvió
            escribir_lf(s.carpeta / "comandos.log", "".join(
                f"{r['n']:02d} {r['utc']} codigo={r['codigo']} sha256={r['sha256_salida']} {r['comando']}\n"
                for r in s.registro) + f"ERROR: {ex}\n")
            print(f"Registro del intento en {s.carpeta / 'comandos.log'}", file=sys.stderr)
        sys.exit(f"Error: {ex}")


if __name__ == "__main__":
    main()
