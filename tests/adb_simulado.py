#!/usr/bin/env python3
"""
adb_simulado.py - Imita a `adb` para probar adb_triage.py sin un teléfono conectado.

Simula el Samsung Galaxy A54 del Caso 1 de mi laboratorio forense. El almacenamiento /sdcard se
mapea a una carpeta local. Como el adb real, `shell` recibe UN texto que interpreta un shell
(acá: shlex), así que los argumentos mal citados fallan igual que en un teléfono.

Variables de entorno:
  ADB_SIM_SDCARD   carpeta local que hace de /sdcard (obligatoria para find/pull)
  ADB_SIM_MODO     normal | sin_dispositivo | no_autorizado | dos | corrupto
                   (corrupto: pull entrega un archivo alterado, para probar la verificación)
  ADB_SIM_DESFASE  segundos de diferencia del reloj del teléfono (default 0)
  ADB_SIM_AVION    1 o 0 (default 0)
  ADB_SIM_LOG      archivo donde se anota cada invocación (para auditar qué se ejecutó)
"""
import hashlib
import os
import shlex
import shutil
import sys
import time
from pathlib import Path

SERIAL = "R58TA0FICT1"
MODO = os.environ.get("ADB_SIM_MODO", "normal")
SDCARD = Path(os.environ.get("ADB_SIM_SDCARD", "."))

PROPS = {
    "ro.product.manufacturer": "samsung", "ro.product.brand": "samsung", "ro.product.model": "SM-A546E",
    "ro.product.device": "a54x", "ro.build.version.release": "14", "ro.build.version.sdk": "34",
    "ro.build.version.security_patch": "2026-09-01", "ro.build.display.id": "UP1A.231005.007.A546EXXS8CXI1",
    "ro.build.fingerprint": "samsung/a54xnsxx/a54x:14/UP1A.231005.007/A546EXXS8CXI1:user/release-keys",
    "ro.serialno": SERIAL, "persist.sys.timezone": "America/Argentina/Salta", "ro.crypto.state": "encrypted",
    "ro.crypto.type": "file", "ro.boot.verifiedbootstate": "green", "ro.boot.flash.locked": "1",
}
APPS = [  # (apk, paquete, versionCode, instalador, de_usuario)
    ("/system/app/SamsungCamera/SamsungCamera.apk", "com.sec.android.app.camera", "140500", "null", False),
    ("/system/priv-app/Settings/Settings.apk", "com.android.settings", "34", "null", False),
    ("/product/app/Messages/Messages.apk", "com.google.android.apps.messaging", "190030", "null", False),
    ("/data/app/~~a1/com.whatsapp-1/base.apk", "com.whatsapp", "242210", "com.android.vending", True),
    ("/data/app/~~b2/com.mercadopago.wallet-1/base.apk", "com.mercadopago.wallet", "2614", "com.android.vending", True),
    ("/data/app/~~c3/com.facebook.katana-1/base.apk", "com.facebook.katana", "4721", "com.android.vending", True),
    ("/data/app/~~d4/com.anydesk.anydeskandroid-1/base.apk", "com.anydesk.anydeskandroid", "8120", "null", True),
    ("/data/app/~~e5/com.calculator.hide.photo.video-1/base.apk", "com.calculator.hide.photo.video", "57", "null", True),
]


def log(args):
    if os.environ.get("ADB_SIM_LOG"):
        with open(os.environ["ADB_SIM_LOG"], "a", encoding="utf-8") as f:
            f.write(" ".join(args) + "\n")


def local(ruta_tel):
    if not ruta_tel.startswith("/sdcard"):
        sys.exit(f"find: '{ruta_tel}': Permission denied")
    return SDCARD / ruta_tel[len("/sdcard"):].lstrip("/")


def archivos(ruta_tel):
    base = local(ruta_tel)
    if not base.exists():
        sys.stderr.write(f"find: '{ruta_tel}': No such file or directory\n")
        sys.exit(1)
    for p in sorted(base.rglob("*")):
        if p.is_file():
            yield "/sdcard/" + p.relative_to(SDCARD).as_posix(), p


def shell(texto):
    a = shlex.split(texto)  # lo que haría el sh del teléfono
    if a == ["getprop"]:
        for k, v in sorted(PROPS.items()):
            print(f"[{k}]: [{v}]")
    elif a == ["date", "+%s"]:
        print(int(time.time()) + int(os.environ.get("ADB_SIM_DESFASE", "0")))
    elif a == ["dumpsys", "battery"]:
        print("Current Battery Service state:\n  AC powered: false\n  USB powered: true\n  level: 63\n  scale: 100")
    elif a == ["settings", "get", "global", "airplane_mode_on"]:
        print(os.environ.get("ADB_SIM_AVION", "0"))
    elif a[:3] == ["pm", "list", "packages"]:
        if "-3" in a:
            for _, p, _, _, usuario in APPS:
                if usuario:
                    print(f"package:{p}")
        else:
            for apk, p, v, inst, _ in APPS:
                print(f"package:{apk}={p} versionCode:{v} installer={inst}")
    elif a[0] == "find" and a[2:5] == ["-type", "f", "-exec"] and a[-2:] == ["{}", "+"]:
        if a[5] == "sha256sum":
            for tel, p in archivos(a[1]):
                print(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {tel}")
        elif a[5:8] == ["stat", "-c", "%Y|%s|%n"]:
            for tel, p in archivos(a[1]):
                print(f"{int(p.stat().st_mtime)}|{p.stat().st_size}|{tel}")
        else:
            sys.exit(f"/system/bin/sh: syntax error: {texto}")
    else:
        sys.stderr.write(f"/system/bin/sh: {a[0]}: inaccessible or not found ({texto})\n")
        sys.exit(127)


def main():
    args = sys.argv[1:]
    log(args)
    if args and args[0] == "-s":
        if args[1] != SERIAL:
            sys.exit(f"adb: device '{args[1]}' not found")
        args = args[2:]
    if args == ["version"]:
        print("Android Debug Bridge version 1.0.41 (SIMULADO para pruebas)")
    elif args[:1] == ["devices"]:
        print("List of devices attached")
        if MODO == "no_autorizado":
            print(f"{SERIAL}       unauthorized usb:1-1 transport_id:3")
        elif MODO == "dos":
            print(f"{SERIAL}       device usb:1-1 product:a54xnsxx model:SM_A546E device:a54x transport_id:3")
            print("emulator-5554  device product:sdk_gphone64 model:sdk_gphone64_x86_64 transport_id:4")
        elif MODO != "sin_dispositivo":
            print(f"{SERIAL}       device usb:1-1 product:a54xnsxx model:SM_A546E device:a54x transport_id:3")
        print()
    elif args[:1] == ["shell"] and len(args) == 2:
        shell(args[1])
    elif args[:2] == ["pull", "-a"] and len(args) == 4:
        origen, destino = local(args[2]), Path(args[3])
        copia = destino / origen.name
        shutil.copytree(origen, copia, dirs_exist_ok=True, copy_function=shutil.copy2)
        if MODO == "corrupto":  # simula una copia defectuosa
            primero = next(p for p in sorted(copia.rglob("*")) if p.is_file())
            primero.write_bytes(primero.read_bytes()[:-1] + b"X")
        n = sum(1 for p in copia.rglob("*") if p.is_file())
        print(f"{args[2]}/: {n} files pulled, 0 skipped.")
    else:
        sys.exit(f"adb: comando no simulado: {' '.join(args)}")


if __name__ == "__main__":
    main()
