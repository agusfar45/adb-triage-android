# Acta de extracción lógica — dispositivo Android

**Causa:** Práctica — teléfono simulado (Caso 1 del laboratorio)  
**Perito / operador:** (nombre del perito)  
**Fecha y hora de inicio (PC, UTC):** 2026-11-22T01:49:46+00:00  
**Herramienta:** adb_triage.py v1.0 · Python 3.11.9 · Android Debug Bridge version 1.0.41 (SIMULADO para pruebas)  
**Equipo de trabajo:** Windows 11 (10.0.26200) (su reloj debe estar sincronizado por NTP)

## 1. Identificación del dispositivo

| Dato | Valor |
|---|---|
| Fabricante / marca | samsung / samsung |
| Modelo | SM-A546E |
| Nombre de dispositivo | a54x |
| Número de serie (ADB) | R58TA0FICT1 |
| Número de serie (ro.serialno) | R58TA0FICT1 |
| Android / SDK | 14 / 34 |
| Parche de seguridad | 2026-09-01 |
| Build | UP1A.231005.007.A546EXXS8CXI1 |
| Huella del build | samsung/a54xnsxx/a54x:14/UP1A.231005.007/A546EXXS8CXI1:user/release-keys |
| Zona horaria configurada | America/Argentina/Salta |
| Cifrado | encrypted (file) |
| Verified boot / bootloader bloqueado | green / sí |

## 2. Estado del equipo al momento de la extracción

| Dato | Valor |
|---|---|
| Hora del teléfono (UTC) | 2026-11-22T01:46:41+00:00 |
| Hora de la PC (UTC) | 2026-11-22T01:49:46+00:00 |
| **Desfase del reloj del teléfono** | **-186 s** |
| Batería | 63 % (cargando: sí) |
| Modo avión | DESACTIVADO |

> **Atención:** el reloj del teléfono está 186 s atrasado respecto de la PC. Las fechas que registra el propio equipo (fotos, archivos, logs) pueden arrastrar este error y se corrigen en la línea de tiempo. Los mensajes con hora del servidor (p. ej. WhatsApp) no siempre lo tienen.

> **Atención:** el modo avión estaba desactivado: el equipo podía recibir datos o un borrado remoto durante la extracción. Corresponde aislarlo (modo avión o bolsa de Faraday).

Interacciones necesarias con el equipo (a completar por el operador): habilitar la depuración USB y autorizar esta PC. ADB guarda la clave pública de la PC en el teléfono; queda constancia aquí.

## 3. Aplicaciones instaladas

Total: 8 paquetes (5 instaladas por el usuario, 3 de sistema). Listado completo: `apps.csv`.

**De interés pericial:**

| Categoría | Paquete | Versión | Instalador |
|---|---|---|---|
| Acceso remoto | `com.anydesk.anydeskandroid` | 8120 | null |
| Ocultamiento / borrado | `com.calculator.hide.photo.video` | 57 | null |
| Billeteras / bancos | `com.mercadopago.wallet` | 2614 | com.android.vending |
| Mensajería | `com.whatsapp` | 242210 | com.android.vending |
| Mensajería | `com.google.android.apps.messaging` | 190030 | null |

**Instaladas por el usuario sin tienda de origen registrada (2):** `com.anydesk.anydeskandroid`, `com.calculator.hide.photo.video`. Pueden ser APK instalados a mano: revisar.

## 4. Archivos extraídos

Se copiaron 4 archivos de `/sdcard/DCIM`, `/sdcard/Download`. El SHA-256 se calculó en el teléfono y luego sobre la copia: **4 de 4 coinciden**.

| Archivo en el teléfono | Tamaño | Modificado (teléfono) | SHA-256 | Copia |
|---|---|---|---|---|
| `/sdcard/DCIM/Camera/IMG_20261101_102233.jpg` | 15273 | 20/11/2026 18:29:18 UTC | `f56bd0fafe2624b222272d89c30c205de37446a4d30d993d7bc60afecdc4922c` | OK |
| `/sdcard/DCIM/Camera/IMG_20261104_130010.jpg` | 12973 | 20/11/2026 18:29:18 UTC | `dad8e131c8d183dab10c06e96f6f92ba4069b41973cdaeafd952121b2ec3b02b` | OK |
| `/sdcard/DCIM/Camera/IMG_20261106_181502.jpg` | 13992 | 20/11/2026 18:29:18 UTC | `561b40a15d01d491492a01fd30317542d3f048c5b56c1c2288756cf35c2015a5` | OK |
| `/sdcard/Download/recibo moto.pdf` | 11 | 22/11/2026 01:46:42 UTC | `a6b3e0ef2b6c597727c5f5d776c0714e7515d0d919ea4b5e8b83a698803dcdec` | OK |

**Alcance:** extracción lógica por ADB. No incluye datos privados de las apps (`/data/data`), que requieren extracción de sistema de archivos o física con herramientas específicas.

## 5. Registro de comandos

Cada comando se ejecutó en este orden. Su salida completa está en `raw/` y su SHA-256 permite comprobar que no fue modificada.

| # | Hora (UTC) | Comando | Código | SHA-256 de la salida |
|---|---|---|---|---|
| 1 | 2026-11-22T01:49:45+00:00 | `adb version` | 0 | `21bb3b8702c40f9a…` |
| 2 | 2026-11-22T01:49:46+00:00 | `adb devices -l` | 0 | `a5a082963a36a8cf…` |
| 3 | 2026-11-22T01:49:46+00:00 | `adb shell getprop` | 0 | `1a038543774829e0…` |
| 4 | 2026-11-22T01:49:46+00:00 | `adb shell date +%s` | 0 | `90cf9968d034f724…` |
| 5 | 2026-11-22T01:49:46+00:00 | `adb shell dumpsys battery` | 0 | `da1437ea79f7a3a3…` |
| 6 | 2026-11-22T01:49:46+00:00 | `adb shell settings get global airplane_mode_on` | 0 | `13bf7b3039c63bf5…` |
| 7 | 2026-11-22T01:49:47+00:00 | `adb shell pm list packages -f -i --show-versioncode` | 0 | `c625e949d349f50f…` |
| 8 | 2026-11-22T01:49:47+00:00 | `adb shell pm list packages -3` | 0 | `5854632613cbec3e…` |
| 9 | 2026-11-22T01:49:47+00:00 | `adb shell find /sdcard/DCIM -type f -exec sha256sum {} +` | 0 | `d95fcc8dcd36e7f3…` |
| 10 | 2026-11-22T01:49:47+00:00 | `adb shell find /sdcard/DCIM -type f -exec stat -c %Y\|%s\|%n {} +` | 0 | `b031971f7a8f1582…` |
| 11 | 2026-11-22T01:49:47+00:00 | `adb pull -a /sdcard/DCIM <carpeta de extracción>\archivos` | 0 | `2ebe8958fffe791c…` |
| 12 | 2026-11-22T01:49:48+00:00 | `adb shell find /sdcard/Download -type f -exec sha256sum {} +` | 0 | `54a9b68bdfbeae94…` |
| 13 | 2026-11-22T01:49:48+00:00 | `adb shell find /sdcard/Download -type f -exec stat -c %Y\|%s\|%n {} +` | 0 | `75921cc40f205b21…` |
| 14 | 2026-11-22T01:49:48+00:00 | `adb pull -a /sdcard/Download <carpeta de extracción>\archivos` | 0 | `6fe4c8e71960e032…` |

## 6. Cierre

Finalizado: 2026-11-22T01:49:48+00:00. El SHA-256 de esta acta queda en `acta.md.sha256`.

Firma del perito: ______________________     Testigos: ______________________
