# adb_triage — triage forense de celulares Android con acta automática

Script en Python (solo librería estándar) que se conecta a un celular Android por **ADB**, lo identifica,
registra su estado, lista las apps, copia carpetas del almacenamiento y **verifica la copia con hashes
calculados en el propio teléfono**. Al terminar genera un **acta de extracción** lista para firmar, con el
registro de cada comando ejecutado.

→ **[Ver un acta de ejemplo](ejemplo/acta.md)** (generada con el teléfono simulado de las pruebas)

```
$ python adb_triage.py -o extraccion_01 --causa "Expte. 1234/2026" --perito "Nombre Apellido" --extraer /sdcard/DCIM /sdcard/Download
Dispositivo: R58TA0FICT1 (SM_A546E)
  samsung SM-A546E · Android 14 · parche 2026-09-01
  Reloj del teléfono: -186 s respecto de la PC · batería 63 % · modo avión DESACTIVADO
  8 apps (5 del usuario, 5 de interés pericial)
  4 archivos copiados · hashes teléfono vs. copia: todos coinciden

Acta: extraccion_01/acta.md  (SHA-256 6b9921d7…c357)
```

## Qué registra

| Sección del acta | Contenido |
|---|---|
| 1. Identificación | Fabricante, modelo, serie, Android y SDK, **parche de seguridad**, huella del build, zona horaria, cifrado, *verified boot* y estado del bootloader |
| 2. Estado al extraer | **Desfase del reloj del teléfono respecto de la PC**, batería, modo avión. Si el reloj difiere más de 60 s o el equipo no está aislado, lo advierte |
| 3. Apps | Todas, con versión e instalador. Marca las de interés pericial (mensajería, billeteras y bancos, acceso remoto, VPN, ocultamiento) y las **instaladas por el usuario sin tienda de origen** (posibles APK instalados a mano) |
| 4. Archivos | Cada archivo con tamaño, fecha de modificación según el teléfono, **SHA-256 calculado en el teléfono** y resultado de compararlo con la copia |
| 5. Registro de comandos | Cada comando con hora UTC, código de salida y SHA-256 de su salida, que se guarda completa en `raw/` |
| 6. Cierre | Hora de fin, hash del acta (`acta.md.sha256`) y espacio para firmas |

Además genera `dispositivo.json` (todas las propiedades del sistema), `apps.csv`, `manifiesto.sha256`
(se verifica con `sha256sum -c`) y `comandos.log`.

## Por qué está hecho así

- **Solo lectura, garantizado por código.** Cada comando pasa por una lista blanca (`COMANDOS_PERMITIDOS`):
  `install`, `push`, `rm`, `settings put` o `pm uninstall` se rechazan **antes** de llegar al teléfono.
  Hay una prueba que lo verifica.
- **El hash se calcula del lado del teléfono.** `sha256sum` corre dentro del equipo (toybox, Android 7+) antes de
  copiar; después se recalcula en la PC. Si coinciden, la copia es fiel. Si no, el archivo se marca en el acta
  y queda fuera del manifiesto.
- **El reloj del teléfono no es confiable.** Si el equipo está atrasado 3 minutos, todas las fechas de sus
  fotos y archivos también lo están. El desfase queda medido en el acta para corregir la línea de tiempo.
- **Reproducible.** El registro de comandos con el hash de cada salida permite que otro perito vea
  exactamente qué se hizo y compruebe que las salidas guardadas no se tocaron.
- **Los errores también se documentan.** Si la extracción se corta (teléfono no autorizado, cable), queda
  `comandos.log` con lo ejecutado hasta ese momento.
- **Lo que viene del teléfono no es confiable.** Nombres de archivos y paquetes se escapan en el acta, y los
  argumentos de `adb shell` se citan: `adb` los pasa al shell del teléfono, que si no interpretaría el `|` de
  `stat -c %Y|%s|%n` como una tubería.

## Uso

1. Instalar [Android platform-tools](https://developer.android.com/tools/releases/platform-tools) (incluye `adb`).
2. En el teléfono: *Ajustes → Acerca del teléfono →* tocar 7 veces *Número de compilación*; en *Opciones de
   desarrollador*, activar **Depuración USB**. Conectar y aceptar el aviso de autorización.
3. Ejecutar:

```bash
python adb_triage.py --listar                                    # ver el dispositivo
python adb_triage.py -o extraccion_01 --causa "..." --perito "..."  # identificación + apps
python adb_triage.py -o extraccion_02 --extraer /sdcard/DCIM /sdcard/Download /sdcard/Documents
```

- `--adb "C:\ruta\platform-tools\adb.exe"` si `adb` no está en el PATH.
- `--serial` si hay más de un dispositivo conectado.
- En **Git Bash**, anteponer `MSYS_NO_PATHCONV=1`; si no, Git Bash convierte `/sdcard/DCIM` en una ruta de
  Windows. En PowerShell o Linux no hace falta.

**Antes de usarlo en un caso real:** habilitar la depuración USB es una interacción con el equipo y ADB guarda
la clave de la PC en el teléfono. Hay que dejarlo escrito en el acta. Aislar el equipo (modo avión o bolsa de
Faraday) y sincronizar el reloj de la PC por NTP.

## Alcance y limitaciones

- Es una **extracción lógica**: identificación, apps y almacenamiento compartido (`/sdcard`). Los datos privados
  de las apps (`/data/data`, por ejemplo la base de WhatsApp) requieren extracción de sistema de archivos o física
  con herramientas específicas (Cellebrite, Magnet AXIOM, Oxygen) o un equipo rooteado.
- Necesita el teléfono **desbloqueado** para autorizar la depuración USB.
- Las categorías de apps son una lista orientativa que se amplía caso por caso (`CATEGORIAS`).
- **Probado contra un ADB simulado** ([tests/adb_simulado.py](tests/adb_simulado.py)), no contra un teléfono
  físico. El simulador imita el Samsung Galaxy A54 del Caso 1 de mi
  [laboratorio forense](https://github.com/agusfar45/laboratorio-perito-informatico) y reproduce cómo el
  `adb shell` real interpreta los argumentos.

## Pruebas

```bash
python -m unittest -v
```

9 pruebas contra el simulador:
- flujo completo, con verificación de hashes, del acta y del manifiesto;
- **que solo se ejecuten comandos de la lista blanca** y que los de escritura se bloqueen sin llegar a adb;
- citado de argumentos para el shell del teléfono;
- copia corrupta detectada;
- dispositivo ausente, no autorizado o duplicado;
- rutas fuera de `/sdcard`;
- parseo de apps en Android viejo.

## Uso legal

Usalo solo con **tu propio teléfono** o con autorización: orden judicial, consentimiento escrito del titular
o encargo en el marco de una pericia. Acceder a un dispositivo ajeno sin autorización es delito
(Ley 26.388; art. 153 bis del Código Penal).

---

Agustín Farfán · Ingeniería en Informática (UCASAL) ·
[laboratorio forense](https://github.com/agusfar45/laboratorio-perito-informatico) ·
[analizador de pcap](https://github.com/agusfar45/analizador-pcap-forense)
