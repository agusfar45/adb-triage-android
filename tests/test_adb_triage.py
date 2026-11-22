"""Pruebas de adb_triage.py contra el ADB simulado.   Correr desde la raíz:  python -m unittest -v"""
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
import adb_triage as at  # noqa: E402

ADB_SIM = f'"{sys.executable}" "{RAIZ / "tests" / "adb_simulado.py"}"'


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        sd = self.dir / "sdcard"
        (sd / "DCIM" / "Camera").mkdir(parents=True)
        (sd / "Download").mkdir()
        (sd / "DCIM" / "Camera" / "IMG_20261101_102233.jpg").write_bytes(b"\xff\xd8\xff" + bytes(range(256)) * 20)
        (sd / "Download" / "recibo moto.pdf").write_bytes(b"%PDF-1.4 recibo $850.000")
        self.log = self.dir / "invocaciones.log"
        self.env = {**os.environ, "ADB_SIM_SDCARD": str(sd), "ADB_SIM_LOG": str(self.log),
                    "MSYS_NO_PATHCONV": "1", "PYTHONIOENCODING": "utf-8"}

    def tearDown(self):
        self.tmp.cleanup()

    def correr(self, *extra, **env):
        salida = self.dir / "ext"
        p = subprocess.run([sys.executable, str(RAIZ / "adb_triage.py"), "--adb", ADB_SIM, "-o", str(salida), *extra],
                           capture_output=True, env={**self.env, **env}, cwd=RAIZ)
        return p, salida


class Extraccion(Base):
    def test_flujo_completo(self):
        p, sal = self.correr("--extraer", "/sdcard/DCIM", "/sdcard/Download", "--causa", "Práctica 01/2026",
                             ADB_SIM_DESFASE="-185")
        self.assertEqual(p.returncode, 0, p.stderr.decode("utf-8", "replace"))
        acta = (sal / "acta.md").read_text(encoding="utf-8")
        self.assertIn("SM-A546E", acta)
        self.assertIn("**2 de 2 coinciden**", acta)
        self.assertIn("atrasado", acta)                       # desfase de reloj detectado
        self.assertIn("modo avión estaba desactivado", acta)
        self.assertIn("`com.anydesk.anydeskandroid`, `com.calculator.hide.photo.video`", acta)  # APK sin tienda
        self.assertNotIn(str(sal), acta)                      # sin rutas locales en el acta
        # el hash del acta y el manifiesto se verifican igual que con sha256sum -c
        h, nombre = (sal / "acta.md.sha256").read_text().split()
        self.assertEqual(hashlib.sha256((sal / nombre).read_bytes()).hexdigest(), h)
        for linea in (sal / "manifiesto.sha256").read_text(encoding="utf-8").splitlines():
            h, ruta = linea.split("  ", 1)
            self.assertEqual(hashlib.sha256((sal / ruta).read_bytes()).hexdigest(), h)
        self.assertTrue((sal / "archivos" / "Download" / "recibo moto.pdf").is_file())  # nombre con espacio

    def test_solo_comandos_de_lectura(self):
        self.correr("--extraer", "/sdcard/DCIM")
        for inv in self.log.read_text(encoding="utf-8").splitlines():
            args = tuple(inv.split()[2:] if inv.startswith("-s ") else inv.split())
            self.assertTrue(any(args[:len(pref)] == pref for pref in at.COMANDOS_PERMITIDOS), inv)

    def test_argumentos_citados_para_el_shell_del_telefono(self):
        self.correr("--extraer", "/sdcard/DCIM")
        self.assertIn("stat -c '%Y|%s|%n' '{}' +", self.log.read_text(encoding="utf-8"))

    def test_copia_corrupta(self):
        p, sal = self.correr("--extraer", "/sdcard/DCIM", ADB_SIM_MODO="corrupto")
        self.assertEqual(p.returncode, 1)
        self.assertIn("NO COINCIDE", (sal / "acta.md").read_text(encoding="utf-8"))
        self.assertEqual((sal / "manifiesto.sha256").read_text(), "")  # lo alterado no entra al manifiesto

    def test_sin_avisos_si_esta_aislado_y_en_hora(self):
        p, sal = self.correr(ADB_SIM_AVION="1", ADB_SIM_DESFASE="0")
        acta = (sal / "acta.md").read_text(encoding="utf-8")
        self.assertNotIn("Atención", acta)
        self.assertIn("No se extrajeron archivos", acta)


class Errores(Base):
    def test_estados_del_dispositivo(self):
        casos = {"sin_dispositivo": "no hay ningún dispositivo", "no_autorizado": "no autorizó esta PC",
                 "dos": "más de un dispositivo"}
        for modo, texto in casos.items():
            with self.subTest(modo=modo):
                p, sal = self.correr(ADB_SIM_MODO=modo)
                self.assertEqual(p.returncode, 1)
                self.assertIn(texto, p.stderr.decode("utf-8"))
                self.assertIn("ERROR:", (sal / "comandos.log").read_text(encoding="utf-8"))  # el intento queda documentado
                import shutil; shutil.rmtree(sal)

    def test_rutas_fuera_de_sdcard_y_carpeta_existente(self):
        p, _ = self.correr("--extraer", "/data/data/com.whatsapp")
        self.assertEqual(p.returncode, 1)
        self.assertFalse(self.log.exists())  # se rechaza antes de tocar el teléfono
        (self.dir / "ext").mkdir()
        p, _ = self.correr()
        self.assertIn("ya existe", p.stderr.decode("utf-8"))

    def test_lista_blanca_bloquea_escrituras(self):
        s = at.Sesion(ADB_SIM, None, None)
        for peligroso in (("shell", "rm", "-rf", "/sdcard"), ("install", "x.apk"), ("shell", "settings", "put", "global", "x", "1"),
                          ("push", "a", "/sdcard/"), ("shell", "pm", "uninstall", "com.whatsapp")):
            with self.assertRaises(at.ErrorADB):
                s.correr(*peligroso)
        self.assertFalse(self.log.exists())  # ninguno llegó a ejecutarse


class Parser(unittest.TestCase):
    def test_apps_android_viejo_sin_version(self):
        class Falsa:
            def correr(self, *args, permitir_error=False):
                if "--show-versioncode" in args:
                    return "Error: Unknown option: --show-versioncode\n"
                if "-3" in args:
                    return "package:org.telegram.messenger\n"
                return ("package:/data/app/org.telegram.messenger-1/base.apk=org.telegram.messenger installer=null\n"
                        "package:/system/app/Phone.apk=com.android.phone installer=null\n")
        apps = at.listar_apps(Falsa())
        tg = next(x for x in apps if x["paquete"] == "org.telegram.messenger")
        self.assertEqual((tg["origen"], tg["categoria"], tg["version_code"]), ("usuario", "Mensajería", ""))
        self.assertEqual(apps[-1]["origen"], "sistema")


if __name__ == "__main__":
    unittest.main()
