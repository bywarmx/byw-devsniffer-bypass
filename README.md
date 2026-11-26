# bywZero Dev & Sniffer Bypass

Módulo para **LSPosed / Vector / EdXposed** diseñado para neutralizar la detección de:
- **Opciones de Desarrollador** y **Depuración USB** (`development_settings_enabled`, `adb_enabled`).
- **Aplicaciones de análisis de red y captura de paquetes (Sniffers)** como PCAPdroid, HTTP Canary, Packet Capture, etc.
- **Interfaces VPN activas** (`NetworkCapabilities.TRANSPORT_VPN`).
- **Verificaciones nativas de integridad y seguridad** (como `libnative-security.so` de Halcon Connect y utilidades similares).

---

## Características
1. **Settings Hooking**: Intercepta consultas a `Settings.Global` y `Settings.Secure`, retornando `0` para `development_settings_enabled` y `adb_enabled`.
2. **PackageManager Filtering**: Filtra la presencia de paquetes de análisis, captura de paquetes y gestores root en `getPackageInfo`, `getApplicationInfo`, `getInstalledPackages` y `getInstalledApplications`.
3. **VPN Cloaking**: Modifica `NetworkCapabilities.hasTransport(TRANSPORT_VPN)` devolviendo `false` para que la app objetivo no detecte el proxy/túnel de captura.
4. **Native Hooking**: Neutraliza rutinas de seguridad de `NativeSecurity.checkSecurity` forzando código de éxito `0` y bypass de diálogo en `v3.b.m`.

---

## Instalación y Uso
1. Descarga el APK precompilado desde [release/byw_devsniffer_bypass.apk](release/byw_devsniffer_bypass.apk).
2. Instala el APK en tu dispositivo con KernelSU/Magisk + LSPosed/Vector.
3. Abre el gestor de **LSPosed / Vector**.
4. Habilita el módulo **bywZero Dev & Sniffer Bypass**.
5. Marca en el Scope la aplicación que deseas parchear (por ejemplo `com.halcon.connect`).
6. Fuerza la detención de la app objetivo y vuelve a abrirla.

---

## Compilación Manual
Si deseas recompilar el módulo:
```bash
./build.sh
```
Requiere JDK 17 y Android SDK build-tools (AAPT, D8, ZipAlign, Apksigner).

---
*Desarrollado con el protocolo autónomo bywZero.*
