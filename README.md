# SecureVault

Gestor de contraseñas local-first con cifrado PGP, construido en .NET MAUI Blazor
Hybrid. Una sola master passphrase da acceso a contraseñas, notas seguras, tarjetas,
generador de contraseñas, TOTP (2FA), auditoría de seguridad, cifrado de archivos y
gestión de llaves PGP para compartir archivos con contactos.

No hay servidor ni cuenta en la nube: la bóveda vive cifrada en el propio dispositivo.

## Características

- Bóveda cifrada con PGP + integridad HMAC-SHA256 (detecta manipulación/corrupción)
- KDF Argon2id (OWASP) para derivar claves desde la passphrase
- Contraseñas, notas seguras, tarjetas, TOTP (2FA)
- Generador de contraseñas configurable (incluye palabra personalizada, exclusión de
  caracteres, reglas de longitud/complejidad)
- Auditoría de contraseñas débiles/reutilizadas
- Cifrado de archivos individuales con PGP (compartir con contactos por llave pública)
- Import/Export de la bóveda: **cifrado por defecto** (PGP con tu propia llave
  pública) o CSV plano opcional para migrar a otro gestor
- Backup rotativo automático (`.bak`) con restauración ante corrupción
- Interfaz en español e inglés (i18n completo)
- Multiplataforma: Windows, macOS, Android; iOS compila (ver limitaciones abajo)

Para el modelo de amenazas y el detalle de las decisiones de seguridad, ver
[SECURITY.md](SECURITY.md). Para el roadmap multiplataforma, ver
[MULTIPLATFORM.md](MULTIPLATFORM.md).

## Estructura del proyecto

```
src/
  PasswordManager.Core/            Modelos, interfaces, lógica de dominio (sin dependencias externas)
  PasswordManager.Infrastructure/  Implementaciones: PGP, Argon2id, persistencia, servicios
  PasswordManager.UI/              Componentes Razor + i18n compartidos (Razor Class Library)
  PasswordManager.App/             Shell MAUI (Windows/macOS/Android/iOS) — implementa
                                    las abstracciones de plataforma (portapapeles, file picker)
  PasswordManager.Console/         CLI mínima de referencia (sin UI, útil para debug rápido)
tests/
  PasswordManager.Tests/           Tests unitarios y de integración (xUnit)
```

`PasswordManager.UI` no depende de MAUI: es una librería Razor pura pensada para que
un futuro shell Blazor WebAssembly (web) pueda reusar toda la UI sin reescribirla.

## Requisitos comunes (todas las plataformas)

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- Workload de MAUI:
  ```
  dotnet workload install maui
  ```
- Git

Verificar que todo esté instalado:
```
dotnet --list-sdks
dotnet workload list
```

## Clonar el repositorio

```
git clone https://github.com/rohid7401/Safety-Vault.git
cd Safety-Vault
dotnet restore
```

## Compilar y correr los tests (multiplataforma, no requiere nada extra)

```
dotnet test tests/PasswordManager.Tests/PasswordManager.Tests.csproj
```

## Windows

Sin requisitos adicionales más allá de los comunes.

```
dotnet build src/PasswordManager.App/PasswordManager.App.csproj -f net8.0-windows10.0.19041.0 -t:Run
```

O abrir `PasswordManager.sln` en Visual Studio 2022 (workload **.NET Multi-platform
App UI development**), seleccionar el target Windows y F5.

## Android

### Requisitos adicionales

| Herramienta | Notas |
|---|---|
| **JDK 17** | Microsoft Build of OpenJDK recomendado. Puede convivir con otras versiones de Java ya instaladas — no hace falta que sea el `JAVA_HOME` global, ver abajo |
| **Android SDK** | Mínimo: `platform-tools`, `platforms;android-34`, `build-tools;34.0.0`. Se puede instalar con Android Studio (GUI) o solo las [command-line tools](https://developer.android.com/studio#command-tools) (más liviano, sin IDE) |
| Dispositivo o emulador Android 7.0+ (API 24) | Para probar la app compilada |

### Instalación rápida (Windows, sin Android Studio)

```powershell
# 1. JDK 17
winget install --id Microsoft.OpenJDK.17 -e

# 2. Android SDK — command-line tools desde developer.android.com/studio
#    (descargar el zip "Command line tools only" para Windows, extraer, y anidar
#    el contenido en <SDK_ROOT>\cmdline-tools\latest\)

# 3. Instalar los paquetes necesarios y aceptar licencias
<SDK_ROOT>\cmdline-tools\latest\bin\sdkmanager.bat --sdk_root=<SDK_ROOT> "platform-tools" "platforms;android-34" "build-tools;34.0.0"
<SDK_ROOT>\cmdline-tools\latest\bin\sdkmanager.bat --sdk_root=<SDK_ROOT> --licenses

# 4. Variables de entorno (nueva terminal para que tomen efecto)
setx ANDROID_HOME "<SDK_ROOT>"
setx ANDROID_SDK_ROOT "<SDK_ROOT>"
# agregar <SDK_ROOT>\platform-tools al PATH
```

> **Nota:** si `sdkmanager` se queda colgado indefinidamente en "Fetch remote
> repository..." sin avisar error, es un problema conocido de Java prefiriendo IPv6 en
> redes donde esa ruta está rota. Solución: exportar
> `JAVA_OPTS=-Djava.net.preferIPv4Stack=true` antes de correr `sdkmanager`.

### Compilar y correr (dispositivo físico por USB o emulador)

```
# Con el dispositivo conectado y depuración USB activada (u emulador ya iniciado):
adb devices     # confirmar que aparece

dotnet build src/PasswordManager.App/PasswordManager.App.csproj -f net8.0-android -t:Run
```

Si el `JAVA_HOME` global apunta a una versión distinta de 17, pasar explícitamente:
```
-p:JavaSdkDirectory="<ruta al JDK 17>" -p:AndroidSdkDirectory="<SDK_ROOT>"
```

El `.apk` firmado para instalar manualmente (`adb install ...`) queda en:
```
src/PasswordManager.App/bin/Debug/net8.0-android/com.securevault.app-Signed.apk
```

## macOS (Mac Catalyst)

Requiere una Mac con Xcode instalado.

```
dotnet build src/PasswordManager.App/PasswordManager.App.csproj -f net8.0-maccatalyst -t:Run
```

## iOS

Requiere una **Mac** con **Xcode** instalado — no es posible compilar ni probar iOS
desde Windows/Linux (restricción de Apple, no de este proyecto).

```
dotnet build src/PasswordManager.App/PasswordManager.App.csproj -f net8.0-ios -t:Run
```

Con un iPhone conectado por USB y confiado en la Mac, esto compila, firma (con tu
Apple ID personal, gratis) e instala directo en el dispositivo.

**Compartir el build con otras personas** (no solo tu propio iPhone) requiere el
[Apple Developer Program](https://developer.apple.com/programs/) ($99/año) y
distribuir vía **TestFlight** — a diferencia de Android, iOS no permite instalar un
`.ipa` suelto en cualquier dispositivo sin firma válida para ese dispositivo
específico.

## Notas de seguridad y despliegue

- El backup automático de Android (`allowBackup`) está deshabilitado a propósito: la
  bóveda no debe salir del dispositivo sin acción explícita del usuario.
- El export de la bóveda es cifrado por defecto (PGP con la llave pública propia); el
  CSV plano es una opción explícita para migrar a otro gestor, con advertencia en la UI.
- Ver [SECURITY.md](SECURITY.md) para el modelo de amenazas completo y el checklist
  de hardening (ítems `N1`–`N11`).
- Ver [MULTIPLATFORM.md](MULTIPLATFORM.md) para el estado y roadmap de cada
  plataforma, y el plan de sincronización multi-dispositivo (KEK / `IVaultStorage`).

## Internacionalización

La UI está completamente traducida a español e inglés
(`src/PasswordManager.UI/Localization/Resources/{en,es}.json`, misma cantidad de
claves en ambos). El selector de idioma está disponible en la app.
