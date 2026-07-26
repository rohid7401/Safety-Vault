# SafetyVault

Gestor de contraseñas local-first con cifrado PGP, construido en .NET MAUI Blazor
Hybrid. Una sola master passphrase da acceso a contraseñas, notas seguras, tarjetas,
generador de contraseñas, TOTP (2FA), auditoría de seguridad, cifrado de archivos y
gestión de llaves PGP para compartir archivos con contactos.

No hay servidor ni cuenta en la nube: la bóveda vive cifrada en el propio dispositivo.

## Características

- Bóveda cifrada con PGP + integridad HMAC-SHA256 (detecta manipulación/corrupción)
- KDF Argon2id (OWASP) para derivar claves desde la passphrase
- Contraseñas, notas seguras, tarjetas, TOTP (2FA)
- Varias cuentas por servicio: una tarjeta "Universidad" agrupa credenciales con nombre
  propio ("Plataforma", "Matrícula", "Pagos"), cada una con sus campos tipados (correo,
  usuario, contraseña, PIN, **enlace web**, teléfono, 2FA, texto libre) y su política de
  rotación. El campo web es lo que deja que varios sitios compartan la misma cuenta con
  contraseñas distintas sin partirlos en tarjetas separadas
- Fecha de alta de cada cuenta y de último cambio de su contraseña, visibles en la tarjeta
- Etiquetas por chips: el espacio cierra la etiqueta y abre la siguiente, con sugerencias
  tomadas de las que ya existen en la bóveda
- Generador de contraseñas configurable (incluye palabra personalizada, exclusión de
  caracteres, reglas de longitud/complejidad)
- Auditoría de contraseñas débiles/reutilizadas
- Cifrado de archivos con PGP para compartir con contactos por llave pública, tanto
  individuales como varios a la vez empaquetados en un `.zip` cifrado
- Import/Export con varios formatos — ver [Importar y exportar](#importar-y-exportar)
- Borrado por apartado ("Borrar datos"), para vaciar una sección sin tocar el resto
- Tour guiado en el primer uso, repetible después desde el menú
- Backup rotativo automático (`.bak`) con restauración ante corrupción
- Interfaz en español e inglés (i18n completo)
- Multiplataforma: Windows, macOS, Android; iOS compila (ver limitaciones abajo)

## Importar y exportar

Pensado para dos escenarios distintos, que tienen necesidades opuestas:

**Mover tus datos entre tus propios dispositivos** (móvil ↔ PC) → *Respaldo SafetyVault*
(`.safetyvault.json`). Es el único formato sin pérdida: conserva las cuentas múltiples
por servicio, el nombre de cada credencial, PIN, teléfonos, campos de texto, políticas
de rotación, tipo de 2FA y contador HOTP, etiquetas y fechas.

> El respaldo lleva los valores **en texto plano dentro del JSON**, no los ciphertexts
> guardados en la bóveda: esos están sellados con una clave derivada de la passphrase de
> *esa* cuenta, así que el dispositivo receptor —otra cuenta, otra clave— jamás podría
> abrirlos. La protección es el sobre PGP que se aplica al exportar, que está activo por
> defecto. Exportarlo en texto plano es posible pero la app lo advierte explícitamente.

**Migrar a otro gestor** → *CSV*, con presets para **Bitwarden**, **Chrome / Edge /
Google** o un **CSV genérico** legible en Excel. Eliges el destino y puedes destildar
campos individualmente; destildar elimina la columna entera del archivo, de modo que el
dato realmente no sale del dispositivo.

Al **importar**, el formato se detecta solo a partir del contenido (respaldo nativo,
JSON de Bitwarden, o CSV). Se entienden los CSV de Chrome/Edge/Google,
KeePass/KeePassXC, Bitwarden y el propio. La columna `url` / `login_uri` del origen entra
como enlace web de la credencial y ya no se pisa con el nombre de la tarjeta. Antes de
escribir nada se muestra un resumen con la cantidad de entradas y una vista previa, para
confirmar.

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

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) — Core/Infrastructure/UI/tests
- [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0) — necesario para Android,
  que usa `net9.0-android36.0`: la API 36 solo existe en el workload de Android de .NET 9
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

### Generar un ejecutable distribuible (Windows)

```
dotnet publish src/PasswordManager.App/PasswordManager.App.csproj -f net8.0-windows10.0.19041.0 -c Release
```

Genera el paquete MSIX en
`src/PasswordManager.App/bin/Release/net8.0-windows10.0.19041.0/win10-x64/AppPackages/`.
Para instalarlo en otra máquina el paquete debe estar firmado y su certificado
confiado en el equipo destino; para uso personal alcanza con correr la app desde el
build de desarrollo (`-t:Run`).

## Android

La app apunta a **Android 16 (API 36)**, mínimo Android 7.0 (API 24). Google Play exige
API 36 para poder publicar actualizaciones a partir del **30 de agosto de 2026**.

### Requisitos adicionales

| Herramienta | Notas |
|---|---|
| **JDK 17** | Microsoft Build of OpenJDK recomendado. Puede convivir con otras versiones de Java ya instaladas — no hace falta que sea el `JAVA_HOME` global, ver abajo |
| **Android SDK** con **platform 36** | Se instala automáticamente con el comando de la sección siguiente. Manualmente: `platform-tools`, `platforms;android-36`, `build-tools;35.0.0` |
| Dispositivo o emulador Android 7.0+ (API 24) | El emulador puede ser de cualquier API ≥ 24; no necesita ser API 36 |

### Preparar una máquina nueva para Android

```powershell
# 1. JDK 17
winget install --id Microsoft.OpenJDK.17 -e

# 2. Workload de MAUI al día (necesario para que exista el target Android 36)
dotnet workload update

# 3. Android SDK: instala la plataforma 36 y acepta licencias automáticamente.
#    Si aún no tenés el SDK, instalá antes Android Studio o las command-line tools
#    (https://developer.android.com/studio#command-tools) y definí ANDROID_HOME.
dotnet build src/PasswordManager.App/PasswordManager.App.csproj `
  -t:InstallAndroidDependencies -f net9.0-android36.0 -p:AcceptAndroidSDKLicenses=true
```

Si el SDK no está en la ruta por defecto, agregar
`-p:AndroidSdkDirectory="<SDK_ROOT>"` al comando 3.

> **Nota:** si `sdkmanager` se queda colgado indefinidamente en "Fetch remote
> repository..." sin avisar error, es un problema conocido de Java prefiriendo IPv6 en
> redes donde esa ruta está rota. Solución: exportar
> `JAVA_OPTS=-Djava.net.preferIPv4Stack=true` antes de correr `sdkmanager`.

### Compilar y correr (dispositivo físico por USB o emulador)

Con el dispositivo conectado y depuración USB activada (o el emulador ya iniciado):

```
adb devices     # confirmar que aparece

dotnet build src/PasswordManager.App/PasswordManager.App.csproj -f net9.0-android36.0 -t:Run
```

`-t:Run` compila, instala y lanza la app en el dispositivo. Sin `-t:Run` solo compila el
`.apk`, que queda en:

```
src/PasswordManager.App/bin/Debug/net9.0-android36.0/com.safetyvault.app-Signed.apk
```

y se puede instalar a mano con `adb install -r <ruta al apk>`.

Si el `JAVA_HOME` global apunta a una versión distinta de 17, pasar el JDK
explícitamente (y el SDK si tampoco está en la ruta por defecto):

```
dotnet build src/PasswordManager.App/PasswordManager.App.csproj -f net9.0-android36.0 -t:Run `
  -p:JavaSdkDirectory="C:\Program Files\Microsoft\jdk-17.0.19.10-hotspot" `
  -p:AndroidSdkDirectory="<SDK_ROOT>"
```

### Publicar a Google Play

El workflow [`release-android.yml`](.github/workflows/release-android.yml) publica al
track de **internal testing** automáticamente al empujar un tag de versión:

```
git tag v1.0.1
git push origin v1.0.1
```

El nombre del tag se convierte en el `versionName`; el `versionCode` sale del número de
ejecución del workflow más un offset (ver el comentario en el YAML). El workflow corre
los tests antes de publicar, así que un test roto detiene el release.

Secrets requeridos en el repositorio de GitHub:

| Secret | Contenido |
|---|---|
| `ANDROID_KEYSTORE_BASE64` | El `.keystore` de firma, codificado en base64 |
| `ANDROID_KEY_ALIAS` | Alias de la llave dentro del keystore |
| `ANDROID_KEY_PASSWORD` | Contraseña de la llave |
| `ANDROID_KEYSTORE_PASSWORD` | Contraseña del keystore |
| `PLAY_SERVICE_ACCOUNT_JSON` | JSON de la cuenta de servicio de Google Play con permiso de publicación |

Para generar el `.aab` firmado localmente (sin publicar), ver los parámetros del paso
"Publish signed .aab" en ese mismo workflow.

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
- Todo export está cifrado con PGP por defecto (con la llave pública propia). El texto
  plano es una opción explícita con advertencia en la UI, más fuerte para el respaldo
  nativo, que contiene la bóveda completa incluidos PIN y secretos 2FA.
- El cifrado de carpetas se comporta distinto por plataforma por una restricción del
  sistema, no por diseño: en escritorio se elige la carpeta y se empaqueta entera; en
  Android/iOS el selector no entrega una ruta de archivos real (Storage Access
  Framework), así que se eligen varios archivos que se empaquetan en un `.zip` cifrado.
- La política de privacidad publicada está en [PRIVACY.md](PRIVACY.md).

## Internacionalización

La UI está completamente traducida a español e inglés
(`src/PasswordManager.UI/Localization/Resources/{en,es}.json`, misma cantidad de
claves en ambos). El selector de idioma está disponible en la app.
