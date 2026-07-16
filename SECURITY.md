# SecureVault — Modelo de seguridad y plan de endurecimiento

> Documento vivo. Es la fuente de verdad del **modelo de amenazas**, el **esquema
> criptográfico objetivo** y el **inventario de vulnerabilidades** del proyecto.
> Se actualiza cada vez que se cierra un hallazgo o se descubre uno nuevo.
>
> Última revisión: análisis completo del núcleo criptográfico + auditoría profunda
> de servicios auxiliares (keyserver, import/export, key directory) + Fase 0 aplicada.

---

## 1. Objetivo de seguridad

SecureVault busca el equilibrio: **una sola master passphrase** da acceso a todo,
pero la infraestructura debe ser **robusta y resiliente a ataques**. Esto significa:

- La passphrase es el **único secreto** que el usuario memoriza.
- Todo lo demás (claves, datos, archivos) se deriva o protege a partir de ella.
- El compromiso del **archivo en disco** no debe revelar secretos sin la passphrase.
- El sistema debe **detectar manipulación** y **sobrevivir fallos** sin perder datos.

---

## 2. Modelo de amenazas

Definimos tres atacantes concretos y qué garantía buscamos frente a cada uno.

| # | Atacante | Escenario | Garantía objetivo |
|---|---|---|---|
| **T1** | **Acceso al archivo en reposo** | Laptop robada, malware con permisos de usuario, backup en nube filtrado, disco secundario | Sin la passphrase, los secretos son ilegibles **y** cualquier manipulación del vault es detectable |
| **T2** | **App desbloqueada** | Sesión abandonada, evil-maid, usuario se levanta del escritorio | Bloqueo automático; ventana de exposición acotada |
| **T3** | **Memoria / RAM** | Volcado de memoria, archivo de hibernación, swap a disco | Los secretos viven el menor tiempo posible y se limpian al bloquear |

**Fuera de alcance (asumido):** un atacante con **keylogger activo** o **RAM en vivo
durante el uso** puede capturar la passphrase mientras se teclea. Contra eso ninguna
app local puede defenderse; se mitiga con higiene del SO, no del vault.

---

## 3. Arquitectura criptográfica ACTUAL (as-is)

```
Registro:
  passphrase ──PBKDF2-SHA256(200k)──> hash ──> accounts.json (texto plano)   [oráculo]
  passphrase ──> cifra clave privada PGP (RSA-2048) ──> private_key.asc
  RNG ──> clave AES-256 ──cifrada con clave pública PGP──> vault.key.pgp

Guardado del vault:
  cada campo ──AES-GCM(clave AES)──> EncryptedField
  VaultData(JSON) ──cifrado con clave PÚBLICA PGP──> vault.data.pgp   [sin firmar]

Login:
  passphrase ──> se compara su hash contra accounts.json   [única puerta]
  passphrase ──> descifra clave privada ──> descifra clave AES ──> descifra campos
```

**Problemas estructurales de este diseño:**

1. **Dos caminos de confianza divergentes.** La passphrase protege (a) un hash de login
   y (b) la clave privada PGP, por separado. La "puerta" real de login es el hash, que
   es **más débil** que el PGP y es un **oráculo de fuerza bruta offline**.
2. **El vault no está autenticado.** Se cifra con la clave **pública**, que está en disco
   sin protección. Cualquiera puede fabricar un vault y cifrarlo → **sustitución/inyección
   indetectable** (hallazgo C1).
3. **Escritura destructiva.** `File.WriteAllBytes` directo, sin atomicidad ni backup →
   un fallo a mitad de guardado **corrompe todo** (hallazgo C2).

---

## 4. Arquitectura criptográfica ACTUAL — post Fase 2b ✅ (envelope encryption con KEK)

Una sola raíz criptográfica derivada de la passphrase, con **envelope encryption**:
una Vault Key (VK) aleatoria y fija se genera una única vez al registrarse, y una
Key-Encryption-Key (KEK) derivada de la passphrase la envuelve. Esto separa "cambiar
la passphrase" (solo re-envolver la VK) de "recifrar toda la bóveda" (nunca hace falta).

```
Registro (una vez):
  RNG(32 bytes) ──────────────────────────────────► Vault Key (VK)
  passphrase ──Argon2id(salt, m=19MiB,t=2,p=1)──► KEK
  VK ──AES-256-GCM cifrada con KEK──► vault.keyring.json (salt, params, nonce, tag)

Cada login (VK ya existe, se re-deriva la KEK y se desenvuelve):
  passphrase + salt ──Argon2id──► KEK ──AES-GCM-decrypt(wrapped VK)──► VK
                                          ▲
                          si la passphrase es incorrecta, el tag AEAD
                          no valida → UnauthorizedAccessException
                          (ESTA es la única puerta de login; no existe
                          ningún hash de contraseña en ningún archivo)

  VK ──HKDF-Expand(info="vault-blob")──► K_blob  (cifra/autentica todo VaultData vía AES-GCM → vault.data)
  VK ──HKDF-Expand(info="field")─────►  K_field (cifra cada campo sensible individualmente, AES-GCM)
```

**Propiedades que gana el sistema:**

- **Una sola raíz, sin hash en ningún lado.** No existe `PassphraseHash` en `accounts.json`
  ni en ningún archivo; la verificación es "¿el tag AEAD de la VK envuelta valida?", al
  costo completo de Argon2id.
- **Integridad autenticada nativa.** AES-GCM es AEAD: el propio tag de autenticación
  detecta cualquier sustitución o edición del blob al cargar (cierra C1 de forma más
  simple que el HMAC-SHA256 separado de la Fase 1 — ya no hace falta esa capa aparte).
- **Resistencia a hardware.** Argon2id castiga GPU/ASIC mucho más que PBKDF2 (cierra M1).
- **Memoria acotada.** KEK, VK y las subclaves derivadas viven en `byte[]` zeroizables
  (`CryptographicOperations.ZeroMemory`) y se liberan tan pronto se derivan las subclaves
  o al hacer `Dispose()` (cierra A3 por completo — la passphrase-string ya **no** vive
  toda la sesión: solo se usa transitoriamente en `VaultKeyRing.Unlock`/`Create`).
- **Autocontenida / lista para multi-dispositivo.** Cualquier dispositivo que conozca la
  passphrase puede re-derivar la KEK y desenvolver la misma VK — no hay ningún archivo de
  clave específico del dispositivo que sincronizar. Esto es exactamente lo que necesita
  el Paso 5 del roadmap multiplataforma (`IVaultStorage` + sync).

**Nota sobre PGP:** el par PGP se mantiene para lo que es bueno — **cifrar archivos y
directorios externos** y participar del ecosistema de keyservers. El **vault interno**
ya no depende del par pública/privada en absoluto. Son dos dominios: "mi bóveda" (KEK,
simétrico) y "compartir con terceros" (PGP, asimétrico). El par PGP se genera igual que
antes al registrarse, pero además se guarda armado *dentro* de `VaultData`
(`PgpPublicKeyArmored`/`PgpPrivateKeyArmored`), protegido por la misma VK que todo lo
demás — así viaja con la bóveda a cualquier dispositivo. `PasswordManagerService.
EnsurePgpKeyFilesAsync` materializa `public_key.asc`/`private_key.asc` en disco si
faltan, usando esa copia embebida, para que la función de compartir archivos siga
funcionando sin importar cómo llegó la bóveda a ese dispositivo.

---

## 5. Inventario de vulnerabilidades (consolidado)

Estado: `abierto` · `Fase 0 ✅` · `planificado`

### Crítico

| ID | Descripción | Ubicación | Estado |
|----|-------------|-----------|--------|
| C1 | Vault sin autenticar → sustitución/inyección indetectable | `KekVaultRepository.cs` | **Fase 1 ✅ → Fase 2b ✅** (AES-GCM AEAD sobre el blob; el propio tag de autenticación detecta manipulación, ya sin capa de HMAC separada) |
| C2 | Escritura no atómica → corrupción y pérdida total ante fallo | `KekVaultRepository.cs` | **Fase 1 ✅** (escritura temp→move + backup rotativo) |

### Alto

| ID | Descripción | Ubicación | Estado |
|----|-------------|-----------|--------|
| A1 | Hash en `accounts.json` = oráculo de fuerza bruta offline redundante | `AuthService.cs` | **Fase 2 ✅ → Fase 2b ✅** (hash eliminado; passphrase verificada por `VaultKeyRing.CanUnlock`, es decir, por el tag AEAD al desenvolver la Vault Key) |
| A2 | Sin auto-lock ni timeout de sesión | `AppState.cs` | Fase 3 |
| A3 | Passphrase/clave AES no zeroizables en memoria | `VaultKeyRing.cs` | **Fase 2b ✅ completa** (KEK/VK/subclaves zeroizadas tan pronto se usan; la passphrase-string ya no vive toda la sesión — solo durante `Unlock`/`Create`) |
| A4 | Corrupción del vault tragada → sobrescritura silenciosa | `KekVaultRepository.cs` | **Fase 1 ✅** (lanza `VaultIntegrityException`, nunca sobrescribe) |

### Medio

| ID | Descripción | Ubicación | Estado |
|----|-------------|-----------|--------|
| M1 | PBKDF2 200k < 600k recomendado; migrar a Argon2id | `AuthService.cs` | **Fase 2 ✅** (Argon2id OWASP m=19 MiB/t=2/p=1; PBKDF2 eliminado del código) |
| M2 | Sin backup/versionado del vault | `KekVaultRepository.cs` | **Fase 1 ✅** (backup rotativo `.bak` + `RestoreFromBackupAsync`) |
| M3 | `SecureDelete` inefectivo en SSD (falsa confianza) | `SecureFileHandler.cs` | Fase 4 |
| M4 | Descifrado de directorios pasa por temp sin cifrar | `FileEncryptionService.cs` | Fase 4 |
| M5 | Sin rate limiting en intentos de passphrase | `AuthService.cs` | Fase 3 |
| M6 | `accounts.json` sin integridad (email/VaultPath manipulables) | `AuthService.cs` | Fase 4 |
| M7 | CSV/formula injection en export | `ImportExportService.cs` | **Fase 0 ✅** |
| M8 | Export dejaba las contraseñas en texto plano en disco | `ImportExportPage.razor` | **✅ Export cifrado por defecto** (CSV→PGP con la llave pública propia; plano solo opción explícita con advertencia; import detecta y descifra) |

### Bajo / hardening

| ID | Descripción | Ubicación | Estado |
|----|-------------|-----------|--------|
| B1 | Una sola clave AES para todos los campos | `PasswordManagerService.cs` | Fase 5 |
| B2 | Portapapeles no se limpia tras copiar | `VaultPage.razor` | Fase 3 |
| B3 | RSA-2048; subir a RSA-4096 o Curve25519 | `PgpService.cs:30` | Fase 5 |
| B4 | Path traversal latente en key directory | `KeyDirectoryService.cs` | **Fase 0 ✅** |
| B5 | Clave del keyserver sin validar (PGP + UID vs email) | `KeyServerService.cs` | Fase 5 |
| B6 | `.gitignore` sin reglas para secretos | `.gitignore` | **Fase 0 ✅** |

---

## 6. Plan de acción por fases

- **Fase 0 — Red de seguridad barata ✅ (aplicada)**
  B6 (`.gitignore`), M7 (CSV injection), B4 (path traversal).
- **Fase 1 — Integridad y resiliencia (crítico) ✅ APLICADA:** C2 (escritura atómica
  temp→move), M2 (backup rotativo `.bak` + restore), C1 (HMAC-SHA256 sobre el ciphertext
  con clave derivada de la passphrase), A4 (`VaultIntegrityException`, nunca sobrescribe).
  N5 parcial: permisos Unix `0600` en no-Windows; en Windows se apoya en la ACL de AppData.
  *Pendiente de cablear en la UI:* ofrecer "restaurar backup" cuando `LoadAsync` lance
  `VaultIntegrityException` (hoy la capacidad existe en el repositorio; falta el botón).
- **Fase 2 — Raíz criptográfica unificada (alto) ✅ APLICADA:** M1 (Argon2id OWASP,
  `Argon2idKdf`, metadata de integridad v2 auto-descriptiva con id+params del KDF),
  A1 (eliminado el hash de `accounts.json`; `UserAccount` ya no guarda `PassphraseHash`/`Salt`).
- **Fase 2b — Candado de bóveda por KEK ✅ APLICADA:** el cifrado de la bóveda migró de
  PGP a una **KEK derivada de la passphrase con Argon2id** que envuelve una Vault Key (VK)
  aleatoria fija (envelope encryption); el blob se cifra con AES-256-GCM (AEAD) usando un
  subkey HKDF de la VK. Ver §4 para el diagrama completo. Esto (a) cierra A3 del todo —la
  passphrase-string ya no vive toda la sesión, solo durante `VaultKeyRing.Unlock`/`Create`—
  y (b) vuelve la bóveda **autocontenida** para multi-device: cualquier dispositivo
  re-deriva la KEK con solo la passphrase, no hay archivo de clave que sincronizar.
  **El par PGP se conserva** y ahora se guarda también *dentro* de la bóveda
  (`VaultData.PgpPublicKeyArmored`/`PgpPrivateKeyArmored`): sigue siendo la herramienta
  para **compartir archivos con terceros** (cifrado asimétrico con la llave pública del
  contacto) y para **recibir** archivos cifrados a la llave pública propia —
  `PasswordManagerService.EnsurePgpKeyFilesAsync` los materializa en disco si faltan.
  KEK ≠ PGP: la KEK es simétrica (mi bóveda), PGP es asimétrico (compartir). Prerrequisito
  cumplido del Paso 5 (sincronización) del roadmap multiplataforma.
  Nuevos archivos en disco: `vault.data` (blob AES-GCM) y `vault.keyring.json` (salt Argon2id
  + VK envuelta), reemplazando a `vault.data.pgp`/`vault.integrity.json`/`vault.key.pgp`.
  Fue un **cambio de formato sin migración** (decisión explícita: las bóvedas de prueba
  existentes se recrean desde cero en vez de migrarse).
- **Fase 3 — Seguridad de sesión (alto/medio):** A2 (auto-lock), M5 (backoff), B2
  (limpiar portapapeles).
- **Fase 4 — Higiene de datos (medio):** M4 (temporales cifrados), M3 (borrado honesto),
  M6 (integridad de `accounts.json` o eliminarlo).
- **Fase 5 — Hardening criptográfico (bajo):** B3 (RSA-4096/Curve25519), B5 (validar
  clave del keyserver), B1 (clave por campo).

---

## 7. Análisis fresco — vulnerabilidades adicionales (pendientes de triage)

> Esta sección se generó **partiendo de este documento**, buscando únicamente
> superficies **no cubiertas** por los hallazgos C/A/M/B anteriores. Todas quedan en
> estado **`pendiente`**. Tras aplicar las Fases 1–5 hay que volver aquí y verificar
> si siguen presentes, marcando cada una como `resuelta`, `mitigada` o `persistente`.

### N1 — Enumeración de cuentas por mensajes de login distintos · Medio · `✅ resuelto`
`LoginAsync` respondía `"No account found..."` vs `"Incorrect passphrase."`, dejando
**distinguir qué usuarios/emails existen** en el dispositivo; y el tiempo difería (sin
cuenta no se ejecutaba Argon2id → **oráculo de tiempo**).
*Corrección aplicada:* un único mensaje genérico (`"Incorrect username/email or
passphrase."`) en ambas ramas, y `VaultKeyRing.PerformDummyUnlock` corre un Argon2id de
coste equivalente cuando la cuenta no existe, igualando el tiempo de respuesta (el costo
de Argon2id domina el camino real). Cubierto por
`AuthServiceTests.LoginAsync_WrongPassphraseAndUnknownAccount_ProduceIdenticalMessage`.

### N2 — TOCTOU / carrera sin bloqueo en `accounts.json` · Medio · `✅ resuelto`
`LoadAllAsync` → mutar lista → `SaveAllAsync` era un **read-modify-write no atómico y sin
lock**. Dos registros simultáneos podían leer la misma lista y pisarse → **perder una cuenta**.
*Corrección aplicada:* `AuthService` serializa el read-modify-write de `accounts.json` con
un `SemaphoreSlim` estático (registro y actualización de `LastLogin`), re-leyendo dentro del
lock; y `SaveAllAsync` ahora escribe atómicamente (temp→`File.Move`) para que un fallo a
mitad no deje el archivo truncado. Cubierto por
`AuthServiceTests.RegisterAsync_ConcurrentRegistrations_AllPersist`. (El `SaveAsync` del
vault ya era atómico desde Fase 1.) *Nota:* el lock es intra-proceso; dos instancias
separadas de la app siguen siendo un caso extremo no cubierto — aceptable para un gestor
local de un solo proceso.

### N3 — Bomba de descompresión al desencriptar directorios · Alto · `✅ resuelto`
El límite de 200 MB / 1 GB era sobre el archivo **de entrada**. Un `.zip.pgp` malicioso de
pocos MB podía expandirse a **decenas de GB** al hacer `ZipFile.ExtractToDirectory`
(bomba zip), llenando el disco → DoS.
*Corrección aplicada:* `FileEncryptionService.SafeExtract` reemplaza a
`ZipFile.ExtractToDirectory` y extrae entrada por entrada en streaming, abortando apenas
el **total descomprimido** cruza `MaxExtractedBytes` (1 GB) o la **cantidad de entradas**
supera `MaxExtractedEntries` (100 000). De paso re-implementa la guarda **zip-slip**
(rechaza entradas cuyo path se escape del directorio destino), que al hacer extracción
manual hay que reponer. Cubierto por `SafeExtractTests` (bytes, cantidad, zip-slip,
round-trip).

### N4 — Fuga de datos por mensajes de excepción y logging · Medio · `✅ resuelto`
La UI mostraba `ex.Message` crudo (`$"Could not unlock vault: {ex.Message}"`, etc.), que
podía filtrar **rutas absolutas, detalles criptográficos o estructura interna** en pantalla.
*Corrección aplicada:* el helper `UserError.Describe(Loc, Exception)` centraliza el manejo:
solo las excepciones **cuyo mensaje escribimos nosotros** y que no llevan rutas
(`ArgumentException`, `InvalidOperationException`, `VaultIntegrityException`,
`GeneratorConstraintException` — validación, conflictos del generador, integridad) se muestran
tal cual; cualquier otra (IO con rutas, `CryptographicException`, JSON) se colapsa a un mensaje
genérico (`error.unexpected`) y el detalle técnico va a `Debug` en vez de a la pantalla.
Se convirtieron ~28 sitios de `catch` en la UI (`UnauthorizedAccessException`/`FileNotFound`
quedan deliberadamente **fuera** del whitelist por incluir rutas). Los `catch` tipados de
login/validación conservan su mensaje seguro. La **parte 2** (DevTools + `AddDebug` solo en
Release) ya estaba: ambos están bajo `#if DEBUG` en `MauiProgram`.

### N5 — Permisos de archivo laxos / sin cifrado del SO en reposo · Alto · `pendiente`
`accounts.json`, `private_key.asc` y `vault.data` se escriben con la **ACL por defecto**;
en una máquina compartida, **otros usuarios del SO podrían leerlos**. No se usa DPAPI
(Windows) ni Keychain/Keystore para envolver secretos en reposo. La protección hoy depende
solo de la passphrase, no del aislamiento del SO.
*Corrección:* restringir ACL al usuario actual al crear los archivos; opcionalmente
envolver la clave/salt con DPAPI (`ProtectedData`) como capa adicional ligada al usuario/máquina.

### N6 — Endurecimiento del WebView (CSP / XSS / DevTools) · Medio · `pendiente`
La UI corre en un WebView (BlazorWebView). Blazor escapa por defecto, pero cualquier uso de
`MarkupString` con datos que vengan del vault o de un keyserver sería **XSS con acceso al
runtime**. No hay **Content-Security-Policy** en `index.html`. DevTools está activo en DEBUG.
*Corrección:* añadir CSP restrictiva; prohibir `MarkupString` sobre datos no confiables;
confirmar DevTools deshabilitado en Release. (Nota: hoy `MarkupString` solo se usa con
literales controlados — el riesgo es de regresión futura.)

### N7 — Vault descifrado completo en el heap gestionado · Alto · `pendiente`
`LoadAsync` deserializa **todo el vault en claro** (JSON → `List<VaultEntry>`) y los valores
se descifran on-demand a `string`. Todo eso vive en el **heap gestionado (no zeroizable)** y
puede acabar en **swap o hibernación**. Más amplio que A3 (que era solo la passphrase).
*Corrección:* minimizar la vida de los plaintext, evitar materializar el vault entero cuando
sea posible, y considerar `[JsonIgnore]` + descifrado perezoso; a largo plazo, buffers
nativos fuera del GC para los secretos calientes.

### N8 — Confianza en el keyserver sin verificación de UID · Medio · `✅ resuelto`
`SearchByEmailAsync` descargaba una clave y `KeyManagementPage` la importaba **sin parsear el
paquete PGP ni verificar que su UID coincidiera con el email buscado**; el "fingerprint" que se
mostraba era un SHA-256 del archivo, inútil para verificación. Un keyserver comprometido podía
entregar una **clave de recipiente falsa** y el usuario cifraría archivos "para su contacto"
legibles por el atacante.
*Corrección aplicada:* `IPgpService.InspectPublicKey` (vía `PgpKeyInspector` con BouncyCastle)
parsea la clave y expone su **fingerprint PGP real** + los **UIDs**. La UI de búsqueda ahora
muestra fingerprint (para verificación out-of-band) + identidades antes de importar, y **advierte
si ningún UID contiene el email buscado** (o si la clave no parsea). Además el fingerprint del
directorio de contactos pasó a ser el real (long key ID) en vez del SHA del archivo. Cubierto por
`PgpKeyInspectorTests`. *Pendiente (extiende B5):* pinning del keyserver y bloqueo duro
opcional en mismatch (hoy es advertencia + confirmación explícita del usuario).

### N9 — Cadena de suministro sin fijar · Bajo · `✅ resuelto (parcial)`
No había lockfile de dependencias ni fijación de transitivas. `BouncyCastle.Cryptography`,
`CommunityToolkit.Maui` y demás se confiaban implícitamente por versión.
*Corrección aplicada:* `Directory.Build.props` con `RestorePackagesWithLockFile=true`;
cada proyecto (incl. el MAUI multi-TFM) genera y versiona su `packages.lock.json`, fijando
el grafo transitivo completo con hashes SHA-512 por paquete — auditable y reproducible.
*Pendiente:* activar modo bloqueado en CI (`--locked-mode`) cuando exista pipeline, y una
revisión periódica de vulnerabilidades (`dotnet list package --vulnerable`).

### N10 — Persistencia del portapapeles del SO · Bajo · `pendiente`
Aunque implementemos B2 (limpiar el portapapeles tras N segundos), el **historial del
portapapeles de Windows (Win+V)** y gestores de terceros **retienen la contraseña copiada**
más allá de nuestro borrado programático.
*Corrección:* al copiar, marcar el contenido como sensible/excluido del historial cuando la
plataforma lo permita (formato `ExcludeClipboardContentFromMonitorProcessing` / `CanIncludeInClipboardHistory`
en Windows); documentar la limitación en la UI.

---

### N11 — Android Auto Backup incluye el vault sin exclusión explícita · Medio · `✅ resuelto`
`AndroidManifest.xml` tiene `android:allowBackup="true"` (el valor por defecto de la
plantilla MAUI) y no declara `android:fullBackupContent` / `dataExtractionRules`. Esto
significa que Android **copia el almacenamiento privado de la app** (donde vive
`vault.data`, `accounts.json` y `private_key.asc`) a la cuenta de Google del usuario
vía Auto Backup, sin que el usuario lo pida explícitamente — exactamente el escenario
"backup en nube filtrado" del modelo de amenazas (T1). El contenido sigue protegido por
la passphrase (KEK vía Argon2id), pero es una superficie de exposición evitable.
*Corrección aplicada:* `android:allowBackup="false"` en `AndroidManifest.xml` — no
dependemos de ese mecanismo para nada (el propio backup rotativo `.bak` ya cubre la
recuperación local).

---

### Checklist de re-verificación (tras Fases 1–5)

| ID | Vulnerabilidad | ¿Sigue presente? | Notas |
|----|----------------|------------------|-------|
| N1 | Enumeración de cuentas / timing | ✅ resuelto | Mensaje unificado + `PerformDummyUnlock` (Argon2id de igual costo cuando no hay cuenta) |
| N2 | TOCTOU en accounts.json | ✅ resuelto | `SemaphoreSlim` en el read-modify-write + escritura atómica temp→move |
| N3 | Bomba de descompresión | ✅ resuelto | `SafeExtract`: cap de bytes/entradas descomprimidos + guarda zip-slip |
| N4 | Fuga por excepciones/logging | ✅ resuelto | `UserError.Describe` (whitelist de excepciones seguras + genérico para el resto); DevTools/AddDebug ya en `#if DEBUG` |
| N5 | Permisos de archivo / DPAPI | ⬜ pendiente | |
| N6 | Hardening WebView / CSP | ⬜ pendiente | |
| N7 | Vault en claro en el heap | ⬜ pendiente | |
| N8 | UID del keyserver sin verificar | ✅ resuelto | `InspectPublicKey`: fingerprint real + UIDs + advertencia de mismatch |
| N9 | Cadena de suministro | ✅ resuelto (parcial) | `packages.lock.json` en todos los proyectos; falta `--locked-mode` en CI |
| N10 | Historial de portapapeles | ⬜ pendiente | |
| N11 | Android Auto Backup sin exclusión | ✅ resuelto | `allowBackup="false"` en el manifest |
