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

## 4. Arquitectura criptográfica OBJETIVO (to-be)

Colapsar todo a **una sola raíz criptográfica** derivada de la passphrase.

```
                 ┌─────────────── Argon2id(passphrase, salt, params) ───────────────┐
                 │                                                                    │
             Clave Maestra (KEK, 32 bytes, nunca tocada en disco)                    │
                 │                                                                    │
      ┌──────────┼───────────────────────────┐                                       │
      ▼          ▼                            ▼                                       │
  K_enc      K_mac                        (opcional) K_wrap                           │
  (AES-GCM   (HMAC-SHA256                 envuelve la clave privada PGP               │
   del vault) del vault + metadatos)      para archivos externos)                    │
      │          │                                                                    │
      ▼          ▼                                                                    │
  vault.data ──> se cifra con K_enc y se AUTENTICA con K_mac (o AES-GCM que ya       │
                 provee AEAD sobre todo el blob, no solo por-campo)                   │
      │                                                                               │
  Login = "¿la KEK derivada descifra Y el tag/MAC valida?"  ◄─── única puerta ───────┘
```

**Propiedades que gana el sistema:**

- **Una sola raíz.** No más hash-oráculo en `accounts.json`; la verificación es
  "¿descifra?", con el coste completo de Argon2id **y** del propio cifrado.
- **Integridad autenticada.** El vault entero lleva un tag AEAD / MAC. Sustituir o
  editar el blob se detecta al cargar (cierra C1).
- **Resistencia a hardware.** Argon2id castiga GPU/ASIC mucho más que PBKDF2 (cierra M1).
- **Memoria acotada.** KEK y claves derivadas viven en `byte[]` zeroizables, se limpian
  al bloquear (mitiga A3 / T3).

**Nota sobre PGP:** el par PGP se mantiene para lo que es bueno — **cifrar archivos y
directorios externos** y participar del ecosistema de keyservers. El **vault interno**
deja de depender del par pública/privada y pasa al esquema autenticado de arriba. Son
dos dominios: "mi bóveda" (KEK) y "compartir con terceros" (PGP).

---

## 5. Inventario de vulnerabilidades (consolidado)

Estado: `abierto` · `Fase 0 ✅` · `planificado`

### Crítico

| ID | Descripción | Ubicación | Estado |
|----|-------------|-----------|--------|
| C1 | Vault sin autenticar → sustitución/inyección indetectable | `PgpVaultRepository.cs` | **Fase 1 ✅** (HMAC-SHA256 sobre ciphertext con clave derivada de passphrase) |
| C2 | Escritura no atómica → corrupción y pérdida total ante fallo | `PgpVaultRepository.cs` | **Fase 1 ✅** (escritura temp→move + backup rotativo) |

### Alto

| ID | Descripción | Ubicación | Estado |
|----|-------------|-----------|--------|
| A1 | Hash en `accounts.json` = oráculo de fuerza bruta offline redundante | `AuthService.cs` | **Fase 2 ✅** (hash eliminado; passphrase verificada por desbloqueo de clave privada PGP) |
| A2 | Sin auto-lock ni timeout de sesión | `AppState.cs` | Fase 3 |
| A3 | Passphrase/clave AES no zeroizables en memoria | `VaultOptions`, `PgpService.cs` | **Fase 2 parcial ✅** (claves derivadas zeroizadas; passphrase-string pendiente de migración PGP→KEK) |
| A4 | Corrupción del vault tragada → sobrescritura silenciosa | `PgpVaultRepository.cs` | **Fase 1 ✅** (lanza `VaultIntegrityException`, nunca sobrescribe) |

### Medio

| ID | Descripción | Ubicación | Estado |
|----|-------------|-----------|--------|
| M1 | PBKDF2 200k < 600k recomendado; migrar a Argon2id | `AuthService.cs` | **Fase 2 ✅** (Argon2id OWASP m=19 MiB/t=2/p=1; PBKDF2 eliminado del código) |
| M2 | Sin backup/versionado del vault | `PgpVaultRepository.cs` | **Fase 1 ✅** (backup rotativo `.bak` + `RestoreFromBackupAsync`) |
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
  A1 (eliminado el hash de `accounts.json`; `UserAccount` ya no guarda `PassphraseHash`/`Salt`;
  la passphrase se verifica con `IPgpService.CanUnlockPrivateKey`), A3 parcial (claves
  derivadas —MAC, AES— zeroizadas en `Dispose`; `Argon2idKdf` limpia la copia UTF-8 de la
  passphrase).
- **Fase 2b — Candado de bóveda por KEK (COMPROMETIDA, no opcional):** migrar el cifrado
  de la bóveda de PGP a una **KEK derivada de la passphrase con Argon2id** (envelope
  encryption: KEK → K_enc/K_mac de la bóveda). Esto (a) elimina la vida larga de la
  passphrase-string —hoy el vault se descifra con PGP en cada carga, obligando a mantenerla
  en memoria toda la sesión— cerrando del todo A3, y (b) vuelve la bóveda **autocontenida**
  para multi-device (cualquier dispositivo re-deriva la KEK; no hay archivo de clave que
  sincronizar). **El par PGP se conserva** y pasa a guardarse *dentro* de la bóveda: sigue
  siendo la herramienta para la función de **compartir archivos con terceros** (cifrado
  asimétrico con la llave pública del contacto) y para **recibir** archivos cifrados a la
  llave pública propia. KEK ≠ PGP: la KEK es simétrica (mi bóveda), PGP es asimétrico
  (compartir). Prerrequisito del Paso 5 (sincronización) del roadmap multiplataforma.
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

### N1 — Enumeración de cuentas por mensajes de login distintos · Medio · `pendiente`
`LoginAsync` responde `"No account found with that username or email."` vs
`"Incorrect passphrase."`. Un atacante local puede **distinguir qué usuarios/emails
existen** en el dispositivo. Además el tiempo de respuesta difiere (si no hay cuenta,
no se ejecuta Argon2id/PBKDF2 → respuesta más rápida = **oráculo de tiempo**).
*Corrección:* un único mensaje genérico y ejecutar siempre un KDF "dummy" de coste
equivalente cuando la cuenta no existe.

### N2 — TOCTOU / carrera sin bloqueo en `accounts.json` · Medio · `pendiente`
`LoadAllAsync` → mutar lista → `SaveAllAsync` es un **read-modify-write no atómico y sin
lock de archivo**. Dos registros simultáneos, o dos instancias de la app, pueden pisarse
y **perder una cuenta**. Mismo patrón afecta a `SaveAsync` del vault si hay dos ventanas.
*Corrección:* lock de archivo (`FileStream` con `FileShare.None`) + escritura atómica
temp→rename, o un mutex por-vault a nivel de proceso.

### N3 — Bomba de descompresión al desencriptar directorios · Alto · `pendiente`
El límite de 200 MB / 1 GB es sobre el archivo **de entrada**. Un `.zip.pgp` malicioso de
pocos MB puede expandirse a **decenas de GB** al hacer `ZipFile.ExtractToDirectory`
(bomba zip), llenando el disco o agotando memoria → DoS. También el paquete PGP puede
llevar un `literal data` gigante o compresión anidada.
*Corrección:* extraer entrada por entrada verificando el tamaño total descomprimido
acumulado contra un límite, y abortar si se excede; validar ratio de compresión.

### N4 — Fuga de datos por mensajes de excepción y logging · Medio · `pendiente`
La UI muestra `ex.Message` crudo (`$"Could not unlock vault: {ex.Message}"`, etc.), que
puede filtrar **rutas absolutas, detalles criptográficos o estructura interna**. En DEBUG,
`builder.Logging.AddDebug()` y las DeveloperTools del WebView pueden volcar datos sensibles.
*Corrección:* mensajes genéricos al usuario + log técnico separado sin secretos; asegurar
que DeveloperTools y AddDebug **nunca** se compilen en Release.

### N5 — Permisos de archivo laxos / sin cifrado del SO en reposo · Alto · `pendiente`
`accounts.json`, `private_key.asc` y `vault.data.pgp` se escriben con la **ACL por defecto**;
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

### N8 — Confianza en el keyserver sin verificación de UID · Medio · `pendiente`
`SearchByEmailAsync` descarga una clave y `KeyManagementPage` la importa **sin parsear el
paquete PGP ni verificar que su UID coincide con el email buscado**. TLS valida el servidor
pero no hay pinning; un keyserver comprometido o un operador malicioso podría entregar una
**clave de recipiente falsa**, y luego el usuario cifraría archivos "para su contacto" que en
realidad puede leer el atacante.
*Corrección:* parsear la clave, mostrar fingerprint + UIDs y **exigir confirmación explícita**;
verificar que algún UID contenga el email consultado antes de guardar (extiende B5).

### N9 — Cadena de suministro sin fijar · Bajo · `pendiente`
No hay lockfile de dependencias ni fijación de transitivas. `BouncyCastle.Cryptography`,
`CommunityToolkit.Maui` y demás se confían implícitamente por versión. Un paquete comprometido
tendría acceso directo a las rutinas criptográficas.
*Corrección:* habilitar `packages.lock.json` (`RestorePackagesWithLockFile`), revisar hashes,
y fijar versiones exactas de paquetes con superficie criptográfica.

### N10 — Persistencia del portapapeles del SO · Bajo · `pendiente`
Aunque implementemos B2 (limpiar el portapapeles tras N segundos), el **historial del
portapapeles de Windows (Win+V)** y gestores de terceros **retienen la contraseña copiada**
más allá de nuestro borrado programático.
*Corrección:* al copiar, marcar el contenido como sensible/excluido del historial cuando la
plataforma lo permita (formato `ExcludeClipboardContentFromMonitorProcessing` / `CanIncludeInClipboardHistory`
en Windows); documentar la limitación en la UI.

---

### Checklist de re-verificación (tras Fases 1–5)

| ID | Vulnerabilidad | ¿Sigue presente? | Notas |
|----|----------------|------------------|-------|
| N1 | Enumeración de cuentas / timing | ⬜ persistente | Fase 2 no lo resolvió: `LoginAsync` aún distingue "no account" vs "incorrect passphrase" y solo corre PGP si la cuenta existe (oráculo de tiempo). Abordar con mensaje único + verificación dummy |
| N2 | TOCTOU en accounts.json | ⬜ pendiente | |
| N3 | Bomba de descompresión | ⬜ pendiente | |
| N4 | Fuga por excepciones/logging | ⬜ pendiente | |
| N5 | Permisos de archivo / DPAPI | ⬜ pendiente | |
| N6 | Hardening WebView / CSP | ⬜ pendiente | |
| N7 | Vault en claro en el heap | ⬜ pendiente | |
| N8 | UID del keyserver sin verificar | ⬜ pendiente | |
| N9 | Cadena de suministro | ⬜ pendiente | |
| N10 | Historial de portapapeles | ⬜ pendiente | |
