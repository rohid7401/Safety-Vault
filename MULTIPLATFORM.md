# SecureVault — Plan de adaptación multiplataforma y sincronización

> Documento vivo. Define cómo llevar SecureVault a **escritorio, web y móvil** con
> **disponibilidad de datos entre dispositivos**, manteniendo el modelo de seguridad
> descrito en [`SECURITY.md`](SECURITY.md). Complementa a `SECURITY.md` y `DESIGN.md`.

---

## 1. Las dos realizaciones que ordenan todo el plan

**R1 — El modelo PGP-por-dispositivo actual es el bloqueador; la raíz derivada de la
passphrase (Fase 2 de seguridad) es el habilitador.**
Hoy cada dispositivo genera su propio par PGP que nunca sale de ahí. Para que el
dispositivo B lea el vault del dispositivo A habría que sincronizar la clave privada
—frágil e inseguro—. Con la **KEK derivada de la passphrase vía Argon2id**, cualquier
dispositivo con la passphrase re-deriva la clave y descifra: el blob del vault se vuelve
**autocontenido** (el salt viaja con él). Por eso el orden es innegociable:
**Fase 1 → Fase 2 de seguridad ANTES de tocar cloud/multi-device.**

**R2 — Con cifrado E2E cliente, la nube solo ve ciphertext.**
El servidor (propio o de terceros) es un **almacén de blobs "tonto"** que nunca puede
descifrar. Esto mantiene la complejidad de seguridad baja: un compromiso total del
servidor entrega ciphertext ilegible mientras la passphrase sea fuerte y el KDF sea duro.

---

## 2. Reestructuración de proyectos

MAUI **no soporta web**. La estrategia: extraer la UI a una biblioteca compartida
(Razor Class Library) y montar dos shells.

```
PasswordManager.Core              sin cambios — .NET puro, agnóstico de plataforma
PasswordManager.Infrastructure    abstraer File.* detrás de interfaces
PasswordManager.UI  (RCL nuevo)   componentes .razor + servicios compartidos
├── PasswordManager.App.Maui      shell escritorio + móvil (Win / macOS / iOS / Android)
└── PasswordManager.App.Web       shell Blazor WebAssembly (navegador)
PasswordManager.Sync.Contracts    DTOs de sincronización compartidos
[opcional futuro] PasswordManager.Server   almacén de blobs + auth propios
```

Lo que cambia por plataforma **no es la UI**, son tres servicios detrás de interfaces:

```csharp
IClipboard      // MAUI Clipboard          vs  navigator.clipboard (JS interop)
IFilePicker     // MAUI FilePicker         vs  <input type=file>
IVaultStorage   // filesystem / IndexedDB  vs  cloud
```

---

## 3. Estado y esfuerzo por plataforma

| Plataforma | Estado hoy | Trabajo para llegar |
|---|---|---|
| **Windows / macOS** | ✅ Ya corre (MAUI) | 0 |
| **iOS / Android** | ⚠️ Compila | Servicio de cifrado ya es **stream-based** ✅ y el picker expone `PickFileForReadAsync`/`SaveStreamAsync` ✅. Falta: cablear las páginas Encrypt para usar streams, ajustar permisos y **probar en dispositivo/emulador** (requiere Mac para iOS). ~4–6 h restantes |
| **Web (WASM)** | ❌ No existe | Proyecto Blazor WASM + `IVaultStorage` sobre IndexedDB + JS interop clipboard/archivos. **Sin folder picker** (limitación del navegador). ~20–30 h |

El refactor a streams tiene doble beneficio: desbloquea móvil **y** es lo que la web
necesita (en WASM no hay filesystem).

---

## 4. Modelo de sincronización

El diseño de datos actual ya da ventaja: `VaultEntry` tiene `Id`, `LastUpdateTime`,
`IsDeleted` y `DeletedAt`. Eso permite **merge a nivel de entrada** en vez de a nivel de
blob completo, evitando que un dispositivo pise al otro.

- Dos dispositivos editan offline → al sincronizar se comparan entradas por `Id` y gana
  la de `LastUpdateTime` más reciente (last-write-wins por entrada).
- Los borrados (`IsDeleted` + `DeletedAt`) se propagan como **tombstones**, no reaparecen.

Abstracción de almacenamiento:

```csharp
interface IVaultStorage {
    Task<VaultBlob?> PullAsync();                            // baja ciphertext + versión (etag)
    Task PushAsync(VaultBlob blob, string expectedVersion);  // concurrencia optimista
}
```

Implementaciones intercambiables: `LocalFileStorage`, `DropboxStorage`, `OneDriveStorage`,
`OurBackendStorage`. La UI no sabe cuál está debajo.

---

## 5. Complejidad de seguridad en la nube (análisis)

| Aspecto | Complejidad | Notas |
|---|---|---|
| Cifrado E2E del blob | **Baja** | Ya ciframos; la nube guarda opaco |
| Distribución de clave entre dispositivos | **Baja** *(tras Fase 2)* | La KEK se re-deriva de la passphrase; nada que sincronizar |
| Resolución de conflictos | **Media** | Merge por entrada con `Id` + `LastUpdateTime` (el modelo ya lo soporta) |
| Auth sin debilitar zero-knowledge | **Media** | El secreto de login debe ser **distinto** del de cifrado |
| **Rollback attack** | **Media-Alta** | Un servidor puede servir una versión **vieja**. El MAC protege el contenido pero no la frescura → hace falta un **contador de versión firmado y monótono** |
| Fuga de metadatos | **Media** | El servidor ve tamaño del blob, frecuencia, IPs, horarios → análisis de tráfico. Normalmente se acepta |

El **rollback attack** es la trampa sutil: cifrar bien no basta si el servidor puede
revertirte a un estado anterior. Se mitiga con un número de versión firmado que el
cliente verifica que solo suba.

---

## 6. Manejo de cuentas — separación zero-knowledge

En un diseño zero-knowledge **nunca** se mezclan dos conceptos:

1. **Cuenta de identidad/auth** — da acceso al *almacén de blobs* (email + contraseña de
   servidor, u OAuth del proveedor). El servidor la valida.
2. **Master passphrase** — descifra el *vault*. **Nunca se envía al servidor.**

Deben ser **secretos distintos**. Si se reusa la passphrase para autenticar, el servidor
aprende algo sobre ella. Modelo estándar (Bitwarden): derivar un "auth hash" con un KDF y
la clave de cifrado con otro salt/KDF, de modo que el token que ve el servidor **no sirve
para descifrar**.

### Estrategia elegida: Opción C (híbrida) ✅

| Opción | Descripción | Decisión |
|---|---|---|
| A — BYO storage | El usuario conecta su Dropbox / Drive / iCloud / OneDrive; la app lee/escribe un archivo. Sin cuentas ni infra propias, cero costo, cero responsabilidad legal. OAuth del proveedor = "cuenta" | **Punto de partida** |
| B — Backend propio | Cuentas propias, blob store, API de sync. Mejor UX y control (revocación de dispositivos, compartir), pero se opera infra y se asume responsabilidad legal | Futuro, si se justifica |
| **C — Híbrida** | Diseñar `IVaultStorage` desde el inicio, arrancar con A y dejar la puerta abierta a B sin reescribir | **ELEGIDA** |

**Racional de la decisión:** sacar el producto rápido con almacenamiento del propio
usuario (sin cuentas propias, sin costo, zero-knowledge por diseño). Si en el futuro se
requiere aislar el proyecto, se le crea su **backend propio** implementando `OurBackendStorage`
+ auth, sin tocar el resto de la app.

---

## 7. Roadmap secuenciado (integrado con SECURITY.md)

Los pasos 1 y 2 son **no negociables** y deben ir primero: la seguridad multi-device
depende de la raíz derivada de la passphrase.

| # | Paso | Depende de | Estado |
|---|------|-----------|--------|
| 0 | **Fase 0 de seguridad** — `.gitignore`, CSV injection, path traversal | — | ✅ Hecho |
| 1 | **🔒 NO NEGOCIABLE — Fase 1 de seguridad** — escritura atómica, backup, integridad/MAC del vault, corrupto≠vacío, ACL de archivos | 0 | ✅ Hecho (falta cablear botón "restaurar backup" en UI) |
| 2 | **🔒 NO NEGOCIABLE — Fase 2 de seguridad** — Argon2id, colapsar autenticación, memoria zeroizable | 1 | ✅ Hecho |
| 2b | **🔒 NO NEGOCIABLE — Fase 2b** — migrar el candado de la bóveda de PGP a **KEK derivada de la passphrase** (Argon2id); guardar el par PGP **dentro** de la bóveda para que viaje entre dispositivos. **El par PGP se conserva** para la función de compartir archivos con terceros (cifrado asimétrico) | 2 | Pendiente (prerrequisito de multi-device) |
| 3 | Refactor de `FileEncryptionService` a **streams** | 1 | ✅ Servicio + picker + UI (Encrypt Files e Import/Export por streams). Directorios quedan solo-escritorio. Falta prueba en dispositivo |
| 4 | Extraer UI a **Razor Class Library** | — | ✅ Hecho (`PasswordManager.UI` con abstracciones `IClipboardService`/`IFilePickerService`; shell MAUI las implementa) |
| 5 | `IVaultStorage` + **merge por entrada** (Id/LastUpdateTime) | 2b | Pendiente |
| 6 | Proyecto **Blazor WebAssembly** (plataforma web) | 4 | Pendiente |
| 7 | Adaptadores **BYO cloud** (Dropbox/Drive) — Opción A | 5 | Pendiente |
| 8 | *(Opcional)* **Backend propio** + contador de versión firmado (anti-rollback) — Opción B | 5, 7 | Futuro |

**La regla de oro:** nada de sincronización ni multi-device sobre el modelo
PGP-por-dispositivo actual. Primero pasos 1 y 2, luego el resto.

---

## 8. Riesgos de seguridad que introduce la nube (a re-verificar)

Cuando se llegue al paso 5+, revisar contra el apartado 7 de `SECURITY.md`:

- **Rollback attack** (§5) — requiere contador de versión firmado y monótono.
- **N2 (TOCTOU)** se agrava con múltiples dispositivos → concurrencia optimista por etag.
- **N4 (fuga por metadatos/logs)** — el backend no debe loguear IPs/tamaños asociables.
- **N8 (confianza en keyserver)** — sin cambios, pero el patrón de "confiar en un servidor"
  aplica igual al blob store: validar siempre en el cliente.
- Nuevo a documentar cuando exista backend: **autenticación separada del cifrado** (§6).
