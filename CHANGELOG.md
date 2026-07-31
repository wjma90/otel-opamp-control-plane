# Changelog

Todos los cambios relevantes de O11y OpAMP Control Plane se documentan aquí.
Las versiones siguen Semantic Versioning.

## [Unreleased]

## [0.25.4-opamp.0.23.0-otelcol.0.156.0] - 2026-07-30

### Changed

- La versión publicable identifica la versión propia del Control Plane,
  `opamp-go` y el Collector Contrib embebido como validador.
- Los artefactos no Helm excluyen `README.md`; el chart conserva su README.

## [0.25.3] - 2026-07-25

### Fixed

- El paso Destinos mantiene una instantánea estable del inventario mientras se
  revisan los destinatarios; el polling vivo ya no reordena ni reemplaza las
  filas y existe una actualización manual explícita.
- La tabla combina selectores y búsqueda, muestra únicamente destinos que
  recibirían la versión y presenta `Ninguno` cuando no hay coincidencias.

## [0.25.2] - 2026-07-25

### Removed

- Se retiró la allowlist semántica de componentes y topología Collector. El
  editor delega la compatibilidad del YAML al binario real
  `otelcol-contrib 0.156.0`; conserva el preflight que impide providers de
  archivos, HTTP y variables de entorno no autorizadas dentro del proceso
  validador.

## [0.24.11] - 2026-07-24

### Fixed

- Los campos de listas separados por comas conservan la coma mientras el
  usuario escribe y normalizan el valor al perder el foco; aplica a condiciones
  HTTP/mensajería, listas permitidas y buckets.

## [0.24.10] - 2026-07-24

### Changed

- La guía HTTP integrada usa un ejemplo neutral de órdenes y elimina referencias
  visibles a CambistApp para mantener el Control Plane independiente de una
  aplicación concreta.

## [0.24.9] - 2026-07-24

### Removed

- La imagen deja de añadir labels `org.opencontainers.image.*`.

## [0.24.8] - 2026-07-24

### Fixed

- El sidebar expandido tiene ancho suficiente para `Remote management` y el
  detalle `Agents and Supervisors: HTTP · 10s`, sin overflow, truncamiento ni
  saltos de línea.

## [0.24.7] - 2026-07-24

### Changed

- El menú y el título del editor usan la etiqueta breve `Editor OTel` para
  encajar correctamente en el sidebar. La ruta estable `/policy-studio` se
  mantiene compatible.

## [0.24.6] - 2026-07-24

### Changed

- El menú y el título del editor pasan de `Policy Studio` a
  `Studio de configuración` porque allí se crean tanto policies Java como
  configuraciones de Collector. La ruta estable `/policy-studio` se conserva
  para no romper enlaces existentes.

## [0.24.5] - 2026-07-24

### Fixed

- Fleet deja de mostrar el bundle técnico `java-policy-set · v0`: presenta
  “Sin policies activas” para un `PolicySet` vacío y las policies/versiones
  efectivas cuando existen.

## [0.24.4] - 2026-07-24

### Added

- TLS nativo opcional para el listener OpAMP `:4320`, con certificado y clave
  leídos desde archivos, validación fail-fast y mínimo TLS 1.2.
- El chart monta el par TLS desde un Secret existente mediante `opampTls`,
  sin depender de Istio ni crear material criptográfico.

## [0.24.3] - 2026-07-23

### Fixed

- La confirmación por destino normaliza el tipo de documento y muestra
  `Ver configuración` también ante variantes Collector con espacios,
  mayúsculas o sufijos, sin alterar el texto `Ver policy` de Java.
- La regresión queda cubierta con una prueba de interfaz que renderiza ambos
  tipos de documento en la misma tabla.

## [0.24.2] - 2026-07-23

### Added

- Rutas estables para Policy Studio, agentes, gestión remota, versiones,
  perfil y configuración, con soporte para refresh y navegación atrás/adelante.

### Changed

- Los enlaces históricos `?tab=...` se mantienen compatibles y se
  canonicalizan a la ruta equivalente; una ruta desconocida vuelve de forma
  segura a Policy Studio.

## [0.24.1] - 2026-07-23

### Fixed

- La confirmación por destino muestra `Ver configuración` para documentos
  Collector y conserva `Ver policy` únicamente para policies Java.

## [0.24.0] - 2026-07-23

### Added

- Policy schema `1.6` para añadir a métricas derivadas de eventos HTTP los
  atributos contextuales `http.request.method`, `http.route`,
  `http.response.status_code` y `error.type`.
- Policy Studio separa los atributos OTel contextuales de los labels de
  negocio y explica que las métricas conservan los resource attributes de la
  instancia que las emite.

### Changed

- Backend, UI y extensión validan el mismo catálogo acotado por dirección:
  `http.route` sólo puede seleccionarse para HTTP entrante.

## [0.23.0] - 2026-07-22

### Added

- Policy schema `1.5` para path parameters HTTP y eventos Kafka/JMS separados
  por producer y consumer.
- Editor guiado de mensajería con condiciones, datos y salidas a spans, logs y
  métricas con cardinalidad acotada.

### Changed

- La validación del backend mantiene paridad estricta con la extensión para
  valores nulos, campos vacíos, colisiones Prometheus y compatibilidad de
  schemas.

## [0.22.1] - 2026-07-22

### Changed

- La pestaña del navegador muestra explícitamente `O11Y Control Plane`.

## [0.22.0] - 2026-07-21

### Added

- Selector de idioma español/inglés, con español predeterminado, preferencia
  local persistente y formato de fechas acorde al idioma.
- Búsqueda dinámica de versiones PostgreSQL por ID, versión, servicio,
  `InstanceUID` y resource attributes antes de cargarlas en Policy Studio.
- Guía HTTP integrada y documentación paso a paso para mapear request/response
  hacia atributos de span, logs correlacionados y métricas.

### Changed

- El menú **Gestión remota** reúne explícitamente policies, configuraciones
  Collector y su estado por destino.
- El historial explica cuándo restaurar o retirar y que toda acción crea una
  nueva versión auditable sin sobrescribir las anteriores.
- El polling vivo actualiza únicamente inventario, versiones, destinos y bases;
  sesión, seguridad, almacenamiento y auditoría dejan de recargarse cada cuatro
  segundos.

### Fixed

- Fleet, destinos y versiones usan un orden determinista, por lo que un refresh
  conserva posición visual, filtros y foco del usuario.

## [0.21.1] - 2026-07-21

### Added

- La verificación de UI ejecuta el bundle de producción en Chromium y falla
  ante excepciones de página, errores de consola o recursos externos.
- DM Sans y Space Mono se empaquetan como assets locales compatibles con la
  política CSP estricta.

### Fixed

- Se activa el plugin React de Vite para evitar referencias globales a `React`
  al renderizar componentes JSX del Fleet.
- La UI ya no solicita Google Fonts, que era bloqueado correctamente por
  `style-src 'self'` y `font-src 'self'`.

## [0.21.0] - 2026-07-21

### Added

- Policy Studio permite definir explícitamente `event.name` y elegir si cada
  dato HTTP se añade al span, al log correlacionado o a los labels acotados de
  una métrica.

### Changed

- HTTP entrante y saliente usan un único editor progresivo
  **Cuándo → Datos capturados → Salidas**. Las configuraciones históricas de
  headers y métricas directas se conservan sin mutación y se editan en JSON.
- Las métricas de una regla se expresan como **Contar coincidencias**,
  **Total acumulado** o **Distribución**, sin exponer el enlace interno
  `eventName`.
- Una regla HTTP de conteo puede omitir campos extraídos, pero toda regla activa
  debe producir al menos un span enriquecido, un log habilitado o una métrica.

## [0.20.2] - 2026-07-21

### Added

- Fleet de agentes incorpora búsqueda textual y filtros multiselección por
  servicio, tipo, transporte, disponibilidad y estado efectivo.
- La tabla anuncia cuántos clientes coinciden y diferencia un inventario vacío
  de una búsqueda sin resultados.

### Changed

- La proyección usada para filtrar Fleet comparte el mismo estado efectivo,
  fallback y versiones que se muestran en cada fila, evitando divergencias
  entre el filtro y el estado visible.

## [0.20.1] - 2026-07-21

### Added

- Selector múltiple accesible con checkboxes y opción **Todos** para los nueve
  filtros categóricos de configuraciones Collector, policies, destinos y
  versiones.

### Changed

- Los valores de un mismo criterio se combinan con OR; búsqueda, estado,
  servicio y tipo se combinan entre sí con AND. Una selección vacía conserva la
  semántica dinámica de todos los valores, incluso cuando aparece uno nuevo.

## [0.20.0] - 2026-07-21

### Added

- Policy Studio agrupa HTTP entrante, método Java y HTTP saliente bajo
  **Eventos de telemetría**, con modo HTTP directo y correlacionado.
- Schema `1.4` para request/response headers y query params en condiciones y
  campos, incluyendo denylist central `QUERY_PARAM` y preflight por capacidad
  reportada del agente.
- Entorno manual local con PostgreSQL efímero y Mailpit opcional, mientras
  backend y UI se ejecutan desde el host.
- Chart Helm reusable con schema de values, seguridad por defecto, SAML
  opcional, Services configurables y pruebas de render.

### Changed

- `eventName` es único también en reglas deshabilitadas, el límite de 16
  selectores se valida sobre el `PolicySet` compuesto y los preflight sólo
  consideran destinos vivos coincidentes.
- La comparación de schemas usa `major.minor`; una versión como `1.10` ya no se
  interpreta como un decimal menor que `1.4`.
- El workflow de release ahora es autocontenido, usa tags `vX.Y.Z` y publica
  imagen, tarballs y chart OCI desde la raíz del producto.

## [0.19.1] - 2026-07-20

### Changed

- El Supervisor vuelve a ser propietario de su binario Collector y de su base
  NOP inmutable. El Control Plane conserva únicamente la administración de
  remote config por OpAMP y el inventario read-only de bases reportadas.
- Las versiones de Supervisor y Collector se muestran sólo cuando el cliente
  las reporta mediante los atributos `o11y.supervisor.version` y
  `o11y.collector.version`.

### Removed

- Se retiraron `POST /v1/supervisor/bootstrap`, la API
  `/api/collector-bootstrap-profiles`, el catálogo de artefactos y sus handlers.
- La migración elimina las tablas efímeras `collector_bootstrap_profiles` y
  `collector_bootstrap_audit` sin modificar configuraciones, policies ni
  historial OpAMP.

## [0.19.0] - 2026-07-20

### Added

- Bootstrap seguro para Supervisors Kubernetes: el Control Plane selecciona una
  base NOP versionada, entrega el artefacto oficial de otelcol-contrib por
  plataforma y exige verificación SHA-256 antes de iniciar.
- Inventario visible de versiones de Supervisor, Collector y origen efectivo
  de la configuración base.
- API versionada para actualizar perfiles protegidos de bootstrap sin permitir
  su eliminación.
- Recuperación persistente y descartable de borradores de Policy Studio.

### Changed

- `OPAMP_AUTH_MODE=disabled` es el camino local predeterminado; `token` conserva
  autenticación bearer opcional para despliegues que la requieran.

### Security

- El workflow ejecuta Semgrep 1.169.0 y Trivy 0.72.0 sobre backend y UI antes
  de empaquetar o publicar. Ambas herramientas están fijadas por digest,
  conservan reportes JSON; Semgrep bloquea hallazgos y Trivy bloquea
  severidades `HIGH`/`CRITICAL` del código fuente.

## [0.18.5] - 2026-07-20

### Added

- Baseline publicable del backend Go y la UI React como un solo componente.
- Administración versionada de policies y configuraciones de Collector.
- Inventario OpAMP, selectores dinámicos, confirmación efectiva y lifecycle de
  publicación, rollback y retiro.
- Validación de configuraciones con OpenTelemetry Collector Contrib 0.156.0.
- Identidad local, OIDC, SAML, RBAC, recuperación de contraseña y configuración
  de correo SMTP, AWS SES y Azure ACS.
- Persistencia PostgreSQL y auditoría estructurada.
- Artefactos Linux AMD64/ARM64, imagen GHCR multi-arquitectura y checksums desde
  GitHub Actions.
- Tarball portable con UI embebida y el validador Collector exacto junto al
  servidor.

### Security

- OpAMP limitado a HTTP polling autenticado, con límites de mensaje y WebSocket
  deshabilitado.
- Validación de URL/proxy, cookies protegidas, PKCE/nonce en OIDC y firma en SAML.
- Imagen distroless, non-root, con bases fijadas por digest.
- SBOM, provenance y scan Trivy por arquitectura como parte de la puerta de
  release, conservando explícita la excepción upstream del Collector.
