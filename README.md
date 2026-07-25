# O11y OpAMP Control Plane

Reúne en un solo producto el backend Go y la UI
React para administrar clientes OpAMP, configuraciones de OpenTelemetry
Collector y policies dinámicas de la extensión Java.

## Qué incluye

- inventario y estado de señal de Java Agents y Supervisors;
- **Gestión remota** para consultar policies, configuraciones de Collector,
  versiones, destinos, restauraciones y retiros;
- validación real de configuraciones de Collector mediante `otelcol-contrib`;
- inventario read-only de las bases locales y versiones que reporta cada
  Supervisor;
- selectores por servicio, instance UID y resource attributes, incluidos pods
  futuros que coincidan;
- login local, OIDC, SAML y autorización basada en roles;
- auditoría y persistencia en PostgreSQL;
- búsqueda de versiones por ID, versión y selectores, e interfaz en español o
  inglés con español como idioma inicial;
- UI React embebida en el binario Go.

Los clientes vigentes usan `POST /v1/opamp` por HTTP polling. Cada Supervisor es
propietario de su binario Collector y de su base NOP inmutable; el Control Plane
sólo administra remote config. WebSocket se rechaza explícitamente.
`OPAMP_AUTH_MODE` usa `disabled` por defecto y permite habilitar el modo `token`.

## Desarrollo

Requisitos: Go 1.26, Node.js 22 y npm. Desde esta carpeta:

```bash
cd ui
npm ci
npm run verify

cd ..
go test -count=1 ./...
go vet ./...
```

Las integraciones de protocolos usan mocks locales. La integración persistente
usa PostgreSQL 18.4:

```bash
docker run --rm -d \
  --name o11y-control-plane-test-postgres \
  -p 55432:5432 \
  -e POSTGRES_DB=o11y_test \
  -e POSTGRES_USER=o11y_test \
  -e POSTGRES_PASSWORD=o11y-test-password \
  postgres:18.4-alpine

until docker exec o11y-control-plane-test-postgres \
  pg_isready -U o11y_test -d o11y_test; do sleep 1; done

O11Y_TEST_DATABASE_URL='postgres://o11y_test:o11y-test-password@127.0.0.1:55432/o11y_test?sslmode=disable' \
  go test -count=1 -tags=integration ./...

docker stop o11y-control-plane-test-postgres
```

## Imagen local

```bash
docker build -t o11y-control-plane:0.24.11 .
```

Puertos:

- `8080`: UI, API, `/healthz` y `/readyz`;
- `4320`: `POST /v1/opamp`.

## Helm

El chart reusable se ubica en `charts/o11y-control-plane`. Sus defaults no exponen
un NodePort, no crean credenciales y esperan Secrets existentes. Para validarlo:

```bash
helm lint --strict charts/o11y-control-plane
charts/o11y-control-plane/tests/render.sh
```

Una release se instala directamente desde GHCR:

```bash
helm upgrade --install control-plane \
  oci://ghcr.io/OWNER/charts/o11y-control-plane \
  --version X.Y.Z \
  --namespace o11y \
  --create-namespace \
  --values values.yaml
```
