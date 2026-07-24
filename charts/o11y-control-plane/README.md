# O11y Control Plane Helm chart

The chart deploys one O11y Control Plane Deployment and its internal UI/OpAMP
Service. It does not install PostgreSQL, Istio, cert-manager or an ingress
gateway.

The default is portable and closed: the public OpAMP Service and Istio
injection are disabled. Existing Secrets are required for PostgreSQL, bootstrap
identity and the session signing key. See the product
[Helm guide](../../docs/HELM.md) for installation and OCI commands.

Validate every change from the product root:

```bash
helm lint --strict charts/o11y-control-plane
charts/o11y-control-plane/tests/render.sh
```
