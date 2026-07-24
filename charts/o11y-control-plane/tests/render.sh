#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chart_dir="$(cd "${script_dir}/.." && pwd)"
product_dir="$(cd "${chart_dir}/../.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

helm lint --strict "${chart_dir}"
version="$(tr -d '[:space:]' < "${product_dir}/VERSION")"
chart_version="$(helm show chart "${chart_dir}" | awk '$1 == "version:" {print $2}')"
app_version="$(helm show chart "${chart_dir}" | awk '$1 == "appVersion:" {gsub(/"/, "", $2); print $2}')"
test "${chart_version}" = "${version}"
test "${app_version}" = "${version}"
helm template control-plane "${chart_dir}" --namespace o11y > "${tmp_dir}/default.yaml"

grep -q '^kind: Deployment$' "${tmp_dir}/default.yaml"
grep -q '^kind: Service$' "${tmp_dir}/default.yaml"
grep -q 'readOnlyRootFilesystem: true' "${tmp_dir}/default.yaml"
grep -q 'automountServiceAccountToken: false' "${tmp_dir}/default.yaml"
grep -q 'name: OPAMP_TLS_ENABLED' "${tmp_dir}/default.yaml"
grep -q 'value: "false"' "${tmp_dir}/default.yaml"
if grep -q 'OPAMP_TLS_CERT_FILE\\|mountPath: /etc/o11y/opamp-tls' "${tmp_dir}/default.yaml"; then
  echo "default render must not mount OpAMP TLS material" >&2
  exit 1
fi

if grep -q '^kind: Certificate$' "${tmp_dir}/default.yaml"; then
  echo "default render must not require cert-manager" >&2
  exit 1
fi

if grep -q 'nodePort:' "${tmp_dir}/default.yaml"; then
  echo "default render must not expose a NodePort" >&2
  exit 1
fi

full_values=(
  --namespace o11y
  --set istio.sidecarInjection=true
  --set fullnameOverride=control-plane
  --set-string selectorLabels.app=control-plane
  --set opampPublicService.enabled=true
  --set opampPublicService.nodePort=30320
  --set opampTls.enabled=true
  --set opampTls.existingSecret=control-plane-opamp-tls
  --set config.opampPublicURL=https://opamp.example.test/v1/opamp
  --set saml.enabled=true
  --set saml.certManager.enabled=true
  --set auth.signing.existingSecret=
  --set auth.signing.key=tls.key
)
helm template control-plane "${chart_dir}" "${full_values[@]}" > "${tmp_dir}/full.yaml"

grep -q '^kind: Issuer$' "${tmp_dir}/full.yaml"
grep -q '^kind: Certificate$' "${tmp_dir}/full.yaml"
grep -q 'sidecar.istio.io/inject: "true"' "${tmp_dir}/full.yaml"
grep -q 'app: control-plane' "${tmp_dir}/full.yaml"
grep -q 'nodePort: 30320' "${tmp_dir}/full.yaml"
grep -q 'AUTH_SAML_SP_CERT_FILE' "${tmp_dir}/full.yaml"
grep -q 'OPAMP_TLS_CERT_FILE' "${tmp_dir}/full.yaml"
grep -q 'mountPath: /etc/o11y/opamp-tls' "${tmp_dir}/full.yaml"
grep -q 'secretName: "control-plane-opamp-tls"' "${tmp_dir}/full.yaml"

invalid_values=(
  --set config.opampAuthMode=token
  --set auth.opampToken.existingSecret=
)
if helm template invalid "${chart_dir}" "${invalid_values[@]}" > "${tmp_dir}/invalid.yaml" 2>&1; then
  echo "token mode without a Secret must fail rendering" >&2
  exit 1
fi

if helm template invalid-tls "${chart_dir}" \
  --set opampTls.enabled=true \
  --set opampTls.existingSecret= > "${tmp_dir}/invalid-tls.yaml" 2>&1; then
  echo "TLS mode without a Secret must fail rendering" >&2
  exit 1
fi

if helm template invalid-tls-url "${chart_dir}" \
  --set opampTls.enabled=true \
  --set opampTls.existingSecret=control-plane-opamp-tls > "${tmp_dir}/invalid-tls-url.yaml" 2>&1; then
  echo "TLS mode with an HTTP public URL must fail rendering" >&2
  exit 1
fi

echo "Helm chart render tests passed."
