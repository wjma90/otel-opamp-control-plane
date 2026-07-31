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
grep -q '^kind: ConfigMap$' "${tmp_dir}/default.yaml"
grep -q 'readOnlyRootFilesystem: true' "${tmp_dir}/default.yaml"
grep -q 'automountServiceAccountToken: false' "${tmp_dir}/default.yaml"
grep -q 'name: COLLECTOR_VALIDATOR_ENV_FILE' "${tmp_dir}/default.yaml"
grep -q 'value: /etc/o11y/collector-validator/allowed-environment.json' "${tmp_dir}/default.yaml"
grep -q '"name": "K8S_POD_NAME"' "${tmp_dir}/default.yaml"
grep -q 'invalid-credential: o11y-validator-no-api-access' "${tmp_dir}/default.yaml"
grep -q 'path: token' "${tmp_dir}/default.yaml"
grep -q 'name: validator-serviceaccount' "${tmp_dir}/default.yaml"
grep -q 'mountPath: /var/run/secrets/kubernetes.io/serviceaccount' "${tmp_dir}/default.yaml"
grep -q 'name: "kube-root-ca.crt"' "${tmp_dir}/default.yaml"
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

helm template custom-validator "${chart_dir}" \
  --set validator.allowedEnvironment[0].name=POD_NAME \
  --set validator.allowedEnvironment[0].value=custom-validation-pod \
  --set validator.allowedEnvironment[1].name=CLUSTER_NAME \
  --set validator.allowedEnvironment[1].value=custom-cluster \
  --set validator.allowedEnvironment[2].name=K8S_NODE_IP \
  --set validator.allowedEnvironment[2].value=127.0.0.2 \
  --set validator.allowedEnvironment[3].name=K8S_NODE_NAME \
  --set validator.allowedEnvironment[3].value=custom-node \
  > "${tmp_dir}/custom-validator.yaml"
grep -q '"name": "CLUSTER_NAME"' "${tmp_dir}/custom-validator.yaml"
grep -q '"value": "custom-cluster"' "${tmp_dir}/custom-validator.yaml"

if helm template duplicate-validator "${chart_dir}" \
  --set validator.allowedEnvironment[0].name=POD_NAME \
  --set validator.allowedEnvironment[1].name=POD_NAME \
  > "${tmp_dir}/duplicate-validator.yaml" 2>&1; then
  echo "duplicated validator environment names must fail rendering" >&2
  exit 1
fi

if helm template reserved-validator "${chart_dir}" \
  --set validator.allowedEnvironment[0].name=KUBERNETES_SERVICE_HOST \
  > "${tmp_dir}/reserved-validator.yaml" 2>&1; then
  echo "reserved validator environment names must fail rendering" >&2
  exit 1
fi

if helm template unsafe-serviceaccount "${chart_dir}" \
  --set automountServiceAccountToken=true \
  > "${tmp_dir}/unsafe-serviceaccount.yaml" 2>&1; then
  echo "the Control Plane must not mount a real Kubernetes service account token" >&2
  exit 1
fi

echo "Helm chart render tests passed."
