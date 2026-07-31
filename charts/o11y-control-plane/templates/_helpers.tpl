{{- define "o11y-control-plane.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "o11y-control-plane.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "o11y-control-plane.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "o11y-control-plane.labels" -}}
helm.sh/chart: {{ include "o11y-control-plane.chart" . }}
{{ include "o11y-control-plane.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}

{{- define "o11y-control-plane.selectorLabels" -}}
{{- if .Values.selectorLabels }}
{{- toYaml .Values.selectorLabels }}
{{- else }}
app.kubernetes.io/name: {{ include "o11y-control-plane.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
{{- end }}

{{- define "o11y-control-plane.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{- define "o11y-control-plane.samlSecretName" -}}
{{- if .Values.saml.certManager.enabled }}
{{- default (printf "%s-saml" (include "o11y-control-plane.fullname" .)) .Values.saml.certManager.secretName }}
{{- else }}
{{- .Values.saml.existingSecret }}
{{- end }}
{{- end }}

{{- define "o11y-control-plane.signingSecretName" -}}
{{- if .Values.auth.signing.existingSecret }}
{{- .Values.auth.signing.existingSecret }}
{{- else if .Values.saml.certManager.enabled }}
{{- include "o11y-control-plane.samlSecretName" . }}
{{- else }}
{{- fail "auth.signing.existingSecret is required unless saml.certManager.enabled=true" }}
{{- end }}
{{- end }}

{{- define "o11y-control-plane.validatorConfigMapName" -}}
{{- printf "%s-validator" (include "o11y-control-plane.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "o11y-control-plane.validate" -}}
{{- if .Values.automountServiceAccountToken }}
{{- fail "automountServiceAccountToken must remain false; the validator uses a synthetic serviceAccount sandbox" }}
{{- end }}
{{- if and (eq .Values.config.opampAuthMode "token") (not .Values.auth.opampToken.existingSecret) }}
{{- fail "auth.opampToken.existingSecret is required when config.opampAuthMode=token" }}
{{- end }}
{{- if and .Values.opampTls.enabled (not .Values.opampTls.existingSecret) }}
{{- fail "opampTls.existingSecret is required when opampTls.enabled=true" }}
{{- end }}
{{- if and .Values.opampTls.enabled (not (hasPrefix "https://" .Values.config.opampPublicURL)) }}
{{- fail "config.opampPublicURL must use https:// when opampTls.enabled=true" }}
{{- end }}
{{- if and .Values.saml.enabled (not .Values.saml.certManager.enabled) (not .Values.saml.existingSecret) }}
{{- fail "saml.existingSecret or saml.certManager.enabled=true is required when saml.enabled=true" }}
{{- end }}
{{- if and .Values.saml.certManager.enabled (not .Values.saml.certManager.createIssuer) (not .Values.saml.certManager.issuerRef.name) }}
{{- fail "saml.certManager.issuerRef.name is required when createIssuer=false" }}
{{- end }}
{{- if gt (len .Values.validator.allowedEnvironment) 32 }}
{{- fail "validator.allowedEnvironment cannot contain more than 32 entries" }}
{{- end }}
{{- $reserved := list "HOME" "TMPDIR" "KUBERNETES_SERVICE_HOST" "KUBERNETES_SERVICE_PORT" "KUBERNETES_SERVICE_PORT_HTTPS" "KUBERNETES_PORT" "COLLECTOR_VALIDATOR_ENV_FILE" }}
{{- $seen := dict }}
{{- range .Values.validator.allowedEnvironment }}
{{- if not (regexMatch "^[A-Za-z_][A-Za-z0-9_]*$" .name) }}
{{- fail (printf "validator.allowedEnvironment contains invalid name %q" .name) }}
{{- end }}
{{- if has .name $reserved }}
{{- fail (printf "validator.allowedEnvironment name %q is reserved" .name) }}
{{- end }}
{{- if hasKey $seen .name }}
{{- fail (printf "validator.allowedEnvironment name %q is duplicated" .name) }}
{{- end }}
{{- $_ := set $seen .name true }}
{{- end }}
{{- end }}
