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

{{- define "o11y-control-plane.validate" -}}
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
{{- end }}
