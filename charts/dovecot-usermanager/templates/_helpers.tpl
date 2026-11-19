{{- define "dovecot-usermanager.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "dovecot-usermanager.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- include "dovecot-usermanager.name" . | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "dovecot-usermanager.labels" -}}
app.kubernetes.io/name: {{ include "dovecot-usermanager.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "dovecot-usermanager.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dovecot-usermanager.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
