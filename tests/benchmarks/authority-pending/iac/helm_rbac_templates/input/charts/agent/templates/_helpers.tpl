{{- define "agent.fullname" -}}{{ .Release.Name }}-agent{{- end }}
{{- define "agent.serviceAccountName" -}}{{ include "agent.fullname" . }}{{- end }}
