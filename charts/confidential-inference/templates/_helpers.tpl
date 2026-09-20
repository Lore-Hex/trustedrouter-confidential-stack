{{- define "trcs.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "trcs.fullname" -}}
{{- default (printf "%s-%s" .Release.Name (include "trcs.name" .)) .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "trcs.selectorLabels" -}}
app.kubernetes.io/name: {{ include "trcs.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "trcs.labels" -}}
{{ include "trcs.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/part-of: trustedrouter-confidential-stack
{{- if .Values.labels.chart }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end }}
{{- if .Values.labels.managedBy }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
{{- end -}}
{{- define "trcs.image" -}}
{{- if .digest -}}{{ printf "%s@%s" .repository .digest }}{{- else -}}{{ printf "%s:%s" .repository .tag }}{{- end -}}
{{- end -}}
{{- define "trcs.engineImage" -}}
{{- $repo := .Values.inference.image.repository -}}
{{- $tag := .Values.inference.image.tag -}}
{{- if eq .Values.inference.engine "sglang" -}}
{{- $repo = default "lmsysorg/sglang" $repo -}}{{- $tag = default "v0.5.20" $tag -}}
{{- else -}}
{{- $repo = default "vllm/vllm-openai" $repo -}}{{- $tag = default "v0.29.0" $tag -}}
{{- end -}}
{{- include "trcs.image" (dict "repository" $repo "tag" $tag "digest" .Values.inference.image.digest) -}}
{{- end -}}
{{- define "trcs.shimImage" -}}
{{- include "trcs.image" (dict "repository" .Values.shim.image.repository "tag" (default .Chart.AppVersion .Values.shim.image.tag) "digest" .Values.shim.image.digest) -}}
{{- end -}}
{{- define "trcs.guardrails" -}}
{{- if not (has .Values.inference.engine (list "vllm" "sglang")) -}}{{ fail "inference.engine must be vllm or sglang" }}{{- end -}}
{{- if eq .Values.tee.mode "coco" -}}
{{- if not (has .Values.tee.coco.platform (list "sev-snp" "tdx")) -}}{{ fail "coco requires tee.coco.platform: sev-snp or tdx" }}{{- end -}}
{{- if not (and .Values.inference.image.digest .Values.shim.image.digest) -}}{{ fail "coco requires digest-pinned images for both inference and shim" }}{{- end -}}
{{- if not .Values.tee.coco.runtimeClassName -}}{{ fail "coco requires tee.coco.runtimeClassName" }}{{- end -}}
{{- if not (hasPrefix "kata-" .Values.tee.coco.runtimeClassName) -}}{{ fail "coco runtimeClassName must start with kata-" }}{{- end -}}
{{- if and (eq .Values.tee.coco.platform "sev-snp") (contains "tdx" .Values.tee.coco.runtimeClassName) -}}{{ fail "tee.coco.platform sev-snp disagrees with a tdx runtimeClassName" }}{{- end -}}
{{- if and (eq .Values.tee.coco.platform "tdx") (contains "snp" .Values.tee.coco.runtimeClassName) -}}{{ fail "tee.coco.platform tdx disagrees with an snp runtimeClassName" }}{{- end -}}
{{- if and (eq .Values.inference.cache.type "pvc") (not .Values.tee.coco.allowHostProvidedCache) -}}{{ fail "coco refuses a PersistentVolumeClaim model cache: it is host-provided storage and the host could alter cached weights. Set tee.coco.allowHostProvidedCache=true to accept that" }}{{- end -}}
{{- if not .Values.inference.gpu.resourceName -}}{{ fail "coco requires explicit inference.gpu.resourceName" }}{{- end -}}
{{- if .Values.shim.tls.existingSecret -}}{{ fail "shim.tls.existingSecret is allowed only in mode none" }}{{- end -}}
{{- if and (gt (int .Values.inference.gpu.count) 1) (not .Values.tee.coco.allowMultiGpu) -}}{{ fail "coco single-GPU passthrough: set tee.coco.allowMultiGpu=true to acknowledge multi-GPU support must be verified" }}{{- end -}}
{{- end -}}
{{- if and (eq .Values.inference.cache.type "pvc") (not .Values.inference.cache.existingClaim) -}}{{ fail "cache type pvc requires inference.cache.existingClaim" }}{{- end -}}
{{- end -}}
