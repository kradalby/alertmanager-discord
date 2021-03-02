package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/Masterminds/sprig"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	alertmanager "github.com/prometheus/alertmanager/template"
	promModel "github.com/prometheus/common/model"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	jaegerPropagator "go.opentelemetry.io/contrib/propagators/jaeger"
	jaegerExporter "go.opentelemetry.io/otel/exporters/trace/jaeger"
)

const alertTemplateStr string = `
{{- define "__alert_silence_link" -}}
    {{ .ExternalURL }}/#/silences/new?filter=%7B
    {{- range .Alert.Labels.SortedPairs -}}
        {{- if ne .Name "alertname" -}}
            {{- .Name }}%3D"{{- .Value -}}"%2C%20
        {{- end -}}
    {{- end -}}
    alertname%3D"{{ .Alert.Labels.alertname }}"%7D
{{- end -}}

{{- define "__alertmanager_link" -}}
  {{- $name := .ExternalURL | trimPrefix "https://" -}}
  {{- $name = $name | trimPrefix "https://" -}}
  [{{ $name }}]({{ .ExternalURL }})
{{- end -}}

{{- define "__alert_severity_prefix" -}}
    {{ if ne .Alert.Status "firing" -}}
    :green_heart:
    {{- else if eq .Alert.Labels.severity "critical" -}}
    :fire:
    {{- else if eq .Alert.Labels.severity "warning" -}}
    :warning:
    {{- else -}}
    :question:
    {{- end }}
{{- end -}}

{{- define "__alert_severity" -}}
    {{ if ne .Alert.Status "firing" -}}
    :green_heart: Resolved
    {{- else if eq .Alert.Labels.severity "critical" -}}
    :fire: Critical
    {{- else if eq .Alert.Labels.severity "warning" -}}
    :warning: Warning
    {{- else -}}
    :question: Unknown
    {{- end }}
{{- end -}}

{{- define "__alert_runbook_link" -}}
  {{- if .Alert.Annotations.runbook -}}
	[Runbook]({{- .Alert.Annotations.runbook -}})
  {{- else if .Alert.Annotations.runbook_url -}}
	[Runbook]({{- .Alert.Annotations.runbook_url -}})
  {{- else -}}
	No runbook annotation found
  {{- end -}}
{{- end -}}

{{- define "__alert_description" -}}
  {{- if .Alert.Annotations.description -}}
	{{ .Alert.Annotations.description }}
  {{- else if .Alert.Annotations.message -}}
	{{ .Alert.Annotations.message }}
  {{- else if .Alert.Annotations.summary -}}
	{{ .Alert.Annotations.summary }}
  {{- else -}}
	No description found
  {{- end -}}
{{- end -}}

{{- define "__alert_instance" -}}
  {{- if .Alert.Labels.instance }}
**Instance:**
{{ .Alert.Labels.instance }}
  {{ end -}}
{{- end -}}

{{- define "__alert_job" -}}
  {{- if .Alert.Labels.job }}
**Job:**
{{ .Alert.Labels.job }}
  {{ end -}}
{{- end -}}

{{- define "__alert_namespace" -}}
  {{- if .Alert.Labels.namespace }}
**Namespace:**
{{ .Alert.Labels.namespace }}
  {{ end -}}
{{- end -}}

{{- define "__alert_site" -}}
  {{- if .Alert.Labels.site }}
**Site:**
{{ .Alert.Labels.site }}
  {{ end -}}
{{- end -}}

--------------------------------

{{- template "__alert_instance" . }}
{{- template "__alert_job" . }}
{{- template "__alert_site" . }}
{{- template "__alert_namespace" . }}
**Description:**
{{ template "__alert_description" . }}

**Severity:**
{{ template "__alert_severity" . }}

[Source]({{ .Alert.GeneratorURL }})
{{ template "__alert_runbook_link" . }}
[Silence]({{ template "__alert_silence_link" . }})
Sent by: {{ template "__alertmanager_link" . }}
`

const (
	colorRed   = 14177041
	colorGreen = 3394560
)

type DiscordEmbed struct {
	Author struct {
		Name    string `json:"name"`
		URL     string `json:"url"`
		IconURL string `json:"icon_url"`
	} `json:"author,omitempty"`
	Title       string              `json:"title,omitempty"`
	URL         string              `json:"url,omitempty"`
	Description string              `json:"description,omitempty"`
	Color       int                 `json:"color,omitempty"`
	Fields      []DiscordEmbedField `json:"fields,omitempty"`
	Thumbnail   struct {
		URL string `json:"url"`
	} `json:"thumbnail,omitempty"`
	Image struct {
		URL string `json:"url"`
	} `json:"image,omitempty"`
	Footer struct {
		Text    string `json:"text"`
		IconURL string `json:"icon_url"`
	} `json:"footer,omitempty"`
}

type DiscordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

type DiscordWebhookPayload struct {
	Username  string         `json:"username"`
	AvatarURL string         `json:"avatar_url"`
	Content   string         `json:"content,omitempty"`
	Embeds    []DiscordEmbed `json:"embeds,omitempty"`
}

func getColour(alert *alertmanager.Alert) int {
	switch alert.Status {
	case string(promModel.AlertFiring):
		return colorRed
	case string(promModel.AlertResolved):
		return colorGreen
	default:
		return 0
	}
}

func getStatusEmoji(alert *alertmanager.Alert) string {
	switch alert.Status {
	case string(promModel.AlertFiring):
		return ":fire:"
	case string(promModel.AlertResolved):
		return ":green_heart:"
	default:
		return ""
	}
}

func getAlertname(a *alertmanager.Data) string {
	if name, ok := a.CommonLabels["alertname"]; ok {
		return name
	} else if name, ok := a.GroupLabels["alertname"]; ok {
		return name
	}

	return "no alertname found"
}

func newEmbed(temp *template.Template, data *alertmanager.Data, alerts []alertmanager.Alert) DiscordEmbed {
	embed := DiscordEmbed{
		Title: fmt.Sprintf(
			"%s  [%d]  %s",
			getStatusEmoji(&alerts[0]),
			len(alerts),
			getAlertname(data),
		),
		URL:   data.ExternalURL,
		Color: getColour(&alerts[0]),
	}

	fields := []DiscordEmbedField{
		// {
		// 	Name:   "Severity",
		// 	Value:  getSeverity(data),
		// 	Inline: true,
		// },
	}

	for _, alert := range alerts {
		var tpl bytes.Buffer

		err := temp.Execute(&tpl, struct {
			Alert       alertmanager.Alert
			ExternalURL string
		}{
			alert,
			data.ExternalURL,
		},
		)
		if err != nil {
			level.Error(logger).Log("msg", fmt.Sprintf("error: failed to build message from template %s", err))
		}

		field := DiscordEmbedField{
			Name:  "Information",
			Value: tpl.String(),
		}
		fields = append(fields, field)
	}

	embed.Fields = fields

	return embed
}

var logger log.Logger

func initTracer(logger log.Logger) func() {
	flush, err := jaegerExporter.InstallNewPipeline(
		jaegerExporter.WithCollectorEndpoint(""),
		jaegerExporter.WithProcess(jaegerExporter.Process{
			ServiceName: "thanos-remote-read",
		}),
		jaegerExporter.WithDisabled(true),
		jaegerExporter.WithDisabledFromEnv(),
	)
	if err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
		jaegerPropagator.Jaeger{},
	))

	return flush
}

func main() {
	logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	logger = level.NewFilter(logger, level.AllowDebug())
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)

	_ = initTracer(logger)

	webhookURL := os.Getenv("DISCORD_WEBHOOK")
	whURL := flag.String("webhook.url", webhookURL, "")
	flag.Parse()

	if webhookURL == "" && *whURL == "" {
		level.Error(logger).Log("msg", "environment variable DISCORD_WEBHOOK not found")
		os.Exit(1)
	}

	alertTemplate := template.Must(
		template.New("alertTemplate").
			Funcs(sprig.FuncMap()).
			Parse(alertTemplateStr),
	)

	level.Info(logger).Log("msg", "Listening on 0.0.0.0:9094")

	err := http.ListenAndServe(":9094", otelhttp.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		tracer := otel.Tracer("")
		var span trace.Span
		_, span = tracer.Start(ctx, "remoteRead")
		defer span.End()

		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			level.Error(logger).Log(
				"traceID", span.SpanContext().TraceID,
				"msg", fmt.Sprintf("failed to read Alertmanager request %s", err),
			)
		}

		alertmanagerPayload := &alertmanager.Data{}
		err = json.Unmarshal(b, &alertmanagerPayload)
		if err != nil {
			level.Error(logger).Log("traceID", span.SpanContext().TraceID,
				"msg", fmt.Sprintf("failed to unmarshal alert %s", err),
			)
		}

		level.Info(logger).Log(
			"traceID", span.SpanContext().TraceID,
			"msg", "received alert",
			"source", alertmanagerPayload.ExternalURL,
			"receiver", alertmanagerPayload.Receiver,
			"status", alertmanagerPayload.Status,
			"proto", r.Proto,
			"alertname", getAlertname(alertmanagerPayload),
		)

		payload := DiscordWebhookPayload{
			Embeds: []DiscordEmbed{},
		}

		firing := alertmanagerPayload.Alerts.Firing()
		if len(firing) != 0 {
			embed := newEmbed(alertTemplate, alertmanagerPayload, firing)
			payload.Embeds = append(payload.Embeds, embed)
		}

		resolved := alertmanagerPayload.Alerts.Resolved()
		if len(resolved) != 0 {
			embed := newEmbed(alertTemplate, alertmanagerPayload, resolved)
			payload.Embeds = append(payload.Embeds, embed)
		}

		data, _ := json.Marshal(payload)

		req, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, *whURL, bytes.NewReader(data))
		if err != nil {
			level.Error(logger).Log(
				"traceID", span.SpanContext().TraceID,
				"msg", fmt.Sprintf("failed to create request %s", err),
			)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			level.Error(logger).Log(
				"traceID", span.SpanContext().TraceID,
				"msg", fmt.Sprintf("failed to post message to discord %s", err),
			)
		}

		level.Info(logger).Log(
			"traceID", span.SpanContext().TraceID,
			"msg", "response received",
			"status", resp.Status,
			"status_code", resp.StatusCode,
			"proto", resp.Proto,
		)

		defer resp.Body.Close()
	}), "webhook"),
	)
	if err != nil {
		panic(err)
	}
}
