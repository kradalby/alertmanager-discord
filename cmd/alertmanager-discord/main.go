package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"text/template"
	"time"

	"github.com/Masterminds/sprig"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	alertmanager "github.com/prometheus/alertmanager/template"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	promModel "github.com/prometheus/common/model"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	jaegerPropagator "go.opentelemetry.io/contrib/propagators/jaeger"
	jaegerExporter "go.opentelemetry.io/otel/exporters/trace/jaeger"
)

var (
	httpRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "http",
			Name:      "requests_total",
		},
		[]string{"code", "method", "handler"},
	)

	alertsPayloadProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "alertmanager_discord_processed_alert_payloads_total",
		Help: "The total number of processed alert payloads",
	})
	alertsPayloadReceived = promauto.NewCounter(prometheus.CounterOpts{
		Name: "alertmanager_discord_alert_payloads_received_total",
		Help: "The total number of alert payloads received from Alertmanager",
	})
	alertsProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "alertmanager_discord_processed_alerts_total",
		Help: "The total number of processed alerts",
	})
	alertsReceived = promauto.NewCounter(prometheus.CounterOpts{
		Name: "alertmanager_discord_alerts_received_total",
		Help: "The total number of alerts received from Alertmanager",
	})
	alertsSent = promauto.NewCounter(prometheus.CounterOpts{
		Name: "alertmanager_discord_alerts_sent_total",
		Help: "The total number of alerts sent to Discord webhook",
	})
	alertsWithoutSilentURLSent = promauto.NewCounter(prometheus.CounterOpts{
		Name: "alertmanager_discord_alerts_sent_without_silence_total",
		Help: "The total number of alerts sent to Discord webhook without silence URL",
	})
	alertsFailedSent = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "alertmanager_discord_alerts_sent_failed_total",
		Help: "The total number of alerts that failed to send Discord webhook",
	}, []string{"code"})

	logger        log.Logger
	alertTemplate *template.Template
)

func init() {
	prometheus.MustRegister(httpRequests)

	alertTemplate = template.Must(
		template.New("alertTemplate").
			Funcs(sprig.TxtFuncMap()).
			Parse(alertTemplateStr),
	)
}

var errFailedAfter5Retries = errors.New("failed to send alert after 5 retries")

const alertTemplateStr string = `
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

{{- define "__alert_summary" -}}
  {{- if .Alert.Annotations.summary -}}
	{{ .Alert.Annotations.summary }}
  {{- else if .Alert.Annotations.message -}}
	{{ .Alert.Annotations.message }}
  {{- else -}}
	No summary found
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
**Summary:**
{{ template "__alert_summary" . }}
**Description:**
{{ template "__alert_description" . }}

**Severity:**
{{ template "__alert_severity" . }}

[Source]({{ .Alert.GeneratorURL }})
{{ template "__alert_runbook_link" . }}
{{- if .SilenceURL }}
[Silence]({{ .SilenceURL }})
{{- end }}
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

type DiscordRateLimitResponse struct {
	Message    string  `json:"message"`
	RetryAfter float64 `json:"retry_after"`
	Global     bool    `json:"global"`
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

func getAlertnameFromPayload(a *alertmanager.Data) string {
	if name, ok := a.CommonLabels["alertname"]; ok {
		return name
	} else if name, ok := a.GroupLabels["alertname"]; ok {
		return name
	}

	for _, alert := range a.Alerts {
		if name, ok := alert.Labels["alertname"]; ok {
			return name
		}
	}

	return "no alertname found"
}

func getAlertname(alerts []alertmanager.Alert, payload *alertmanager.Data) string {
	for _, alert := range alerts {
		if name, ok := alert.Labels["alertname"]; ok {
			return name
		}
	}

	return getAlertnameFromPayload(payload)
}

func createSilenceURL(externalURL string, alert alertmanager.Alert) string {
	baseURL := fmt.Sprintf("%s/#/silences/new?filter=", externalURL)
	labels := "{"

	for _, label := range alert.Labels.SortedPairs() {
		labels += fmt.Sprintf("%s=\"%s\",", label.Name, label.Value)
	}

	labels = labels[:len(labels)-1]
	labels += "}"
	baseURL += url.QueryEscape(labels)

	return baseURL
}

func newEmbed(
	temp *template.Template,
	data *alertmanager.Data,
	alerts []alertmanager.Alert,
	withSilence bool,
) DiscordEmbed {
	embed := DiscordEmbed{
		Title: fmt.Sprintf(
			"%s  [%d]  %s",
			getStatusEmoji(&alerts[0]),
			len(alerts),
			getAlertname(alerts, data),
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
		silenceURL := ""
		if withSilence {
			silenceURL = createSilenceURL(data.ExternalURL, alert)
		}

		var tpl bytes.Buffer

		err := temp.Execute(&tpl, struct {
			Alert       alertmanager.Alert
			ExternalURL string
			SilenceURL  string
		}{
			alert,
			data.ExternalURL,
			silenceURL,
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

func initTracer(logger log.Logger) func() {
	flush, err := jaegerExporter.InstallNewPipeline(
		jaegerExporter.WithCollectorEndpoint(""),
		jaegerExporter.WithProcess(jaegerExporter.Process{
			ServiceName: "alertmanager-discord",
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

	webhookEnv := os.Getenv("DISCORD_WEBHOOK")
	if webhookEnv == "" {
		level.Error(logger).Log("msg", "environment variable DISCORD_WEBHOOK not found")
		os.Exit(1)
	}

	level.Info(logger).Log("msg", "Listening on 0.0.0.0:9094")

	handler := func(path, name string, f http.HandlerFunc) {
		http.HandleFunc(path, promhttp.InstrumentHandlerCounter(
			httpRequests.MustCurryWith(prometheus.Labels{"handler": name}),
			otelhttp.NewHandler(f, name),
		))
	}

	handler("/", "root", root)
	handler("/-/healthy", "health", ok)
	handler("/webhook", "alertmanagerWebhook", alertmanagerHandler)
	http.Handle("/metrics", promhttp.Handler())

	err := http.ListenAndServe(":9094", nil)
	if err != nil {
		panic(err)
	}
}

func alertmanagerHandler(w http.ResponseWriter, r *http.Request) {
	webhookURL := os.Getenv("DISCORD_WEBHOOK")
	span := trace.SpanFromContext(r.Context())

	alertsPayloadReceived.Inc()

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		level.Error(logger).Log(
			"traceID", span.SpanContext().TraceID,
			"msg", fmt.Sprintf("failed to read Alertmanager request %s", err),
		)
		span.RecordError(err)
	}

	alertmanagerPayload := &alertmanager.Data{}

	err = json.Unmarshal(b, &alertmanagerPayload)
	if err != nil {
		level.Error(logger).Log("traceID", span.SpanContext().TraceID,
			"msg", fmt.Sprintf("failed to unmarshal alert %s", err),
		)
		span.RecordError(err)
	}

	level.Info(logger).Log(
		"traceID", span.SpanContext().TraceID,
		"msg", "received alert",
		"source", alertmanagerPayload.ExternalURL,
		"receiver", alertmanagerPayload.Receiver,
		"status", alertmanagerPayload.Status,
		"proto", r.Proto,
		"alertname", getAlertnameFromPayload(alertmanagerPayload),
	)

	for _, alert := range alertmanagerPayload.Alerts {
		alertsReceived.Inc()

		status, err := sendPayloadToDiscord(r.Context(), webhookURL, alertmanagerPayload, alert)
		if err != nil {
			level.Error(logger).Log(
				"traceID", span.SpanContext().TraceID,
				"webhookURL", webhookURL,
				"discord_status", status,
				"msg", fmt.Sprintf("failed to send request: %s", err),
			)
			span.RecordError(err)
		}

		alertsProcessed.Inc()

		// Space each post out a bit so we dont get too many 429.
		time.Sleep((time.Duration(1) * time.Second))
	}

	alertsPayloadProcessed.Inc()
}

func sendPayloadToDiscord(
	ctx context.Context,
	webhookURL string,
	data *alertmanager.Data,
	alert alertmanager.Alert,
) (int, error) {
	alertsSent.Inc()

	return sendPayloadToDiscordWithRetry(ctx, webhookURL, data, alert, true, 5)
}

func sendPayloadToDiscordWithRetry(
	ctx context.Context,
	webhookURL string,
	alertmanagerPayload *alertmanager.Data,
	alert alertmanager.Alert,
	withSilenceURL bool,
	retries int) (int, error) {
	tracer := otel.Tracer("")

	var span trace.Span
	_, span = tracer.Start(ctx, "sendPayloadToDiscord")

	defer span.End()

	embed := newEmbed(alertTemplate, alertmanagerPayload, []alertmanager.Alert{alert}, withSilenceURL)

	payload := DiscordWebhookPayload{
		Embeds: []DiscordEmbed{embed},
	}

	data, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, webhookURL, bytes.NewReader(data))
	if err != nil {
		span.RecordError(err)

		return 500, fmt.Errorf("failed to create request %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		span.RecordError(err)

		return 500, fmt.Errorf("failed to post message to discord %w", err)
	}
	defer resp.Body.Close()

	level.Info(logger).Log(
		"traceID", span.SpanContext().TraceID,
		"msg", "response received",
		"status", resp.Status,
		"status_code", resp.StatusCode,
		"proto", resp.Proto,
		"alertname", payload.Embeds[0].Title,
	)

	if resp.StatusCode == 400 {
		alertsFailedSent.WithLabelValues("400").Inc()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			span.RecordError(err)

			return 400, fmt.Errorf("failed to read Discord response %w", err)
		}

		level.Error(logger).Log(
			"traceID", span.SpanContext().TraceID,
			"msg", "Bad body",
			"status", resp.Status,
			"status_code", resp.StatusCode,
			"proto", resp.Proto,
			"response_body", string(body),
			"request_body", string(data),
			"alertname", payload.Embeds[0].Title,
		)

		if withSilenceURL {
			return sendPayloadToDiscordWithRetry(ctx, webhookURL, alertmanagerPayload, alert, !withSilenceURL, retries)
		}

		return 400, fmt.Errorf("failed to send Discord response %w", err)
	}

	if resp.StatusCode == 429 {
		alertsFailedSent.WithLabelValues("429").Inc()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			span.RecordError(err)

			return 429, fmt.Errorf("failed to read Discord response %w", err)
		}

		ratelimitResponse := &DiscordRateLimitResponse{}

		err = json.Unmarshal(body, &ratelimitResponse)
		if err != nil {
			level.Error(logger).Log("traceID", span.SpanContext().TraceID,
				"msg", fmt.Sprintf("failed to unmarshal ratelimit response %s", err),
			)
			span.RecordError(err)
		}

		waitFor := ratelimitResponse.RetryAfter + 1

		level.Info(logger).Log(
			"traceID", span.SpanContext().TraceID,
			"msg", "received 'too many requests', backing off and retrieing",
			"status", resp.Status,
			"status_code", resp.StatusCode,
			"retry", fmt.Sprintf("%fs", waitFor),
			"proto", resp.Proto,
			"alertname", payload.Embeds[0].Title,
		)

		time.Sleep((time.Duration(waitFor) * time.Second))

		if retries > 0 {
			return sendPayloadToDiscordWithRetry(ctx, webhookURL, alertmanagerPayload, alert, withSilenceURL, retries-1)
		}

		return 429, errFailedAfter5Retries
	}

	if !withSilenceURL {
		silenceURL := createSilenceURL(alertmanagerPayload.ExternalURL, alert)
		level.Info(logger).Log(
			"traceID", span.SpanContext().TraceID,
			"msg", "Successfully sent alert _without_ silence URL",
			"silenceURL", silenceURL,
			"status", resp.Status,
			"status_code", resp.StatusCode,
			"proto", resp.Proto,
			"alertname", payload.Embeds[0].Title,
		)

		alertsWithoutSilentURLSent.Inc()
	}

	return 200, nil
}

func ok(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	span := trace.SpanFromContext(ctx)
	defer span.End()

	if _, err := w.Write([]byte("ok")); err != nil {
		span.RecordError(err)
	}
}

func root(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	span := trace.SpanFromContext(ctx)
	defer span.End()

	if r.URL.Path != "/" {
		http.NotFound(w, r)

		return
	}

	w.Header().Set("Content-type", "text/html")

	_, err := w.Write([]byte(`
	<p>Alertmanager to Discord</p>
	<ul>
	  <li><a href="/-/healthy">/-/healthy</a>
	  <li><a href="/metrics">/metrics</a>
	  <li>/webhook (point Alertmanager here)
	</ul>`))
	if err != nil {
		span.RecordError(err)
	}
}
