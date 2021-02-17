package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/Masterminds/sprig"
	alertmanager "github.com/prometheus/alertmanager/template"
	promModel "github.com/prometheus/common/model"
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

{{- define "__alert_runbook_link" -}}
  {{- if .Alert.Annotations.runbook -}}
	[Runbook]({{- .Alert.Annotations.runbook -}})
  {{- else if .Alert.Annotations.runbook_url -}}
	[Runbook]({{- .Alert.Annotations.runbook_url -}})
  {{- else -}}
	No runbook annotation found
  {{- end -}}
{{- end -}}

{{- define "__alert_instance" -}}
  {{- if .Alert.Labels.hpa }}
	**Resources:**
	{{ .Alert.Labels.hpa }}
  {{- else if .Alert.Labels.job_name }}
	**Resources:**
	{{ .Alert.Labels.job_name }}
  {{- else if .Alert.Labels.deployment }}
	**Resources:**
	{{ .Alert.Labels.deployment }}
  {{- else if .Alert.Labels.pod }}
	**Resources:**
	{{ .Alert.Labels.pod }}
  {{- else if .Alert.Labels.node }}
	**Resources:**
	{{ .Alert.Labels.node }}
  {{- else if .Alert.Labels.cronjob }}
	**Resources:**
	{{ .Alert.Labels.cronjob }}
  {{- else if .Alert.Labels.instance }}
	**Resources:**
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


{{- template "__alert_instance" . }}

**Description:**
{{ template "__alert_description" . }}
:link: {{ template "__alert_runbook_link" . }}
:link: [Silence]({{ template "__alert_silence_link" . }})

**Severity:**
{{ template "__alert_severity" . }}

**Team Responsible:**
:firefighter:

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
			log.Printf("error: failed to build message from template %s", err)
		}

		field := DiscordEmbedField{
			Name:  "---------------------------------------------------------------------",
			Value: tpl.String(),
		}
		fields = append(fields, field)
	}

	embed.Fields = fields

	return embed
}

func main() {
	webhookURL := os.Getenv("DISCORD_WEBHOOK")
	whURL := flag.String("webhook.url", webhookURL, "")
	flag.Parse()

	if webhookURL == "" && *whURL == "" {
		fmt.Fprintf(os.Stderr, "error: environment variable DISCORD_WEBHOOK not found\n")
		os.Exit(1)
	}

	alertTemplate := template.Must(
		template.New("alertTemplate").
			Funcs(sprig.FuncMap()).
			Parse(alertTemplateStr),
	)

	fmt.Fprintf(os.Stdout, "info: Listening on 0.0.0.0:9094\n")

	err := http.ListenAndServe(":9094", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}

		alertmanagerPayload := &alertmanager.Data{}
		err = json.Unmarshal(b, &alertmanagerPayload)
		if err != nil {
			panic(err)
		}

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
			log.Printf("error: failed to create request %s", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("error: failed to post message to discord %s", err)
		}

		defer resp.Body.Close()
	}),
	)
	if err != nil {
		panic(err)
	}
}
