package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

const (
	defaultTimeout = 5 * time.Second
	maxRetries     = 3
	initialBackoff = 500 * time.Millisecond
)

// AlertPayload is the JSON body sent to webhook endpoints
type AlertPayload struct {
	Node          string `json:"node"`
	Timestamp     string `json:"timestamp"`
	ProgramID     uint32 `json:"program_id"`
	ProgramName   string `json:"program_name"`
	ProgramType   string `json:"program_type"`
	OwnerPod      string `json:"owner_pod"`
	OwnerNamespace string `json:"owner_namespace"`
	Severity      string `json:"severity"`
}

// WebhookAlert sends violation alerts to an HTTP webhook
type WebhookAlert struct {
	url     string
	headers map[string]string
	timeout time.Duration
	retries int
	client  *http.Client
	isSlack bool
}

// NewWebhookAlert creates a WebhookAlert configured from environment variables
func NewWebhookAlert() *WebhookAlert {
	url := os.Getenv("CORSO_WEBHOOK_URL")
	if url == "" {
		return nil
	}

	w := &WebhookAlert{
		url:     url,
		headers: make(map[string]string),
		timeout: defaultTimeout,
		retries: maxRetries,
		isSlack: isSlackWebhook(url),
		client: &http.Client{
			Timeout: defaultTimeout,
		},
	}

	if v := os.Getenv("CORSO_WEBHOOK_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			w.timeout = d
			w.client.Timeout = d
		}
	}

	return w
}

// isSlackWebhook returns true if the URL looks like a Slack incoming webhook
func isSlackWebhook(url string) bool {
	return strings.Contains(url, "hooks.slack.com")
}

// SendAlert sends an alert payload to the webhook endpoint with retry
func (w *WebhookAlert) SendAlert(payload *AlertPayload) {
	if w == nil {
		return
	}

	var body []byte
	var err error

	if w.isSlack {
		body, err = json.Marshal(toSlackPayload(payload))
	} else {
		body, err = json.Marshal(payload)
	}
	if err != nil {
		klog.Errorf("Webhook: failed to marshal payload: %v", err)
		return
	}

	backoff := initialBackoff
	for attempt := 0; attempt <= w.retries; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}

		ctx, cancel := context.WithTimeout(context.Background(), w.timeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
		if err != nil {
			cancel()
			klog.Errorf("Webhook: failed to create request: %v", err)
			return
		}

		req.Header.Set("Content-Type", "application/json")
		for k, v := range w.headers {
			req.Header.Set(k, v)
		}

		resp, err := w.client.Do(req)
		cancel()

		if err != nil {
			klog.Warningf("Webhook: attempt %d/%d failed: %v", attempt+1, w.retries+1, err)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			klog.V(2).Infof("Webhook: alert sent successfully (status %d)", resp.StatusCode)
			return
		}
		klog.Warningf("Webhook: attempt %d/%d got status %d", attempt+1, w.retries+1, resp.StatusCode)
	}

	klog.Errorf("Webhook: all %d attempts failed for %s", w.retries+1, w.url)
}

// SlackMessage is the payload format for Slack incoming webhooks
type SlackMessage struct {
	Text string `json:"text"`
}

// toSlackPayload converts an AlertPayload into Slack incoming webhook format
func toSlackPayload(p *AlertPayload) *SlackMessage {
	severity := strings.ToUpper(p.Severity)
	owner := p.OwnerPod
	if owner == "" {
		owner = "host-process"
	} else {
		owner = fmt.Sprintf("%s/%s", p.OwnerNamespace, p.OwnerPod)
	}

	return &SlackMessage{
		Text: fmt.Sprintf(":warning: *%s*: Unauthorized eBPF program detected\n"+
			"• *Node:* %s\n"+
			"• *Program:* `%s` (ID: %d, Type: %s)\n"+
			"• *Owner:* %s\n"+
			"• *Time:* %s",
			severity, p.Node, p.ProgramName, p.ProgramID, p.ProgramType,
			owner, p.Timestamp),
	}
}
