# Corso Helm Chart

eBPF program allowlist and audit daemon for Kubernetes.

## Installation

### From OCI registry (recommended)

```bash
helm install corso oci://ghcr.io/azemoning/charts/corso --version 0.1.0
```

### From source

```bash
helm install corso ./chart/corso
```

### With custom values

```bash
helm install corso oci://ghcr.io/azemoning/charts/corso \
  --set image.tag=v0.1.0 \
  --set webhook.url=https://hooks.example.com/corso
```

## Upgrading

### From OCI registry

```bash
helm upgrade corso oci://ghcr.io/azemoning/charts/corso --version 0.2.0
```

### From source

```bash
helm upgrade corso ./chart/corso
```

## Uninstalling

```bash
helm uninstall corso
```

## Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Container image repository | `ghcr.io/azemoning/corso` |
| `image.tag` | Container image tag (defaults to appVersion) | `""` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.name` | Service account name (auto-generated if empty) | `""` |
| `rbac.create` | Create RBAC resources | `true` |
| `daemonset.privileged` | Run daemonset in privileged mode | `true` |
| `daemonset.resources.requests.cpu` | CPU request | `50m` |
| `daemonset.resources.requests.memory` | Memory request | `64Mi` |
| `daemonset.resources.limits.cpu` | CPU limit | `200m` |
| `daemonset.resources.limits.memory` | Memory limit | `128Mi` |
| `agent.pollInterval` | Agent polling interval | `30s` |
| `agent.metricsPort` | Metrics port | `9090` |
| `webhook.url` | Webhook URL for notifications | `""` |
| `webhook.timeout` | Webhook timeout | `10s` |
| `allowlist.defaultAction` | Default action for unknown programs | `alert` |
| `allowlist.ignoreKnownDaemons` | Ignore known daemon programs | `true` |
| `controller.enabled` | Enable controller component | `true` |
| `dashboard.enabled` | Enable Grafana dashboard | `true` |
| `opaPolicies.enabled` | Enable OPA policies | `false` |

## Example: Custom values file

```yaml
# custom-values.yaml
image:
  tag: v0.2.0

webhook:
  url: https://hooks.example.com/corso
  timeout: 15s

allowlist:
  defaultAction: block

dashboard:
  enabled: true
```

```bash
helm install corso oci://ghcr.io/azemoning/charts/corso -f custom-values.yaml
```
