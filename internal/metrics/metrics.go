package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// ProgramsTotal is a gauge tracking the number of eBPF programs by node, type, and allow status
	ProgramsTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "corso_programs_total",
			Help: "Total number of eBPF programs currently tracked",
		},
		[]string{"node", "type", "allowed"},
	)

	// ViolationsTotal is a counter tracking the total number of violations detected
	ViolationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "corso_violations_total",
			Help: "Total number of unauthorized eBPF program violations detected",
		},
		[]string{"node"},
	)

	// ScanDurationSeconds is a histogram tracking the duration of eBPF program scans
	ScanDurationSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "corso_scan_duration_seconds",
			Help:    "Duration of eBPF program enumeration scans in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		},
	)

	// EnforcementTotal is a counter tracking enforcement actions
	EnforcementTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "corso_enforcement_total",
			Help: "Total number of eBPF program enforcement actions",
		},
		[]string{"mode", "action"},
	)
)

// Register registers all Corso metrics with the default Prometheus registry
func Register() {
	prometheus.MustRegister(ProgramsTotal)
	prometheus.MustRegister(ViolationsTotal)
	prometheus.MustRegister(ScanDurationSeconds)
	prometheus.MustRegister(EnforcementTotal)
}
