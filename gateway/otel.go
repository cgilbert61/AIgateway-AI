package main

import (
	"context"
	"log"
	"math"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

var (
	meter            metric.Meter
	vfeSurpriseGauge metric.Float64ObservableGauge
	beliefDivGauge   metric.Float64ObservableGauge
	blocksCounter    metric.Int64Counter

	// In-memory latest values for the observable gauges
	latestVfeSurprise float64
	latestBeliefDiv   float64
)

func initOTel() {
	// Initialize a simple metric exporter provider.
	// For production, this would register a Prometheus exporter or an OTLP GRPC/HTTP exporter.
	provider := sdkmetric.NewMeterProvider()
	otel.SetMeterProvider(provider)

	meter = provider.Meter("aiaiai-gateway")

	var err error
	blocksCounter, err = meter.Int64Counter(
		"active_inference.containment_blocks_total",
		metric.WithDescription("Total number of containment block events triggered by active inference or policy constraints"),
	)
	if err != nil {
		log.Printf("[OTel Error] Failed to create blocks counter: %v", err)
	}

	// Observable gauges are the standard way in OTel Go to record floating values that represent current state
	vfeSurpriseGauge, err = meter.Float64ObservableGauge(
		"active_inference.vfe_surprise",
		metric.WithDescription("Current Variational Free Energy surprise score"),
		metric.WithFloat64Callback(func(_ context.Context, obs metric.Float64Observer) error {
			obs.Observe(latestVfeSurprise)
			return nil
		}),
	)
	if err != nil {
		log.Printf("[OTel Error] Failed to create VFE surprise gauge: %v", err)
	}

	beliefDivGauge, err = meter.Float64ObservableGauge(
		"active_inference.belief_divergence",
		metric.WithDescription("KL Divergence of L2 belief states from baseline priors"),
		metric.WithFloat64Callback(func(_ context.Context, obs metric.Float64Observer) error {
			obs.Observe(latestBeliefDiv)
			return nil
		}),
	)
	if err != nil {
		log.Printf("[OTel Error] Failed to create belief divergence gauge: %v", err)
	}

	log.Println("[OTel] OpenTelemetry metrics provider initialized successfully.")
}

func recordOTelVFE(vfe float64) {
	latestVfeSurprise = vfe
}

func recordOTelBeliefDivergence(divergence float64) {
	latestBeliefDiv = divergence
}

func incrementOTelBlocks() {
	if blocksCounter != nil {
		blocksCounter.Add(context.Background(), 1)
	}
}

// recordActiveInferenceTelemetry computes KL divergence and records belief vector state and VFE surprise via OTel
func recordActiveInferenceTelemetry(beliefs []float64, vfe float64, decidedAction int) {
	// Baseline L1 resting priors
	priors := []float64{0.95, 0.04, 0.01}
	
	// Calculate KL divergence: D_KL(Q || P) = sum_i Q(i) * log(Q(i) / P(i))
	kl := 0.0
	for i := 0; i < len(beliefs) && i < len(priors); i++ {
		if beliefs[i] > 1e-12 {
			pVal := priors[i]
			if pVal < 1e-12 {
				pVal = 1e-12
			}
			kl += beliefs[i] * (math.Log(beliefs[i]) - math.Log(pVal))
		}
	}

	recordOTelVFE(vfe)
	recordOTelBeliefDivergence(kl)

	if decidedAction == ACTION_BLOCK {
		incrementOTelBlocks()
	}
}
