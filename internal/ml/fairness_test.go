package ml

import (
	"context"
	"strings"
	"testing"
)

func TestNewFairnessChecker(t *testing.T) {
	c := NewFairnessChecker("gender")
	if c == nil {
		t.Fatal("expected checker, got nil")
	}
	if c.protectedAttribute != "gender" {
		t.Errorf("expected protected attribute 'gender', got %q", c.protectedAttribute)
	}
	if len(c.thresholds) == 0 {
		t.Error("expected default thresholds to be set")
	}
}

func TestSetThresholds(t *testing.T) {
	c := NewFairnessChecker("gender")

	thresholds := []FairnessThreshold{
		{Metric: MetricDisparateImpact, Threshold: 0.9, Comparison: "greater"},
	}

	c.SetThresholds(thresholds)

	if len(c.thresholds) != 1 {
		t.Errorf("expected 1 threshold, got %d", len(c.thresholds))
	}
}

func TestCheckFairness(t *testing.T) {
	ctx := context.Background()
	c := NewFairnessChecker("group")

	predictions := []interface{}{true, true, false, true, false, false, true, true}
	labels := []interface{}{true, false, false, true, true, false, true, false}
	groups := []interface{}{"A", "A", "A", "A", "B", "B", "B", "B"}

	result, err := c.CheckFairness(ctx, predictions, labels, groups)
	if err != nil {
		t.Fatalf("CheckFairness failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	if result.ProtectedAttrib != "group" {
		t.Errorf("expected protected attribute 'group', got %q", result.ProtectedAttrib)
	}

	if len(result.GroupMetrics) != 2 {
		t.Errorf("expected 2 group metrics, got %d", len(result.GroupMetrics))
	}

	if len(result.FairnessMetrics) == 0 {
		t.Error("expected at least one fairness metric")
	}
}

func TestCheckFairnessMismatchedLengths(t *testing.T) {
	ctx := context.Background()
	c := NewFairnessChecker("group")

	predictions := []interface{}{true, false}
	labels := []interface{}{true}
	groups := []interface{}{"A", "B"}

	_, err := c.CheckFairness(ctx, predictions, labels, groups)
	if err == nil {
		t.Error("expected error for mismatched lengths")
	}
}

func TestCheckFairnessEmptyData(t *testing.T) {
	ctx := context.Background()
	c := NewFairnessChecker("group")

	_, err := c.CheckFairness(ctx, []interface{}{}, []interface{}{}, []interface{}{})
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestCheckFairnessContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := NewFairnessChecker("group")
	_, err := c.CheckFairness(ctx, []interface{}{}, []interface{}{}, []interface{}{})
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestFairnessResultToJSON(t *testing.T) {
	result := &FairnessResult{
		ProtectedAttrib: "gender",
		OverallScore:    0.9,
		GroupMetrics: []GroupMetrics{
			{Name: "male", Size: 100, PositiveRate: 0.6},
			{Name: "female", Size: 100, PositiveRate: 0.55},
		},
		FairnessMetrics: []FairnessMetric{
			{Type: MetricDisparateImpact, Value: 0.92, Passed: true},
		},
	}

	data, err := result.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}
}

func TestFairnessResultSummary(t *testing.T) {
	result := &FairnessResult{
		ProtectedAttrib:  "gender",
		OverallScore:     0.9,
		PassedThresholds: true,
		GroupMetrics: []GroupMetrics{
			{Name: "male", Size: 100, PositiveRate: 0.6, TruePositiveRate: 0.8},
		},
		FairnessMetrics: []FairnessMetric{
			{Type: MetricDisparateImpact, Value: 0.92, Passed: true},
		},
	}

	summary := result.Summary()
	if summary == "" {
		t.Error("expected non-empty summary")
	}

	if !strings.Contains(summary, "gender") {
		t.Error("expected protected attribute in summary")
	}
}

func TestNewBiasDetector(t *testing.T) {
	d := NewBiasDetector()
	if d == nil {
		t.Fatal("expected detector, got nil")
	}
	if len(d.thresholds) == 0 {
		t.Error("expected default thresholds")
	}
}

func TestDetectBias(t *testing.T) {
	ctx := context.Background()
	d := NewBiasDetector()

	data := []map[string]interface{}{
		{"gender": "male", "age": 30},
		{"gender": "male", "age": 35},
		{"gender": "male", "age": 40},
		{"gender": "male", "age": 45},
		{"gender": "female", "age": 32},
	}

	report, err := d.DetectBias(ctx, data, []string{"gender"})
	if err != nil {
		t.Fatalf("DetectBias failed: %v", err)
	}

	if report == nil {
		t.Fatal("expected report, got nil")
	}

	// With 4:1 ratio, should detect imbalance.
	if len(report.Indicators) == 0 {
		t.Error("expected at least one bias indicator for imbalanced data")
	}
}

func TestDetectBiasMissingValues(t *testing.T) {
	ctx := context.Background()
	d := NewBiasDetector()

	data := []map[string]interface{}{
		{"gender": "male"},
		{"gender": "female"},
		{"gender": nil},
		{"gender": nil},
		{"gender": nil},
		{},
		{},
	}

	report, err := d.DetectBias(ctx, data, []string{"gender"})
	if err != nil {
		t.Fatalf("DetectBias failed: %v", err)
	}

	// High missing rate should be detected.
	foundMissing := false
	for _, ind := range report.Indicators {
		if ind.Type == BiasSelection && strings.Contains(ind.Description, "missing") {
			foundMissing = true
			break
		}
	}
	if !foundMissing {
		t.Error("expected missing value indicator")
	}
}

func TestDetectBiasEmptyData(t *testing.T) {
	ctx := context.Background()
	d := NewBiasDetector()

	_, err := d.DetectBias(ctx, []map[string]interface{}{}, []string{"gender"})
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestDetectBiasInvalidType(t *testing.T) {
	ctx := context.Background()
	d := NewBiasDetector()

	_, err := d.DetectBias(ctx, "not valid", []string{"gender"})
	if err == nil {
		t.Error("expected error for invalid data type")
	}
}

func TestDetectBiasContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	d := NewBiasDetector()
	_, err := d.DetectBias(ctx, []map[string]interface{}{}, []string{})
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestBiasReportToJSON(t *testing.T) {
	report := &BiasReport{
		RiskLevel:    "medium",
		OverallScore: 0.4,
		SummaryText:  "Some bias detected",
		Indicators: []BiasIndicator{
			{Type: BiasSampling, Attribute: "gender", Score: 0.5, Severity: "medium"},
		},
	}

	data, err := report.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}
}

func TestBiasReportSummary(t *testing.T) {
	report := &BiasReport{
		RiskLevel:    "high",
		OverallScore: 0.7,
		SummaryText:  "High bias detected",
		Indicators: []BiasIndicator{
			{Type: BiasSampling, Attribute: "gender", Description: "imbalance", Score: 0.7, Severity: "high"},
		},
	}

	summary := report.Summary()
	if summary == "" {
		t.Error("expected non-empty summary")
	}

	if !strings.Contains(summary, "HIGH") {
		t.Error("expected HIGH risk level in summary")
	}
}

func TestToBool(t *testing.T) {
	tests := []struct {
		input    interface{}
		expected bool
	}{
		{true, true},
		{false, false},
		{1, true},
		{0, false},
		{int64(1), true},
		{int64(0), false},
		{float64(1), true},
		{float64(0), false},
		{"true", true},
		{"1", true},
		{"yes", true},
		{"false", false},
		{"no", false},
		{nil, false},
	}

	for _, tt := range tests {
		result := toBool(tt.input)
		if result != tt.expected {
			t.Errorf("toBool(%v) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestFairnessMetricTypeConstants(t *testing.T) {
	metrics := []FairnessMetricType{
		MetricDemographicParity,
		MetricEqualizedOdds,
		MetricEqualOpportunity,
		MetricPredictiveParity,
		MetricDisparateImpact,
		MetricStatisticalParity,
	}

	for _, m := range metrics {
		if string(m) == "" {
			t.Error("fairness metric constant should not be empty")
		}
	}
}

func TestBiasTypeConstants(t *testing.T) {
	types := []BiasType{
		BiasSelection,
		BiasSampling,
		BiasLabel,
		BiasFeature,
		BiasAlgorithmic,
	}

	for _, bt := range types {
		if string(bt) == "" {
			t.Error("bias type constant should not be empty")
		}
	}
}

func TestCalculateGroupMetrics(t *testing.T) {
	c := NewFairnessChecker("group")

	acc := &groupAccumulator{
		name:         "test",
		size:         100,
		positivePred: 60,
		negativePred: 40,
		tp:           50,
		fp:           10,
		tn:           30,
		fn:           10,
	}

	gm := c.calculateGroupMetrics(acc)

	if gm.Name != "test" {
		t.Errorf("expected name 'test', got %q", gm.Name)
	}
	if gm.Size != 100 {
		t.Errorf("expected size 100, got %d", gm.Size)
	}
	if gm.PositiveRate != 0.6 {
		t.Errorf("expected positive rate 0.6, got %f", gm.PositiveRate)
	}
	// TPR = TP / (TP + FN) = 50 / 60 = 0.833...
	if gm.TruePositiveRate < 0.83 || gm.TruePositiveRate > 0.84 {
		t.Errorf("unexpected TPR: %f", gm.TruePositiveRate)
	}
	// FPR = FP / (FP + TN) = 10 / 40 = 0.25
	if gm.FalsePositiveRate != 0.25 {
		t.Errorf("expected FPR 0.25, got %f", gm.FalsePositiveRate)
	}
	// Precision = TP / (TP + FP) = 50 / 60 = 0.833...
	if gm.Precision < 0.83 || gm.Precision > 0.84 {
		t.Errorf("unexpected precision: %f", gm.Precision)
	}
}

func TestCalculateOverallRisk(t *testing.T) {
	d := NewBiasDetector()

	// No indicators - low risk.
	report := &BiasReport{Indicators: []BiasIndicator{}}
	d.calculateOverallRisk(report)
	if report.RiskLevel != "low" {
		t.Errorf("expected 'low' risk, got %q", report.RiskLevel)
	}

	// High severity indicator.
	report = &BiasReport{
		Indicators: []BiasIndicator{
			{Severity: "high", Score: 0.8},
		},
	}
	d.calculateOverallRisk(report)
	if report.RiskLevel != "high" {
		t.Errorf("expected 'high' risk, got %q", report.RiskLevel)
	}

	// Medium severity indicator.
	report = &BiasReport{
		Indicators: []BiasIndicator{
			{Severity: "medium", Score: 0.5},
		},
	}
	d.calculateOverallRisk(report)
	if report.RiskLevel != "medium" {
		t.Errorf("expected 'medium' risk, got %q", report.RiskLevel)
	}
}

// Benchmark tests for fairness checking and bias detection.

func BenchmarkFairnessCheckSmall(b *testing.B) {
	checker := NewFairnessChecker("group")

	// Create small dataset: 100 samples, 2 groups.
	predictions := make([]interface{}, 100)
	labels := make([]interface{}, 100)
	groups := make([]interface{}, 100)

	for i := 0; i < 100; i++ {
		predictions[i] = i % 2
		labels[i] = i % 2
		if i < 50 {
			groups[i] = "A"
		} else {
			groups[i] = "B"
		}
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = checker.CheckFairness(ctx, predictions, labels, groups)
	}
}

func BenchmarkFairnessCheckMedium(b *testing.B) {
	checker := NewFairnessChecker("group")

	// Create medium dataset: 1000 samples, 5 groups.
	predictions := make([]interface{}, 1000)
	labels := make([]interface{}, 1000)
	groups := make([]interface{}, 1000)

	groupNames := []string{"A", "B", "C", "D", "E"}
	for i := 0; i < 1000; i++ {
		predictions[i] = i % 2
		labels[i] = i % 2
		idx := i % len(groupNames)
		groups[i] = groupNames[idx] //nolint:gosec // Index is always in bounds due to modulo.
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = checker.CheckFairness(ctx, predictions, labels, groups)
	}
}

func BenchmarkFairnessCheckLarge(b *testing.B) {
	checker := NewFairnessChecker("group")

	// Create large dataset: 10000 samples, 10 groups.
	predictions := make([]interface{}, 10000)
	labels := make([]interface{}, 10000)
	groups := make([]interface{}, 10000)

	groupNames := []string{"G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8", "G9", "G10"}
	for i := 0; i < 10000; i++ {
		predictions[i] = i % 2
		labels[i] = i % 2
		idx := i % len(groupNames)
		groups[i] = groupNames[idx] //nolint:gosec // Index is always in bounds due to modulo.
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = checker.CheckFairness(ctx, predictions, labels, groups)
	}
}

func BenchmarkBiasDetectionSmall(b *testing.B) {
	detector := NewBiasDetector()

	data := []map[string]interface{}{}
	for i := 0; i < 100; i++ {
		data = append(data, map[string]interface{}{
			"feature": float64(i),
			"label":   i % 2,
		})
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = detector.DetectBias(ctx, data, []string{"feature"})
	}
}

func BenchmarkBiasDetectionLarge(b *testing.B) {
	detector := NewBiasDetector()

	data := make([]map[string]interface{}, 10000)
	for i := range data {
		data[i] = map[string]interface{}{
			"feature1": float64(i),
			"feature2": float64(i % 100),
			"feature3": float64(i * 2),
			"label":    i % 2,
		}
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = detector.DetectBias(ctx, data, []string{"feature1", "feature2", "feature3"})
	}
}

// Fuzz tests for fairness and bias detection.

func FuzzFairnessCheck(f *testing.F) {
	// Add seed corpus.
	f.Add(0, 0, "A")
	f.Add(1, 1, "B")
	f.Add(0, 1, "A")
	f.Add(1, 0, "B")

	checker := NewFairnessChecker("group")
	ctx := context.Background()

	f.Fuzz(func(t *testing.T, prediction, label int, group string) {
		predictions := []interface{}{prediction}
		labels := []interface{}{label}
		groups := []interface{}{group}

		// Should not panic.
		_, _ = checker.CheckFairness(ctx, predictions, labels, groups)
	})
}

func FuzzBiasDetection(f *testing.F) {
	// Add seed corpus.
	f.Add(1.0, 0)
	f.Add(-1.0, 1)
	f.Add(0.0, 0)
	f.Add(100.0, 1)

	detector := NewBiasDetector()
	ctx := context.Background()

	f.Fuzz(func(t *testing.T, featureVal float64, label int) {
		data := []map[string]interface{}{
			{
				"feature": featureVal,
				"label":   label,
			},
		}

		// Should not panic.
		_, _ = detector.DetectBias(ctx, data, []string{"feature"})
	})
}
