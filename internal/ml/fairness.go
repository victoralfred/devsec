package ml

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
)

// FairnessMetricType represents a fairness metric type.
type FairnessMetricType string

const (
	// MetricDemographicParity measures equal positive prediction rates.
	MetricDemographicParity FairnessMetricType = "demographic_parity"
	// MetricEqualizedOdds measures equal TPR and FPR across groups.
	MetricEqualizedOdds FairnessMetricType = "equalized_odds"
	// MetricEqualOpportunity measures equal TPR across groups.
	MetricEqualOpportunity FairnessMetricType = "equal_opportunity"
	// MetricPredictiveParity measures equal precision across groups.
	MetricPredictiveParity FairnessMetricType = "predictive_parity"
	// MetricDisparateImpact measures ratio of positive rates.
	MetricDisparateImpact FairnessMetricType = "disparate_impact"
	// MetricStatisticalParity measures difference in positive rates.
	MetricStatisticalParity FairnessMetricType = "statistical_parity"
)

// FairnessThreshold defines threshold for fairness metrics.
// Fields ordered for optimal memory alignment.
type FairnessThreshold struct {
	Metric     FairnessMetricType `json:"metric"`
	Comparison string             `json:"comparison"`
	Threshold  float64            `json:"threshold"`
	LowerBound float64            `json:"lower_bound,omitempty"`
	UpperBound float64            `json:"upper_bound,omitempty"`
}

// GroupMetrics contains metrics for a single group.
// Fields ordered for optimal memory alignment.
type GroupMetrics struct {
	Name               string  `json:"name"`
	TruePositiveRate   float64 `json:"true_positive_rate"`
	FalsePositiveRate  float64 `json:"false_positive_rate"`
	Precision          float64 `json:"precision"`
	Recall             float64 `json:"recall"`
	PositiveRate       float64 `json:"positive_rate"`
	Size               int     `json:"size"`
	PositivePrediction int     `json:"positive_predictions"`
	NegativePrediction int     `json:"negative_predictions"`
	TruePositives      int     `json:"true_positives"`
	FalsePositives     int     `json:"false_positives"`
	TrueNegatives      int     `json:"true_negatives"`
	FalseNegatives     int     `json:"false_negatives"`
}

// FairnessMetric contains a single fairness metric result.
// Fields ordered for optimal memory alignment.
type FairnessMetric struct {
	Type        FairnessMetricType `json:"type"`
	Description string             `json:"description"`
	Value       float64            `json:"value"`
	Threshold   float64            `json:"threshold,omitempty"`
	Passed      bool               `json:"passed"`
}

// FairnessResult contains fairness analysis results.
// Fields ordered for optimal memory alignment.
type FairnessResult struct {
	Timestamp        time.Time        `json:"timestamp"`
	ProtectedAttrib  string           `json:"protected_attribute"`
	GroupMetrics     []GroupMetrics   `json:"group_metrics"`
	FairnessMetrics  []FairnessMetric `json:"fairness_metrics"`
	OverallScore     float64          `json:"overall_score"`
	PassedThresholds bool             `json:"passed_thresholds"`
}

// BiasType represents the type of bias.
type BiasType string

const (
	// BiasSelection represents selection bias.
	BiasSelection BiasType = "selection"
	// BiasSampling represents sampling bias.
	BiasSampling BiasType = "sampling"
	// BiasLabel represents label bias.
	BiasLabel BiasType = "label"
	// BiasFeature represents feature bias.
	BiasFeature BiasType = "feature"
	// BiasAlgorithmic represents algorithmic bias.
	BiasAlgorithmic BiasType = "algorithmic"
)

// BiasIndicator represents a potential bias indicator.
// Fields ordered for optimal memory alignment.
type BiasIndicator struct {
	Type        BiasType `json:"type"`
	Attribute   string   `json:"attribute"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"` // "low", "medium", "high"
	Score       float64  `json:"score"`
}

// BiasReport contains bias analysis results.
// Fields ordered for optimal memory alignment.
type BiasReport struct {
	Timestamp    time.Time       `json:"timestamp"`
	SummaryText  string          `json:"summary"`
	RiskLevel    string          `json:"risk_level"`
	Indicators   []BiasIndicator `json:"indicators"`
	OverallScore float64         `json:"overall_score"`
}

// FairnessChecker checks model fairness.
type FairnessChecker interface {
	// CheckFairness analyzes fairness for a protected attribute.
	CheckFairness(ctx context.Context, predictions, labels, groups []interface{}) (*FairnessResult, error)
	// SetThresholds sets fairness thresholds.
	SetThresholds(thresholds []FairnessThreshold)
}

// BiasDetector detects potential biases.
type BiasDetector interface {
	// DetectBias analyzes data for potential biases.
	DetectBias(ctx context.Context, data interface{}, protectedAttributes []string) (*BiasReport, error)
}

// SimpleFairnessChecker provides basic fairness checking.
type SimpleFairnessChecker struct {
	protectedAttribute string
	thresholds         []FairnessThreshold
}

// NewFairnessChecker creates a new fairness checker.
func NewFairnessChecker(protectedAttribute string) *SimpleFairnessChecker {
	return &SimpleFairnessChecker{
		protectedAttribute: protectedAttribute,
		thresholds: []FairnessThreshold{
			{Metric: MetricDisparateImpact, Threshold: 0.8, Comparison: "greater"},
			{Metric: MetricStatisticalParity, Threshold: 0.1, Comparison: "less"},
		},
	}
}

// SetThresholds sets fairness thresholds.
func (c *SimpleFairnessChecker) SetThresholds(thresholds []FairnessThreshold) {
	c.thresholds = thresholds
}

// CheckFairness analyzes fairness for predictions.
func (c *SimpleFairnessChecker) CheckFairness(ctx context.Context, predictions, labels, groups []interface{}) (*FairnessResult, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if len(predictions) != len(labels) || len(predictions) != len(groups) {
		return nil, ErrMismatchedLength
	}

	if len(predictions) == 0 {
		return nil, ErrEmptyData
	}

	result := &FairnessResult{
		Timestamp:       time.Now().UTC(),
		ProtectedAttrib: c.protectedAttribute,
		GroupMetrics:    make([]GroupMetrics, 0),
		FairnessMetrics: make([]FairnessMetric, 0),
	}

	// Group data by protected attribute.
	groupData := make(map[string]*groupAccumulator)
	for i := range predictions {
		groupName := fmt.Sprintf("%v", groups[i])
		pred := toBool(predictions[i])
		label := toBool(labels[i])

		if _, exists := groupData[groupName]; !exists {
			groupData[groupName] = &groupAccumulator{name: groupName}
		}

		acc := groupData[groupName]
		acc.size++

		if pred {
			acc.positivePred++
		} else {
			acc.negativePred++
		}

		// Confusion matrix using switch for clarity.
		switch {
		case pred && label:
			acc.tp++
		case pred && !label:
			acc.fp++
		case !pred && label:
			acc.fn++
		default:
			acc.tn++
		}
	}

	// Calculate metrics for each group.
	for _, acc := range groupData {
		gm := c.calculateGroupMetrics(acc)
		result.GroupMetrics = append(result.GroupMetrics, gm)
	}

	// Calculate fairness metrics.
	c.calculateFairnessMetrics(result)

	// Check thresholds.
	result.PassedThresholds = c.checkThresholds(result)

	// Calculate overall score.
	result.OverallScore = c.calculateOverallScore(result)

	return result, nil
}

type groupAccumulator struct {
	name         string
	size         int
	positivePred int
	negativePred int
	tp           int
	fp           int
	tn           int
	fn           int
}

// calculateGroupMetrics calculates metrics for a group.
func (c *SimpleFairnessChecker) calculateGroupMetrics(acc *groupAccumulator) GroupMetrics {
	gm := GroupMetrics{
		Name:               acc.name,
		Size:               acc.size,
		PositivePrediction: acc.positivePred,
		NegativePrediction: acc.negativePred,
		TruePositives:      acc.tp,
		FalsePositives:     acc.fp,
		TrueNegatives:      acc.tn,
		FalseNegatives:     acc.fn,
	}

	// Positive rate.
	if acc.size > 0 {
		gm.PositiveRate = float64(acc.positivePred) / float64(acc.size)
	}

	// True positive rate (recall).
	if acc.tp+acc.fn > 0 {
		gm.TruePositiveRate = float64(acc.tp) / float64(acc.tp+acc.fn)
		gm.Recall = gm.TruePositiveRate
	}

	// False positive rate.
	if acc.fp+acc.tn > 0 {
		gm.FalsePositiveRate = float64(acc.fp) / float64(acc.fp+acc.tn)
	}

	// Precision.
	if acc.tp+acc.fp > 0 {
		gm.Precision = float64(acc.tp) / float64(acc.tp+acc.fp)
	}

	return gm
}

// calculateFairnessMetrics calculates fairness metrics across groups.
func (c *SimpleFairnessChecker) calculateFairnessMetrics(result *FairnessResult) {
	if len(result.GroupMetrics) < 2 {
		return
	}

	// Find reference group (largest) and comparison groups.
	var refGroup *GroupMetrics
	for i := range result.GroupMetrics {
		if refGroup == nil || result.GroupMetrics[i].Size > refGroup.Size {
			refGroup = &result.GroupMetrics[i]
		}
	}

	// Calculate metrics comparing each group to reference.
	for _, gm := range result.GroupMetrics {
		if gm.Name == refGroup.Name {
			continue
		}

		// Disparate Impact (ratio of positive rates).
		var di float64
		if refGroup.PositiveRate > 0 {
			di = gm.PositiveRate / refGroup.PositiveRate
		}
		result.FairnessMetrics = append(result.FairnessMetrics, FairnessMetric{
			Type:        MetricDisparateImpact,
			Description: fmt.Sprintf("Ratio of positive rates (%s vs %s)", gm.Name, refGroup.Name),
			Value:       di,
		})

		// Statistical Parity (difference in positive rates).
		sp := math.Abs(gm.PositiveRate - refGroup.PositiveRate)
		result.FairnessMetrics = append(result.FairnessMetrics, FairnessMetric{
			Type:        MetricStatisticalParity,
			Description: fmt.Sprintf("Difference in positive rates (%s vs %s)", gm.Name, refGroup.Name),
			Value:       sp,
		})

		// Equal Opportunity (difference in TPR).
		eo := math.Abs(gm.TruePositiveRate - refGroup.TruePositiveRate)
		result.FairnessMetrics = append(result.FairnessMetrics, FairnessMetric{
			Type:        MetricEqualOpportunity,
			Description: fmt.Sprintf("Difference in TPR (%s vs %s)", gm.Name, refGroup.Name),
			Value:       eo,
		})
	}
}

// checkThresholds checks if all thresholds are met.
func (c *SimpleFairnessChecker) checkThresholds(result *FairnessResult) bool {
	for i, fm := range result.FairnessMetrics {
		for _, thresh := range c.thresholds {
			if fm.Type != thresh.Metric {
				continue
			}

			result.FairnessMetrics[i].Threshold = thresh.Threshold

			switch thresh.Comparison {
			case "greater":
				result.FairnessMetrics[i].Passed = fm.Value >= thresh.Threshold
			case "less":
				result.FairnessMetrics[i].Passed = fm.Value <= thresh.Threshold
			case "between":
				result.FairnessMetrics[i].Passed = fm.Value >= thresh.LowerBound && fm.Value <= thresh.UpperBound
			default:
				result.FairnessMetrics[i].Passed = true
			}

			if !result.FairnessMetrics[i].Passed {
				return false
			}
		}
	}
	return true
}

// calculateOverallScore calculates an overall fairness score.
func (c *SimpleFairnessChecker) calculateOverallScore(result *FairnessResult) float64 {
	if len(result.FairnessMetrics) == 0 {
		return 1.0
	}

	passedCount := 0
	for _, fm := range result.FairnessMetrics {
		if fm.Passed {
			passedCount++
		}
	}

	return float64(passedCount) / float64(len(result.FairnessMetrics))
}

// toBool converts a value to bool.
func toBool(v interface{}) bool {
	switch b := v.(type) {
	case bool:
		return b
	case int:
		return b != 0
	case int64:
		return b != 0
	case float64:
		return b != 0
	case string:
		return b == "true" || b == "1" || b == "yes"
	default:
		return false
	}
}

// SimpleBiasDetector provides basic bias detection.
type SimpleBiasDetector struct {
	thresholds map[BiasType]float64
}

// NewBiasDetector creates a new bias detector.
func NewBiasDetector() *SimpleBiasDetector {
	return &SimpleBiasDetector{
		thresholds: map[BiasType]float64{
			BiasSelection: 0.3,
			BiasSampling:  0.3,
			BiasLabel:     0.2,
			BiasFeature:   0.25,
		},
	}
}

// DetectBias analyzes data for potential biases.
func (d *SimpleBiasDetector) DetectBias(ctx context.Context, data interface{}, protectedAttributes []string) (*BiasReport, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	records, ok := data.([]map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: must be []map[string]interface{}", ErrInvalidDataType)
	}

	if len(records) == 0 {
		return nil, ErrEmptyData
	}

	report := &BiasReport{
		Timestamp:  time.Now().UTC(),
		Indicators: make([]BiasIndicator, 0),
	}

	// Check for imbalanced protected attributes.
	for _, attr := range protectedAttributes {
		if indicator := d.checkAttributeBalance(records, attr); indicator != nil {
			report.Indicators = append(report.Indicators, *indicator)
		}
	}

	// Check for missing values in protected attributes.
	for _, attr := range protectedAttributes {
		if indicator := d.checkMissingValues(records, attr); indicator != nil {
			report.Indicators = append(report.Indicators, *indicator)
		}
	}

	// Calculate overall risk.
	d.calculateOverallRisk(report)

	return report, nil
}

// checkAttributeBalance checks for class imbalance in protected attribute.
func (d *SimpleBiasDetector) checkAttributeBalance(records []map[string]interface{}, attr string) *BiasIndicator {
	counts := make(map[string]int)
	total := 0

	for _, record := range records {
		if val, exists := record[attr]; exists && val != nil {
			key := fmt.Sprintf("%v", val)
			counts[key]++
			total++
		}
	}

	if total == 0 || len(counts) < 2 {
		return nil
	}

	// Find min and max counts.
	minCount := total
	maxCount := 0
	for _, count := range counts {
		if count < minCount {
			minCount = count
		}
		if count > maxCount {
			maxCount = count
		}
	}

	// Calculate imbalance ratio.
	imbalance := 1.0 - float64(minCount)/float64(maxCount)

	if imbalance > d.thresholds[BiasSampling] {
		severity := "low"
		if imbalance > 0.7 {
			severity = "high"
		} else if imbalance > 0.5 {
			severity = "medium"
		}

		return &BiasIndicator{
			Type:        BiasSampling,
			Attribute:   attr,
			Description: fmt.Sprintf("significant class imbalance detected (%.1f%%)", imbalance*100),
			Score:       imbalance,
			Severity:    severity,
		}
	}

	return nil
}

// checkMissingValues checks for disproportionate missing values.
func (d *SimpleBiasDetector) checkMissingValues(records []map[string]interface{}, attr string) *BiasIndicator {
	total := len(records)
	missing := 0

	for _, record := range records {
		val, exists := record[attr]
		if !exists || val == nil || val == "" {
			missing++
		}
	}

	if total == 0 {
		return nil
	}

	missingRate := float64(missing) / float64(total)

	if missingRate > 0.1 { // More than 10% missing.
		severity := "low"
		if missingRate > 0.5 {
			severity = "high"
		} else if missingRate > 0.3 {
			severity = "medium"
		}

		return &BiasIndicator{
			Type:        BiasSelection,
			Attribute:   attr,
			Description: fmt.Sprintf("high missing value rate (%.1f%%)", missingRate*100),
			Score:       missingRate,
			Severity:    severity,
		}
	}

	return nil
}

// calculateOverallRisk calculates overall risk level.
func (d *SimpleBiasDetector) calculateOverallRisk(report *BiasReport) {
	if len(report.Indicators) == 0 {
		report.RiskLevel = "low"
		report.OverallScore = 0
		report.SummaryText = "No significant bias indicators detected"
		return
	}

	highCount := 0
	mediumCount := 0
	totalScore := 0.0

	for _, ind := range report.Indicators {
		totalScore += ind.Score
		switch ind.Severity {
		case "high":
			highCount++
		case "medium":
			mediumCount++
		}
	}

	report.OverallScore = totalScore / float64(len(report.Indicators))

	switch {
	case highCount > 0:
		report.RiskLevel = "high"
	case mediumCount > 0:
		report.RiskLevel = "medium"
	default:
		report.RiskLevel = "low"
	}

	report.SummaryText = fmt.Sprintf("Detected %d potential bias indicators (%d high, %d medium severity)",
		len(report.Indicators), highCount, mediumCount)
}

// ToJSON converts fairness result to JSON.
func (r *FairnessResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// Summary returns a summary of fairness analysis.
func (r *FairnessResult) Summary() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Fairness Analysis for: %s\n", r.ProtectedAttrib))
	sb.WriteString(fmt.Sprintf("Overall Score: %.2f\n", r.OverallScore))
	sb.WriteString(fmt.Sprintf("Passed Thresholds: %v\n", r.PassedThresholds))

	if len(r.GroupMetrics) > 0 {
		sb.WriteString("\nGroup Metrics:\n")
		for _, gm := range r.GroupMetrics {
			sb.WriteString(fmt.Sprintf("  %s: size=%d, pos_rate=%.3f, tpr=%.3f\n",
				gm.Name, gm.Size, gm.PositiveRate, gm.TruePositiveRate))
		}
	}

	if len(r.FairnessMetrics) > 0 {
		sb.WriteString("\nFairness Metrics:\n")
		for _, fm := range r.FairnessMetrics {
			status := "PASS"
			if !fm.Passed {
				status = "FAIL"
			}
			sb.WriteString(fmt.Sprintf("  %s: %.3f (%s)\n", fm.Type, fm.Value, status))
		}
	}

	return sb.String()
}

// ToJSON converts bias report to JSON.
func (r *BiasReport) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// Summary returns a summary of bias analysis.
func (r *BiasReport) Summary() string {
	var sb strings.Builder

	sb.WriteString("Bias Analysis Report\n")
	sb.WriteString(fmt.Sprintf("Risk Level: %s\n", strings.ToUpper(r.RiskLevel)))
	sb.WriteString(fmt.Sprintf("Overall Score: %.2f\n", r.OverallScore))
	sb.WriteString(fmt.Sprintf("Summary: %s\n", r.SummaryText))

	if len(r.Indicators) > 0 {
		sb.WriteString("\nBias Indicators:\n")
		for _, ind := range r.Indicators {
			sb.WriteString(fmt.Sprintf("  [%s] %s: %s (score: %.2f)\n",
				strings.ToUpper(ind.Severity), ind.Attribute, ind.Description, ind.Score))
		}
	}

	return sb.String()
}
