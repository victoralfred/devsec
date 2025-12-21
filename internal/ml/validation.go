package ml

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// DataType represents a column data type.
type DataType string

const (
	// DataTypeString represents string data.
	DataTypeString DataType = "string"
	// DataTypeInteger represents integer data.
	DataTypeInteger DataType = "integer"
	// DataTypeFloat represents floating-point data.
	DataTypeFloat DataType = "float"
	// DataTypeBoolean represents boolean data.
	DataTypeBoolean DataType = "boolean"
	// DataTypeDateTime represents datetime data.
	DataTypeDateTime DataType = "datetime"
	// DataTypeCategorical represents categorical data.
	DataTypeCategorical DataType = "categorical"
	// DataTypeArray represents array data.
	DataTypeArray DataType = "array"
	// DataTypeObject represents object/struct data.
	DataTypeObject DataType = "object"
)

// ColumnSchema defines the schema for a single column.
// Fields ordered for optimal memory alignment.
type ColumnSchema struct {
	Name          string        `json:"name"`
	Type          DataType      `json:"type"`
	Description   string        `json:"description,omitempty"`
	Pattern       string        `json:"pattern,omitempty"`
	AllowedValues []interface{} `json:"allowed_values,omitempty"`
	Min           float64       `json:"min,omitempty"`
	Max           float64       `json:"max,omitempty"`
	Required      bool          `json:"required"`
	Nullable      bool          `json:"nullable"`
}

// DataSchema defines the schema for a dataset.
// Fields ordered for optimal memory alignment.
type DataSchema struct {
	Name        string         `json:"name"`
	Version     string         `json:"version,omitempty"`
	Description string         `json:"description,omitempty"`
	Columns     []ColumnSchema `json:"columns"`
}

// ValidationResult contains the result of a validation.
// Fields ordered for optimal memory alignment.
type ValidationResult struct {
	SchemaName string            `json:"schema_name"`
	Errors     []ValidationError `json:"errors,omitempty"`
	Warnings   []ValidationError `json:"warnings,omitempty"`
	Statistics ValidationStats   `json:"statistics"`
	Valid      bool              `json:"valid"`
}

// ValidationError represents a validation error.
// Fields ordered for optimal memory alignment.
type ValidationError struct {
	Column   string `json:"column,omitempty"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Row      int    `json:"row,omitempty"`
}

// ValidationStats contains validation statistics.
// Fields ordered for optimal memory alignment.
type ValidationStats struct {
	Duration       time.Duration `json:"duration"`
	TotalRows      int           `json:"total_rows"`
	ValidRows      int           `json:"valid_rows"`
	InvalidRows    int           `json:"invalid_rows"`
	NullCount      int           `json:"null_count"`
	OutOfRangeRows int           `json:"out_of_range_rows"`
}

// SchemaValidator validates data against a schema.
type SchemaValidator interface {
	// Validate validates data against the schema.
	Validate(ctx context.Context, data interface{}) (*ValidationResult, error)
	// Schema returns the schema being validated against.
	Schema() *DataSchema
}

// DataValidator validates ML data inputs.
type DataValidator struct {
	schema *DataSchema
}

// NewDataValidator creates a new data validator.
func NewDataValidator(schema *DataSchema) *DataValidator {
	return &DataValidator{schema: schema}
}

// Schema returns the schema.
func (v *DataValidator) Schema() *DataSchema {
	return v.schema
}

// Validate validates data against the schema.
func (v *DataValidator) Validate(ctx context.Context, data interface{}) (*ValidationResult, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if v.schema == nil {
		return nil, fmt.Errorf("schema is not set")
	}

	start := time.Now()
	result := &ValidationResult{
		SchemaName: v.schema.Name,
		Errors:     make([]ValidationError, 0),
		Warnings:   make([]ValidationError, 0),
		Valid:      true,
	}

	// Handle different data types.
	switch d := data.(type) {
	case []map[string]interface{}:
		v.validateRecords(d, result)
	case map[string]interface{}:
		v.validateRecord(d, 0, result)
	default:
		return nil, fmt.Errorf("unsupported data type: %T", data)
	}

	result.Statistics.Duration = time.Since(start)
	result.Valid = len(result.Errors) == 0

	return result, nil
}

// validateRecords validates a slice of records.
func (v *DataValidator) validateRecords(records []map[string]interface{}, result *ValidationResult) {
	result.Statistics.TotalRows = len(records)

	for i, record := range records {
		v.validateRecord(record, i, result)
	}

	result.Statistics.ValidRows = result.Statistics.TotalRows - result.Statistics.InvalidRows
}

// validateRecord validates a single record.
func (v *DataValidator) validateRecord(record map[string]interface{}, row int, result *ValidationResult) {
	hasError := false

	for _, col := range v.schema.Columns {
		value, exists := record[col.Name]

		// Check required fields.
		if col.Required && !exists {
			result.Errors = append(result.Errors, ValidationError{
				Code:    "missing_required",
				Message: fmt.Sprintf("required field '%s' is missing", col.Name),
				Column:  col.Name,
				Row:     row,
			})
			hasError = true
			continue
		}

		if !exists {
			continue
		}

		// Check null values.
		if value == nil {
			result.Statistics.NullCount++
			if !col.Nullable {
				result.Errors = append(result.Errors, ValidationError{
					Code:    "null_not_allowed",
					Message: fmt.Sprintf("field '%s' cannot be null", col.Name),
					Column:  col.Name,
					Row:     row,
				})
				hasError = true
			}
			continue
		}

		// Validate type and constraints.
		if err := v.validateValue(value, col, row); err != nil {
			result.Errors = append(result.Errors, *err)
			hasError = true
		}
	}

	if hasError {
		result.Statistics.InvalidRows++
	}
}

// validateValue validates a single value against column schema.
func (v *DataValidator) validateValue(value interface{}, col ColumnSchema, row int) *ValidationError {
	switch col.Type {
	case DataTypeInteger:
		num, ok := toFloat64(value)
		if !ok {
			return &ValidationError{
				Code:     "type_mismatch",
				Message:  fmt.Sprintf("expected integer, got %T", value),
				Column:   col.Name,
				Row:      row,
				Expected: "integer",
				Actual:   fmt.Sprintf("%T", value),
			}
		}
		if col.Min != 0 || col.Max != 0 {
			if num < col.Min || num > col.Max {
				return &ValidationError{
					Code:     "out_of_range",
					Message:  fmt.Sprintf("value %v is out of range [%v, %v]", num, col.Min, col.Max),
					Column:   col.Name,
					Row:      row,
					Expected: fmt.Sprintf("[%v, %v]", col.Min, col.Max),
					Actual:   fmt.Sprintf("%v", num),
				}
			}
		}

	case DataTypeFloat:
		num, ok := toFloat64(value)
		if !ok {
			return &ValidationError{
				Code:     "type_mismatch",
				Message:  fmt.Sprintf("expected float, got %T", value),
				Column:   col.Name,
				Row:      row,
				Expected: "float",
				Actual:   fmt.Sprintf("%T", value),
			}
		}
		if col.Min != 0 || col.Max != 0 {
			if num < col.Min || num > col.Max {
				return &ValidationError{
					Code:     "out_of_range",
					Message:  fmt.Sprintf("value %v is out of range [%v, %v]", num, col.Min, col.Max),
					Column:   col.Name,
					Row:      row,
					Expected: fmt.Sprintf("[%v, %v]", col.Min, col.Max),
					Actual:   fmt.Sprintf("%v", num),
				}
			}
		}

	case DataTypeString:
		_, ok := value.(string)
		if !ok {
			return &ValidationError{
				Code:     "type_mismatch",
				Message:  fmt.Sprintf("expected string, got %T", value),
				Column:   col.Name,
				Row:      row,
				Expected: "string",
				Actual:   fmt.Sprintf("%T", value),
			}
		}

	case DataTypeBoolean:
		_, ok := value.(bool)
		if !ok {
			return &ValidationError{
				Code:     "type_mismatch",
				Message:  fmt.Sprintf("expected boolean, got %T", value),
				Column:   col.Name,
				Row:      row,
				Expected: "boolean",
				Actual:   fmt.Sprintf("%T", value),
			}
		}

	case DataTypeCategorical:
		if len(col.AllowedValues) > 0 {
			found := false
			for _, allowed := range col.AllowedValues {
				if value == allowed {
					found = true
					break
				}
			}
			if !found {
				return &ValidationError{
					Code:     "invalid_category",
					Message:  fmt.Sprintf("value '%v' is not in allowed values", value),
					Column:   col.Name,
					Row:      row,
					Expected: fmt.Sprintf("%v", col.AllowedValues),
					Actual:   fmt.Sprintf("%v", value),
				}
			}
		}
	}

	return nil
}

// toFloat64 converts a value to float64.
func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

// DriftType represents the type of data drift.
type DriftType string

const (
	// DriftTypeDistribution represents distribution drift.
	DriftTypeDistribution DriftType = "distribution"
	// DriftTypeConcept represents concept drift.
	DriftTypeConcept DriftType = "concept"
	// DriftTypeSchema represents schema drift.
	DriftTypeSchema DriftType = "schema"
)

// DriftResult contains drift detection results.
// Fields ordered for optimal memory alignment.
type DriftResult struct {
	Timestamp   time.Time     `json:"timestamp"`
	Type        DriftType     `json:"type"`
	Description string        `json:"description,omitempty"`
	Columns     []ColumnDrift `json:"columns"`
	Score       float64       `json:"score"`
	DriftDetect bool          `json:"drift_detected"`
}

// ColumnDrift contains drift information for a column.
// Fields ordered for optimal memory alignment.
type ColumnDrift struct {
	Column        string  `json:"column"`
	Description   string  `json:"description,omitempty"`
	BaselineMean  float64 `json:"baseline_mean,omitempty"`
	CurrentMean   float64 `json:"current_mean,omitempty"`
	BaselineStd   float64 `json:"baseline_std,omitempty"`
	CurrentStd    float64 `json:"current_std,omitempty"`
	DriftScore    float64 `json:"drift_score"`
	DriftDetected bool    `json:"drift_detected"`
}

// DriftDetector detects data drift between datasets.
type DriftDetector interface {
	// DetectDrift compares current data against baseline.
	DetectDrift(ctx context.Context, baseline, current interface{}) (*DriftResult, error)
	// SetThreshold sets the drift detection threshold.
	SetThreshold(threshold float64)
}

// SimpleDriftDetector provides basic drift detection.
type SimpleDriftDetector struct {
	threshold float64
}

// NewDriftDetector creates a new drift detector.
func NewDriftDetector(threshold float64) *SimpleDriftDetector {
	if threshold <= 0 {
		threshold = 0.1 // Default 10% threshold.
	}
	return &SimpleDriftDetector{threshold: threshold}
}

// SetThreshold sets the drift detection threshold.
func (d *SimpleDriftDetector) SetThreshold(threshold float64) {
	d.threshold = threshold
}

// DetectDrift compares current data against baseline.
func (d *SimpleDriftDetector) DetectDrift(ctx context.Context, baseline, current interface{}) (*DriftResult, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	baselineRecords, ok := baseline.([]map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("baseline must be []map[string]interface{}")
	}

	currentRecords, ok := current.([]map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("current must be []map[string]interface{}")
	}

	if len(baselineRecords) == 0 || len(currentRecords) == 0 {
		return nil, fmt.Errorf("baseline and current data cannot be empty")
	}

	result := &DriftResult{
		Type:      DriftTypeDistribution,
		Timestamp: time.Now().UTC(),
		Columns:   make([]ColumnDrift, 0),
	}

	// Get all numeric columns.
	columns := d.getNumericColumns(baselineRecords[0])

	totalScore := 0.0
	driftCount := 0

	for _, col := range columns {
		baselineVals := d.extractColumn(baselineRecords, col)
		currentVals := d.extractColumn(currentRecords, col)

		if len(baselineVals) == 0 || len(currentVals) == 0 {
			continue
		}

		baselineMean, baselineStd := d.meanStd(baselineVals)
		currentMean, currentStd := d.meanStd(currentVals)

		// Calculate normalized difference.
		var driftScore float64
		if baselineStd > 0 {
			driftScore = abs(currentMean-baselineMean) / baselineStd
		} else if baselineMean != 0 {
			driftScore = abs(currentMean-baselineMean) / abs(baselineMean)
		}

		driftDetected := driftScore > d.threshold

		colDrift := ColumnDrift{
			Column:        col,
			BaselineMean:  baselineMean,
			CurrentMean:   currentMean,
			BaselineStd:   baselineStd,
			CurrentStd:    currentStd,
			DriftScore:    driftScore,
			DriftDetected: driftDetected,
		}

		if driftDetected {
			colDrift.Description = fmt.Sprintf("significant drift detected (score: %.3f)", driftScore)
			driftCount++
		}

		result.Columns = append(result.Columns, colDrift)
		totalScore += driftScore
	}

	if len(columns) > 0 {
		result.Score = totalScore / float64(len(columns))
	}
	result.DriftDetect = driftCount > 0

	if result.DriftDetect {
		result.Description = fmt.Sprintf("drift detected in %d/%d columns", driftCount, len(columns))
	} else {
		result.Description = "no significant drift detected"
	}

	return result, nil
}

// getNumericColumns returns numeric column names from a record.
func (d *SimpleDriftDetector) getNumericColumns(record map[string]interface{}) []string {
	columns := make([]string, 0)
	for col, val := range record {
		if _, ok := toFloat64(val); ok {
			columns = append(columns, col)
		}
	}
	return columns
}

// extractColumn extracts numeric values for a column.
func (d *SimpleDriftDetector) extractColumn(records []map[string]interface{}, col string) []float64 {
	values := make([]float64, 0, len(records))
	for _, record := range records {
		if val, exists := record[col]; exists {
			if num, ok := toFloat64(val); ok {
				values = append(values, num)
			}
		}
	}
	return values
}

// meanStd calculates mean and standard deviation.
func (d *SimpleDriftDetector) meanStd(values []float64) (mean, std float64) {
	if len(values) == 0 {
		return 0, 0
	}

	// Calculate mean.
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	mean = sum / float64(len(values))

	// Calculate standard deviation.
	sumSq := 0.0
	for _, v := range values {
		diff := v - mean
		sumSq += diff * diff
	}
	if len(values) > 1 {
		variance := sumSq / float64(len(values)-1)
		if variance > 0 {
			std = sqrt(variance)
		}
	}

	return mean, std
}

// abs returns absolute value.
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// sqrt returns square root using Newton's method.
func sqrt(x float64) float64 {
	if x == 0 {
		return 0
	}
	z := x / 2
	for i := 0; i < 10; i++ {
		z -= (z*z - x) / (2 * z)
	}
	return z
}

// ToJSON converts drift result to JSON.
func (r *DriftResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// Summary returns a summary of drift detection.
func (r *DriftResult) Summary() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Drift Detection (%s)\n", r.Type))
	sb.WriteString(fmt.Sprintf("Overall Score: %.3f\n", r.Score))
	sb.WriteString(fmt.Sprintf("Drift Detected: %v\n", r.DriftDetect))
	sb.WriteString(fmt.Sprintf("Description: %s\n", r.Description))

	if len(r.Columns) > 0 {
		sb.WriteString("\nColumn Analysis:\n")
		for _, col := range r.Columns {
			status := "OK"
			if col.DriftDetected {
				status = "DRIFT"
			}
			sb.WriteString(fmt.Sprintf("  %s: %.3f (%s)\n", col.Column, col.DriftScore, status))
		}
	}

	return sb.String()
}
