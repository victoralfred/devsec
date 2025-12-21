package ml

import (
	"context"
	"testing"
)

func TestNewDataValidator(t *testing.T) {
	schema := &DataSchema{
		Name: "test-schema",
		Columns: []ColumnSchema{
			{Name: "age", Type: DataTypeInteger, Required: true},
		},
	}

	v := NewDataValidator(schema)
	if v == nil {
		t.Fatal("expected validator, got nil")
	}
	if v.Schema() != schema {
		t.Error("expected schema to be set")
	}
}

func TestValidateRecords(t *testing.T) {
	ctx := context.Background()

	schema := &DataSchema{
		Name: "user-schema",
		Columns: []ColumnSchema{
			{Name: "name", Type: DataTypeString, Required: true},
			{Name: "age", Type: DataTypeInteger, Required: true, Min: 0, Max: 150},
			{Name: "score", Type: DataTypeFloat, Required: false, Nullable: true},
		},
	}

	v := NewDataValidator(schema)

	data := []map[string]interface{}{
		{"name": "Alice", "age": 30, "score": 95.5},
		{"name": "Bob", "age": 25, "score": nil},
		{"name": "Charlie", "age": 35},
	}

	result, err := v.Validate(ctx, data)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected valid result, got errors: %v", result.Errors)
	}

	if result.Statistics.TotalRows != 3 {
		t.Errorf("expected 3 total rows, got %d", result.Statistics.TotalRows)
	}
}

func TestValidateMissingRequired(t *testing.T) {
	ctx := context.Background()

	schema := &DataSchema{
		Name: "test",
		Columns: []ColumnSchema{
			{Name: "id", Type: DataTypeInteger, Required: true},
		},
	}

	v := NewDataValidator(schema)

	data := []map[string]interface{}{
		{"other": "value"},
	}

	result, err := v.Validate(ctx, data)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if result.Valid {
		t.Error("expected invalid result for missing required field")
	}

	if len(result.Errors) == 0 {
		t.Error("expected at least one error")
	}

	foundMissingError := false
	for _, e := range result.Errors {
		if e.Code == "missing_required" {
			foundMissingError = true
			break
		}
	}
	if !foundMissingError {
		t.Error("expected missing_required error")
	}
}

func TestValidateTypeMismatch(t *testing.T) {
	ctx := context.Background()

	schema := &DataSchema{
		Name: "test",
		Columns: []ColumnSchema{
			{Name: "count", Type: DataTypeInteger, Required: true},
		},
	}

	v := NewDataValidator(schema)

	data := []map[string]interface{}{
		{"count": "not a number"},
	}

	result, err := v.Validate(ctx, data)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if result.Valid {
		t.Error("expected invalid result for type mismatch")
	}
}

func TestValidateOutOfRange(t *testing.T) {
	ctx := context.Background()

	schema := &DataSchema{
		Name: "test",
		Columns: []ColumnSchema{
			{Name: "percentage", Type: DataTypeFloat, Required: true, Min: 0, Max: 100},
		},
	}

	v := NewDataValidator(schema)

	data := []map[string]interface{}{
		{"percentage": 150.0},
	}

	result, err := v.Validate(ctx, data)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if result.Valid {
		t.Error("expected invalid result for out of range value")
	}

	foundRangeError := false
	for _, e := range result.Errors {
		if e.Code == "out_of_range" {
			foundRangeError = true
			break
		}
	}
	if !foundRangeError {
		t.Error("expected out_of_range error")
	}
}

func TestValidateNullNotAllowed(t *testing.T) {
	ctx := context.Background()

	schema := &DataSchema{
		Name: "test",
		Columns: []ColumnSchema{
			{Name: "value", Type: DataTypeString, Required: true, Nullable: false},
		},
	}

	v := NewDataValidator(schema)

	data := []map[string]interface{}{
		{"value": nil},
	}

	result, err := v.Validate(ctx, data)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if result.Valid {
		t.Error("expected invalid result for null value")
	}
}

func TestValidateCategorical(t *testing.T) {
	ctx := context.Background()

	schema := &DataSchema{
		Name: "test",
		Columns: []ColumnSchema{
			{Name: "status", Type: DataTypeCategorical, Required: true, AllowedValues: []interface{}{"active", "inactive"}},
		},
	}

	v := NewDataValidator(schema)

	// Valid category.
	data := []map[string]interface{}{
		{"status": "active"},
	}

	result, err := v.Validate(ctx, data)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected valid result, got errors: %v", result.Errors)
	}

	// Invalid category.
	data = []map[string]interface{}{
		{"status": "pending"},
	}

	result, err = v.Validate(ctx, data)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if result.Valid {
		t.Error("expected invalid result for invalid category")
	}
}

func TestValidateSingleRecord(t *testing.T) {
	ctx := context.Background()

	schema := &DataSchema{
		Name: "test",
		Columns: []ColumnSchema{
			{Name: "id", Type: DataTypeInteger, Required: true},
		},
	}

	v := NewDataValidator(schema)

	data := map[string]interface{}{
		"id": 42,
	}

	result, err := v.Validate(ctx, data)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected valid result, got errors: %v", result.Errors)
	}
}

func TestValidateBoolean(t *testing.T) {
	ctx := context.Background()

	schema := &DataSchema{
		Name: "test",
		Columns: []ColumnSchema{
			{Name: "active", Type: DataTypeBoolean, Required: true},
		},
	}

	v := NewDataValidator(schema)

	data := []map[string]interface{}{
		{"active": true},
		{"active": false},
	}

	result, err := v.Validate(ctx, data)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected valid result, got errors: %v", result.Errors)
	}
}

func TestValidateNilSchema(t *testing.T) {
	ctx := context.Background()

	v := NewDataValidator(nil)
	_, err := v.Validate(ctx, []map[string]interface{}{})
	if err == nil {
		t.Error("expected error for nil schema")
	}
}

func TestValidateUnsupportedDataType(t *testing.T) {
	ctx := context.Background()

	schema := &DataSchema{Name: "test"}
	v := NewDataValidator(schema)

	_, err := v.Validate(ctx, "not a valid data type")
	if err == nil {
		t.Error("expected error for unsupported data type")
	}
}

func TestValidateContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	schema := &DataSchema{Name: "test"}
	v := NewDataValidator(schema)

	_, err := v.Validate(ctx, []map[string]interface{}{})
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestNewDriftDetector(t *testing.T) {
	d := NewDriftDetector(0.1)
	if d == nil {
		t.Fatal("expected detector, got nil")
	}
	if d.threshold != 0.1 {
		t.Errorf("expected threshold 0.1, got %f", d.threshold)
	}

	// Test default threshold.
	d2 := NewDriftDetector(0)
	if d2.threshold != 0.1 {
		t.Errorf("expected default threshold 0.1, got %f", d2.threshold)
	}
}

func TestSetThreshold(t *testing.T) {
	d := NewDriftDetector(0.1)
	d.SetThreshold(0.2)
	if d.threshold != 0.2 {
		t.Errorf("expected threshold 0.2, got %f", d.threshold)
	}
}

func TestDetectDrift(t *testing.T) {
	ctx := context.Background()
	d := NewDriftDetector(0.5)

	baseline := []map[string]interface{}{
		{"value": 10.0, "count": 5},
		{"value": 12.0, "count": 6},
		{"value": 11.0, "count": 5},
		{"value": 13.0, "count": 7},
	}

	// Similar data - no drift.
	current := []map[string]interface{}{
		{"value": 11.0, "count": 6},
		{"value": 12.0, "count": 5},
		{"value": 10.0, "count": 6},
		{"value": 13.0, "count": 7},
	}

	result, err := d.DetectDrift(ctx, baseline, current)
	if err != nil {
		t.Fatalf("DetectDrift failed: %v", err)
	}

	if result.DriftDetect {
		t.Error("expected no drift for similar data")
	}
}

func TestDetectDriftWithDrift(t *testing.T) {
	ctx := context.Background()
	d := NewDriftDetector(0.1)

	baseline := []map[string]interface{}{
		{"value": 10.0},
		{"value": 11.0},
		{"value": 10.0},
		{"value": 11.0},
	}

	// Very different data - should drift.
	current := []map[string]interface{}{
		{"value": 100.0},
		{"value": 110.0},
		{"value": 100.0},
		{"value": 110.0},
	}

	result, err := d.DetectDrift(ctx, baseline, current)
	if err != nil {
		t.Fatalf("DetectDrift failed: %v", err)
	}

	if !result.DriftDetect {
		t.Error("expected drift for very different data")
	}

	if result.Score == 0 {
		t.Error("expected non-zero drift score")
	}
}

func TestDetectDriftEmptyData(t *testing.T) {
	ctx := context.Background()
	d := NewDriftDetector(0.1)

	_, err := d.DetectDrift(ctx, []map[string]interface{}{}, []map[string]interface{}{{"a": 1}})
	if err == nil {
		t.Error("expected error for empty baseline")
	}

	_, err = d.DetectDrift(ctx, []map[string]interface{}{{"a": 1}}, []map[string]interface{}{})
	if err == nil {
		t.Error("expected error for empty current")
	}
}

func TestDetectDriftInvalidType(t *testing.T) {
	ctx := context.Background()
	d := NewDriftDetector(0.1)

	_, err := d.DetectDrift(ctx, "not valid", []map[string]interface{}{})
	if err == nil {
		t.Error("expected error for invalid baseline type")
	}

	_, err = d.DetectDrift(ctx, []map[string]interface{}{{"a": 1}}, "not valid")
	if err == nil {
		t.Error("expected error for invalid current type")
	}
}

func TestDetectDriftContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	d := NewDriftDetector(0.1)
	_, err := d.DetectDrift(ctx, []map[string]interface{}{}, []map[string]interface{}{})
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestDriftResultToJSON(t *testing.T) {
	result := &DriftResult{
		Type:        DriftTypeDistribution,
		DriftDetect: true,
		Score:       0.5,
		Description: "test",
		Columns: []ColumnDrift{
			{Column: "value", DriftScore: 0.5, DriftDetected: true},
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

func TestDriftResultSummary(t *testing.T) {
	result := &DriftResult{
		Type:        DriftTypeDistribution,
		DriftDetect: true,
		Score:       0.5,
		Description: "drift detected",
		Columns: []ColumnDrift{
			{Column: "value", DriftScore: 0.5, DriftDetected: true},
			{Column: "count", DriftScore: 0.1, DriftDetected: false},
		},
	}

	summary := result.Summary()
	if summary == "" {
		t.Error("expected non-empty summary")
	}
}

func TestDataTypeConstants(t *testing.T) {
	types := []DataType{
		DataTypeString,
		DataTypeInteger,
		DataTypeFloat,
		DataTypeBoolean,
		DataTypeDateTime,
		DataTypeCategorical,
		DataTypeArray,
		DataTypeObject,
	}

	for _, dt := range types {
		if string(dt) == "" {
			t.Error("data type constant should not be empty")
		}
	}
}

func TestDriftTypeConstants(t *testing.T) {
	types := []DriftType{
		DriftTypeDistribution,
		DriftTypeConcept,
		DriftTypeSchema,
	}

	for _, dt := range types {
		if string(dt) == "" {
			t.Error("drift type constant should not be empty")
		}
	}
}

func TestToFloat64(t *testing.T) {
	tests := []struct {
		input    interface{}
		expected float64
		ok       bool
	}{
		{float64(1.5), 1.5, true},
		{float32(1.5), 1.5, true},
		{int(5), 5.0, true},
		{int32(5), 5.0, true},
		{int64(5), 5.0, true},
		{"not a number", 0, false},
		{nil, 0, false},
	}

	for _, tt := range tests {
		result, ok := toFloat64(tt.input)
		if ok != tt.ok {
			t.Errorf("toFloat64(%v) ok = %v, want %v", tt.input, ok, tt.ok)
		}
		if ok && result != tt.expected {
			t.Errorf("toFloat64(%v) = %f, want %f", tt.input, result, tt.expected)
		}
	}
}

// Benchmark tests for drift detection and data validation.

func BenchmarkDriftDetectionSmall(b *testing.B) {
	baseline := make([]interface{}, 100)
	current := make([]interface{}, 100)
	for i := 0; i < 100; i++ {
		baseline[i] = float64(i)
		current[i] = float64(i + 1)
	}

	detector := NewDriftDetector(0.1)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = detector.DetectDrift(ctx, baseline, current)
	}
}

func BenchmarkDriftDetectionMedium(b *testing.B) {
	baseline := make([]interface{}, 1000)
	current := make([]interface{}, 1000)
	for i := 0; i < 1000; i++ {
		baseline[i] = float64(i)
		current[i] = float64(i) * 1.1 // Slight drift
	}

	detector := NewDriftDetector(0.1)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = detector.DetectDrift(ctx, baseline, current)
	}
}

func BenchmarkDriftDetectionLarge(b *testing.B) {
	baseline := make([]interface{}, 10000)
	current := make([]interface{}, 10000)
	for i := 0; i < 10000; i++ {
		baseline[i] = float64(i)
		current[i] = float64(i) * 1.2 // More significant drift
	}

	detector := NewDriftDetector(0.1)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = detector.DetectDrift(ctx, baseline, current)
	}
}

func BenchmarkDataValidationSmall(b *testing.B) {
	schema := &DataSchema{
		Name: "benchmark-schema",
		Columns: []ColumnSchema{
			{Name: "id", Type: DataTypeInteger, Required: true},
			{Name: "value", Type: DataTypeFloat, Required: true},
		},
	}
	validator := NewDataValidator(schema)

	// Create 100 rows of data.
	data := make([]map[string]interface{}, 100)
	for i := range data {
		data[i] = map[string]interface{}{
			"id":    i,
			"value": float64(i) * 1.5,
		}
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = validator.Validate(ctx, data)
	}
}

func BenchmarkDataValidationLarge(b *testing.B) {
	schema := &DataSchema{
		Name: "benchmark-schema-large",
		Columns: []ColumnSchema{
			{Name: "id", Type: DataTypeInteger, Required: true},
			{Name: "name", Type: DataTypeString, Required: true},
			{Name: "value", Type: DataTypeFloat, Required: true},
			{Name: "active", Type: DataTypeBoolean, Required: false},
			{Name: "category", Type: DataTypeCategorical, Required: false},
		},
	}
	validator := NewDataValidator(schema)

	// Create 10000 rows of data.
	data := make([]map[string]interface{}, 10000)
	for i := range data {
		data[i] = map[string]interface{}{
			"id":       i,
			"name":     "item",
			"value":    float64(i) * 1.5,
			"active":   i%2 == 0,
			"category": "cat",
		}
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = validator.Validate(ctx, data)
	}
}

// Fuzz tests for data validation.

func FuzzDataValidation(f *testing.F) {
	// Add seed corpus.
	f.Add("name", "value", 10, true)
	f.Add("id", "data", 0, false)
	f.Add("field_1", "test_value", -5, true)

	schema := &DataSchema{
		Name: "fuzz-schema",
		Columns: []ColumnSchema{
			{Name: "field", Type: DataTypeString, Required: true},
		},
	}
	validator := NewDataValidator(schema)
	ctx := context.Background()

	f.Fuzz(func(t *testing.T, fieldName, fieldValue string, intVal int, boolVal bool) {
		data := []map[string]interface{}{
			{
				fieldName: fieldValue,
				"int":     intVal,
				"bool":    boolVal,
			},
		}

		// Should not panic.
		_, _ = validator.Validate(ctx, data)
	})
}

func FuzzDriftDetection(f *testing.F) {
	// Add seed corpus.
	f.Add(1.0, 2.0, 0.1)
	f.Add(0.0, 0.0, 0.5)
	f.Add(-100.0, 100.0, 0.01)

	detector := NewDriftDetector(0.1)
	ctx := context.Background()

	f.Fuzz(func(t *testing.T, baselineVal, currentVal, threshold float64) {
		// Skip invalid thresholds.
		if threshold <= 0 || threshold > 1 {
			return
		}

		baseline := []interface{}{baselineVal}
		current := []interface{}{currentVal}

		// Should not panic.
		_, _ = detector.DetectDrift(ctx, baseline, current)
	})
}
