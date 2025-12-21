package ml

import (
	"math"
	"testing"
)

func TestKolmogorovSmirnovTest(t *testing.T) {
	tests := []struct {
		name        string
		sample1     []float64
		sample2     []float64
		wantSig     bool
		maxStatDiff float64
	}{
		{
			name:        "identical samples",
			sample1:     []float64{1, 2, 3, 4, 5},
			sample2:     []float64{1, 2, 3, 4, 5},
			wantSig:     false,
			maxStatDiff: 0.01,
		},
		{
			name:        "similar samples",
			sample1:     []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			sample2:     []float64{1.1, 2.1, 3.1, 4.1, 5.1, 6.1, 7.1, 8.1, 9.1, 10.1},
			wantSig:     false,
			maxStatDiff: 0.2,
		},
		{
			name:        "different distributions",
			sample1:     []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			sample2:     []float64{11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
			wantSig:     true,
			maxStatDiff: 1.1,
		},
		{
			name:    "empty first sample",
			sample1: []float64{},
			sample2: []float64{1, 2, 3},
			wantSig: false,
		},
		{
			name:    "empty second sample",
			sample1: []float64{1, 2, 3},
			sample2: []float64{},
			wantSig: false,
		},
		{
			name:    "both empty",
			sample1: []float64{},
			sample2: []float64{},
			wantSig: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := KolmogorovSmirnovTest(tt.sample1, tt.sample2)

			if result.Test != TestKolmogorovSmirnov {
				t.Errorf("expected test type %s, got %s", TestKolmogorovSmirnov, result.Test)
			}

			if result.Significant != tt.wantSig {
				t.Errorf("expected Significant=%v, got %v (statistic=%f, threshold=%f)",
					tt.wantSig, result.Significant, result.Statistic, result.Threshold)
			}

			if tt.maxStatDiff > 0 && result.Statistic > tt.maxStatDiff {
				t.Errorf("statistic %f exceeds expected max %f", result.Statistic, tt.maxStatDiff)
			}
		})
	}
}

func TestKolmogorovSmirnovTestPValue(t *testing.T) {
	// Large identical samples should have high p-value.
	sample := make([]float64, 100)
	for i := range sample {
		sample[i] = float64(i)
	}

	result := KolmogorovSmirnovTest(sample, sample)

	if result.PValue < 0 || result.PValue > 1 {
		t.Errorf("p-value %f out of valid range [0,1]", result.PValue)
	}

	// For identical samples, p-value should be high.
	if result.PValue < 0.5 {
		t.Errorf("expected high p-value for identical samples, got %f", result.PValue)
	}
}

func TestPopulationStabilityIndex(t *testing.T) {
	tests := []struct {
		name     string
		baseline []float64
		current  []float64
		numBins  int
		wantSig  bool
	}{
		{
			name:     "identical distributions",
			baseline: []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			current:  []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			numBins:  5,
			wantSig:  false,
		},
		{
			name:     "similar distributions",
			baseline: []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
			current:  []float64{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21},
			numBins:  10,
			wantSig:  false,
		},
		{
			name:     "significantly different distributions",
			baseline: []float64{1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5},
			current:  []float64{8, 8, 8, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10},
			numBins:  5,
			wantSig:  true,
		},
		{
			name:     "empty baseline",
			baseline: []float64{},
			current:  []float64{1, 2, 3},
			numBins:  5,
			wantSig:  false,
		},
		{
			name:     "empty current",
			baseline: []float64{1, 2, 3},
			current:  []float64{},
			numBins:  5,
			wantSig:  false,
		},
		{
			name:     "all same values",
			baseline: []float64{5, 5, 5, 5, 5},
			current:  []float64{5, 5, 5, 5, 5},
			numBins:  5,
			wantSig:  false,
		},
		{
			name:     "default bins when zero",
			baseline: []float64{1, 2, 3, 4, 5},
			current:  []float64{1, 2, 3, 4, 5},
			numBins:  0,
			wantSig:  false,
		},
		{
			name:     "negative bins defaults to 10",
			baseline: []float64{1, 2, 3, 4, 5},
			current:  []float64{1, 2, 3, 4, 5},
			numBins:  -1,
			wantSig:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PopulationStabilityIndex(tt.baseline, tt.current, tt.numBins)

			if result.Test != TestPSI {
				t.Errorf("expected test type %s, got %s", TestPSI, result.Test)
			}

			if result.Significant != tt.wantSig {
				t.Errorf("expected Significant=%v, got %v (PSI=%f, threshold=%f)",
					tt.wantSig, result.Significant, result.Statistic, result.Threshold)
			}

			if result.Statistic < 0 {
				t.Errorf("PSI should not be negative, got %f", result.Statistic)
			}
		})
	}
}

func TestChiSquareTest(t *testing.T) {
	tests := []struct {
		name     string
		observed []float64
		expected []float64
		wantSig  bool
	}{
		{
			name:     "matching frequencies",
			observed: []float64{10, 20, 30, 40},
			expected: []float64{10, 20, 30, 40},
			wantSig:  false,
		},
		{
			name:     "slightly different",
			observed: []float64{12, 18, 32, 38},
			expected: []float64{10, 20, 30, 40},
			wantSig:  false,
		},
		{
			name:     "significantly different",
			observed: []float64{50, 10, 5, 35},
			expected: []float64{10, 20, 30, 40},
			wantSig:  true,
		},
		{
			name:     "empty arrays",
			observed: []float64{},
			expected: []float64{},
			wantSig:  false,
		},
		{
			name:     "mismatched lengths",
			observed: []float64{1, 2, 3},
			expected: []float64{1, 2},
			wantSig:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ChiSquareTest(tt.observed, tt.expected)

			if result.Test != TestChiSquare {
				t.Errorf("expected test type %s, got %s", TestChiSquare, result.Test)
			}

			if result.Significant != tt.wantSig {
				t.Errorf("expected Significant=%v, got %v (chi-square=%f, threshold=%f)",
					tt.wantSig, result.Significant, result.Statistic, result.Threshold)
			}
		})
	}
}

func TestChiSquareTestFromCounts(t *testing.T) {
	//nolint:govet // test struct alignment is not performance critical.
	tests := []struct {
		name           string
		baselineCounts map[string]int
		currentCounts  map[string]int
		wantSig        bool
	}{
		{
			name: "identical distributions",
			baselineCounts: map[string]int{
				"a": 100,
				"b": 200,
				"c": 300,
			},
			currentCounts: map[string]int{
				"a": 100,
				"b": 200,
				"c": 300,
			},
			wantSig: false,
		},
		{
			name: "proportionally same",
			baselineCounts: map[string]int{
				"a": 10,
				"b": 20,
				"c": 30,
			},
			currentCounts: map[string]int{
				"a": 100,
				"b": 200,
				"c": 300,
			},
			wantSig: false,
		},
		{
			name: "significantly different",
			baselineCounts: map[string]int{
				"a": 100,
				"b": 100,
				"c": 100,
			},
			currentCounts: map[string]int{
				"a": 10,
				"b": 200,
				"c": 90,
			},
			wantSig: true,
		},
		{
			name:           "empty baseline",
			baselineCounts: map[string]int{},
			currentCounts: map[string]int{
				"a": 10,
			},
			wantSig: false,
		},
		{
			name: "empty current",
			baselineCounts: map[string]int{
				"a": 10,
			},
			currentCounts: map[string]int{},
			wantSig:       false,
		},
		{
			name: "new category in current",
			baselineCounts: map[string]int{
				"a": 100,
				"b": 100,
			},
			currentCounts: map[string]int{
				"a": 80,
				"b": 80,
				"c": 40,
			},
			wantSig: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ChiSquareTestFromCounts(tt.baselineCounts, tt.currentCounts)

			if result.Test != TestChiSquare {
				t.Errorf("expected test type %s, got %s", TestChiSquare, result.Test)
			}

			if result.Significant != tt.wantSig {
				t.Errorf("expected Significant=%v, got %v (chi-square=%f)",
					tt.wantSig, result.Significant, result.Statistic)
			}
		})
	}
}

func TestChiSquareCriticalValue(t *testing.T) {
	tests := []struct {
		df       int
		expected float64
	}{
		{1, 3.841},
		{2, 5.991},
		{5, 11.070},
		{10, 18.307},
		{0, 0}, // Invalid df.
	}

	for _, tt := range tests {
		result := chiSquareCriticalValue(tt.df, 0.05)
		if math.Abs(result-tt.expected) > 0.001 {
			t.Errorf("df=%d: expected %f, got %f", tt.df, tt.expected, result)
		}
	}
}

func TestChiSquareCriticalValueLargeDf(t *testing.T) {
	// Test Wilson-Hilferty approximation for large df.
	result := chiSquareCriticalValue(100, 0.05)

	// For df=100 at alpha=0.05, critical value should be around 124.
	if result < 120 || result > 130 {
		t.Errorf("expected critical value around 124 for df=100, got %f", result)
	}
}

func TestChiSquarePValue(t *testing.T) {
	tests := []struct {
		chiSquare float64
		df        int
		minPValue float64
		maxPValue float64
	}{
		{0, 5, 0.99, 1.0},      // Chi-square of 0 should have p-value ~1.
		{20, 5, 0.0, 0.01},     // Large chi-square should have small p-value.
		{5.991, 2, 0.04, 0.06}, // Critical value at alpha=0.05.
		{-1, 5, 1.0, 1.0},      // Negative chi-square returns 1.
		{10, 0, 1.0, 1.0},      // Invalid df returns 1.
		{10, -1, 1.0, 1.0},     // Negative df returns 1.
	}

	for _, tt := range tests {
		result := chiSquarePValue(tt.chiSquare, tt.df)
		if result < tt.minPValue || result > tt.maxPValue {
			t.Errorf("chiSquare=%f, df=%d: expected p-value in [%f,%f], got %f",
				tt.chiSquare, tt.df, tt.minPValue, tt.maxPValue, result)
		}
	}
}

func TestChiSquarePValueLargeDf(t *testing.T) {
	// Test Wilson-Hilferty approximation for large df (> 30).
	result := chiSquarePValue(50, 50)

	// For chi-square = df, p-value should be around 0.5.
	if result < 0.3 || result > 0.7 {
		t.Errorf("expected p-value around 0.5 for chi-square=df=50, got %f", result)
	}
}

func TestCalculatePercentile(t *testing.T) {
	tests := []struct {
		name     string
		sorted   []float64
		p        float64
		expected float64
	}{
		{
			name:     "median of odd length",
			sorted:   []float64{1, 2, 3, 4, 5},
			p:        50,
			expected: 3,
		},
		{
			name:     "25th percentile",
			sorted:   []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			p:        25,
			expected: 3.25,
		},
		{
			name:     "75th percentile",
			sorted:   []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			p:        75,
			expected: 7.75,
		},
		{
			name:     "0th percentile",
			sorted:   []float64{1, 2, 3, 4, 5},
			p:        0,
			expected: 1,
		},
		{
			name:     "100th percentile",
			sorted:   []float64{1, 2, 3, 4, 5},
			p:        100,
			expected: 5,
		},
		{
			name:     "negative percentile",
			sorted:   []float64{1, 2, 3, 4, 5},
			p:        -10,
			expected: 1,
		},
		{
			name:     "over 100 percentile",
			sorted:   []float64{1, 2, 3, 4, 5},
			p:        110,
			expected: 5,
		},
		{
			name:     "empty slice",
			sorted:   []float64{},
			p:        50,
			expected: 0,
		},
		{
			name:     "single element",
			sorted:   []float64{42},
			p:        50,
			expected: 42,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculatePercentile(tt.sorted, tt.p)
			if math.Abs(result-tt.expected) > 0.001 {
				t.Errorf("expected %f, got %f", tt.expected, result)
			}
		})
	}
}

func TestCalculateMedian(t *testing.T) {
	tests := []struct {
		name     string
		values   []float64
		expected float64
	}{
		{
			name:     "odd length",
			values:   []float64{3, 1, 2, 5, 4},
			expected: 3,
		},
		{
			name:     "even length",
			values:   []float64{4, 1, 3, 2},
			expected: 2.5,
		},
		{
			name:     "single element",
			values:   []float64{42},
			expected: 42,
		},
		{
			name:     "empty slice",
			values:   []float64{},
			expected: 0,
		},
		{
			name:     "negative values",
			values:   []float64{-5, -1, -3, -2, -4},
			expected: -3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateMedian(tt.values)
			if math.Abs(result-tt.expected) > 0.001 {
				t.Errorf("expected %f, got %f", tt.expected, result)
			}
		})
	}
}

func TestCalculateIQR(t *testing.T) {
	tests := []struct {
		name     string
		values   []float64
		expected float64
	}{
		{
			name:     "standard case",
			values:   []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			expected: 4.5,
		},
		{
			name:     "all same values",
			values:   []float64{5, 5, 5, 5, 5},
			expected: 0,
		},
		{
			name:     "empty slice",
			values:   []float64{},
			expected: 0,
		},
		{
			name:     "two elements",
			values:   []float64{1, 10},
			expected: 4.5, // Q3-Q1 = 7.75-3.25 = 4.5
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateIQR(tt.values)
			if math.Abs(result-tt.expected) > 0.001 {
				t.Errorf("expected %f, got %f", tt.expected, result)
			}
		})
	}
}

func TestIncompleteGammaUpperTail(t *testing.T) {
	tests := []struct {
		a        float64
		x        float64
		minValue float64
		maxValue float64
	}{
		{1, 0, 1.0, 1.0},     // Q(a, 0) = 1.
		{1, 10, 0.0, 0.0001}, // Q(1, 10) is very small.
		{5, 5, 0.4, 0.6},     // Q(5, 5) is around 0.5.
		{-1, 1, 1.0, 1.0},    // Invalid a returns 1.
		{1, -1, 1.0, 1.0},    // Invalid x returns 1.
	}

	for _, tt := range tests {
		result := incompleteGammaUpperTail(tt.a, tt.x)
		if result < tt.minValue || result > tt.maxValue {
			t.Errorf("a=%f, x=%f: expected in [%f,%f], got %f",
				tt.a, tt.x, tt.minValue, tt.maxValue, result)
		}
	}
}

func TestGammaSeries(t *testing.T) {
	// Test that gamma series returns 0 for x=0.
	result := gammaSeries(2, 0)
	if result != 0 {
		t.Errorf("expected 0 for x=0, got %f", result)
	}

	// Test convergence for small x.
	result = gammaSeries(2, 1)
	if result < 0 || result > 1 {
		t.Errorf("expected result in [0,1], got %f", result)
	}
}

func TestGammaCF(t *testing.T) {
	// Test continued fraction for larger x values.
	result := gammaCF(2, 5)

	// For a=2, x=5, the upper incomplete gamma should be small.
	if result < 0 || result > 0.1 {
		t.Errorf("expected small value for a=2, x=5, got %f", result)
	}
}

func TestLogGamma(t *testing.T) {
	tests := []struct {
		x        float64
		expected float64
		tol      float64
	}{
		{1, 0, 0.001},        // log(Gamma(1)) = log(1) = 0.
		{2, 0, 0.001},        // log(Gamma(2)) = log(1) = 0.
		{0.5, 0.5724, 0.001}, // log(Gamma(0.5)) = log(sqrt(pi)).
		{-1, math.Inf(1), 0}, // Invalid input.
	}

	for _, tt := range tests {
		result := logGamma(tt.x)
		if tt.expected == math.Inf(1) {
			if !math.IsInf(result, 1) {
				t.Errorf("x=%f: expected +Inf, got %f", tt.x, result)
			}
		} else if math.Abs(result-tt.expected) > tt.tol {
			t.Errorf("x=%f: expected %f, got %f", tt.x, tt.expected, result)
		}
	}
}

// Benchmark tests.

func BenchmarkKolmogorovSmirnovTest(b *testing.B) {
	sample1 := make([]float64, 1000)
	sample2 := make([]float64, 1000)
	for i := range sample1 {
		sample1[i] = float64(i)
		sample2[i] = float64(i) + 0.5
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		KolmogorovSmirnovTest(sample1, sample2)
	}
}

func BenchmarkPopulationStabilityIndex(b *testing.B) {
	baseline := make([]float64, 1000)
	current := make([]float64, 1000)
	for i := range baseline {
		baseline[i] = float64(i)
		current[i] = float64(i) + 0.5
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PopulationStabilityIndex(baseline, current, 10)
	}
}

func BenchmarkChiSquareTest(b *testing.B) {
	observed := make([]float64, 100)
	expected := make([]float64, 100)
	for i := range observed {
		observed[i] = float64(i + 1)
		expected[i] = float64(i + 1)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ChiSquareTest(observed, expected)
	}
}
