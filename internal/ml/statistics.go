// Package ml provides machine learning security detection and validation capabilities.
package ml

import (
	"math"
	"sort"
)

// StatisticalTest represents a type of statistical test.
type StatisticalTest string

const (
	// TestKolmogorovSmirnov is the Kolmogorov-Smirnov test for distribution comparison.
	TestKolmogorovSmirnov StatisticalTest = "kolmogorov_smirnov"
	// TestPSI is the Population Stability Index.
	TestPSI StatisticalTest = "psi"
	// TestChiSquare is the Chi-Square test for categorical data.
	TestChiSquare StatisticalTest = "chi_square"
)

// StatisticalResult contains the result of a statistical test.
// Fields ordered for optimal memory alignment.
type StatisticalResult struct {
	Test        StatisticalTest `json:"test"`
	Statistic   float64         `json:"statistic"`
	PValue      float64         `json:"p_value,omitempty"`
	Threshold   float64         `json:"threshold"`
	Significant bool            `json:"significant"`
}

// KolmogorovSmirnovTest performs a two-sample Kolmogorov-Smirnov test.
// Returns the KS statistic (D) which is the maximum difference between
// the two empirical cumulative distribution functions.
func KolmogorovSmirnovTest(sample1, sample2 []float64) StatisticalResult {
	if len(sample1) == 0 || len(sample2) == 0 {
		return StatisticalResult{
			Test:      TestKolmogorovSmirnov,
			Statistic: 0,
			Threshold: 0.05,
		}
	}

	// Sort both samples.
	s1 := make([]float64, len(sample1))
	s2 := make([]float64, len(sample2))
	copy(s1, sample1)
	copy(s2, sample2)
	sort.Float64s(s1)
	sort.Float64s(s2)

	n1 := float64(len(s1))
	n2 := float64(len(s2))

	// Merge and compute empirical CDFs.
	var maxD float64
	i, j := 0, 0

	for i < len(s1) || j < len(s2) {
		// Advance pointers based on values.
		switch {
		case i < len(s1) && j < len(s2):
			switch {
			case s1[i] < s2[j]:
				i++
			case s1[i] > s2[j]:
				j++
			default:
				// Equal values: advance both pointers.
				i++
				j++
			}
		case i < len(s1):
			i++
		default:
			j++
		}

		// Compute ECDF values after advancement.
		d1 := float64(i) / n1
		d2 := float64(j) / n2

		d := math.Abs(d1 - d2)
		if d > maxD {
			maxD = d
		}
	}

	// Calculate critical value at alpha = 0.05.
	// Using the asymptotic formula: c(alpha) * sqrt((n1+n2)/(n1*n2))
	// where c(0.05) = 1.36.
	criticalValue := 1.36 * math.Sqrt((n1+n2)/(n1*n2))

	// Approximate p-value using Kolmogorov distribution.
	// Using simplified approximation for large samples.
	en := math.Sqrt(n1 * n2 / (n1 + n2))
	lambda := (en + 0.12 + 0.11/en) * maxD
	pValue := 2 * math.Exp(-2*lambda*lambda)
	if pValue > 1 {
		pValue = 1
	}
	if pValue < 0 {
		pValue = 0
	}

	return StatisticalResult{
		Test:        TestKolmogorovSmirnov,
		Statistic:   maxD,
		PValue:      pValue,
		Threshold:   criticalValue,
		Significant: maxD > criticalValue,
	}
}

// PopulationStabilityIndex calculates the PSI between two distributions.
// PSI < 0.1: No significant change.
// 0.1 <= PSI < 0.25: Moderate change.
// PSI >= 0.25: Significant change.
func PopulationStabilityIndex(baseline, current []float64, numBins int) StatisticalResult {
	if len(baseline) == 0 || len(current) == 0 {
		return StatisticalResult{
			Test:      TestPSI,
			Statistic: 0,
			Threshold: 0.1,
		}
	}

	if numBins <= 0 {
		numBins = 10 // Default to 10 bins.
	}

	// Find min and max across both datasets.
	minVal := baseline[0]
	maxVal := baseline[0]
	for _, v := range baseline {
		if v < minVal {
			minVal = v
		}
		if v > maxVal {
			maxVal = v
		}
	}
	for _, v := range current {
		if v < minVal {
			minVal = v
		}
		if v > maxVal {
			maxVal = v
		}
	}

	// Handle edge case where all values are the same.
	if maxVal == minVal {
		return StatisticalResult{
			Test:        TestPSI,
			Statistic:   0,
			Threshold:   0.1,
			Significant: false,
		}
	}

	// Create bins.
	binWidth := (maxVal - minVal) / float64(numBins)
	baselineBins := make([]float64, numBins)
	currentBins := make([]float64, numBins)

	// Bin the baseline data.
	for _, v := range baseline {
		bin := int((v - minVal) / binWidth)
		if bin >= numBins {
			bin = numBins - 1
		}
		if bin < 0 {
			bin = 0
		}
		baselineBins[bin]++
	}

	// Bin the current data.
	for _, v := range current {
		bin := int((v - minVal) / binWidth)
		if bin >= numBins {
			bin = numBins - 1
		}
		if bin < 0 {
			bin = 0
		}
		currentBins[bin]++
	}

	// Convert to proportions and calculate PSI.
	baselineTotal := float64(len(baseline))
	currentTotal := float64(len(current))
	var psi float64

	for i := 0; i < numBins; i++ {
		baselineProp := baselineBins[i] / baselineTotal
		currentProp := currentBins[i] / currentTotal

		// Add small constant to avoid division by zero and log(0).
		if baselineProp < 0.0001 {
			baselineProp = 0.0001
		}
		if currentProp < 0.0001 {
			currentProp = 0.0001
		}

		psi += (currentProp - baselineProp) * math.Log(currentProp/baselineProp)
	}

	return StatisticalResult{
		Test:        TestPSI,
		Statistic:   psi,
		Threshold:   0.1, // < 0.1 is considered stable.
		Significant: psi >= 0.1,
	}
}

// ChiSquareTest performs a chi-square test for categorical data.
// Compares observed frequencies against expected frequencies.
func ChiSquareTest(observed, expected []float64) StatisticalResult {
	if len(observed) != len(expected) || len(observed) == 0 {
		return StatisticalResult{
			Test:      TestChiSquare,
			Statistic: 0,
			Threshold: 0,
		}
	}

	var chiSquare float64
	df := len(observed) - 1 // Degrees of freedom.

	for i := range observed {
		if expected[i] > 0 {
			diff := observed[i] - expected[i]
			chiSquare += (diff * diff) / expected[i]
		}
	}

	// Get critical value for alpha = 0.05.
	criticalValue := chiSquareCriticalValue(df, 0.05)

	// Approximate p-value using chi-square distribution.
	pValue := chiSquarePValue(chiSquare, df)

	return StatisticalResult{
		Test:        TestChiSquare,
		Statistic:   chiSquare,
		PValue:      pValue,
		Threshold:   criticalValue,
		Significant: chiSquare > criticalValue,
	}
}

// ChiSquareTestFromCounts performs chi-square test from count maps.
// Useful for comparing categorical distributions.
func ChiSquareTestFromCounts(baselineCounts, currentCounts map[string]int) StatisticalResult {
	// Get all unique categories.
	categories := make(map[string]bool)
	for k := range baselineCounts {
		categories[k] = true
	}
	for k := range currentCounts {
		categories[k] = true
	}

	if len(categories) == 0 {
		return StatisticalResult{
			Test:      TestChiSquare,
			Statistic: 0,
			Threshold: 0,
		}
	}

	// Calculate totals.
	var baselineTotal, currentTotal float64
	for _, v := range baselineCounts {
		baselineTotal += float64(v)
	}
	for _, v := range currentCounts {
		currentTotal += float64(v)
	}

	if baselineTotal == 0 || currentTotal == 0 {
		return StatisticalResult{
			Test:      TestChiSquare,
			Statistic: 0,
			Threshold: 0,
		}
	}

	// Build observed and expected arrays.
	observed := make([]float64, 0, len(categories))
	expected := make([]float64, 0, len(categories))

	for cat := range categories {
		obs := float64(currentCounts[cat])
		// Expected is based on baseline proportions.
		baselineCount := float64(baselineCounts[cat])
		exp := (baselineCount / baselineTotal) * currentTotal

		observed = append(observed, obs)
		expected = append(expected, exp)
	}

	return ChiSquareTest(observed, expected)
}

// chiSquareCriticalValue returns the critical value for chi-square distribution.
// Uses a lookup table for common degrees of freedom at alpha = 0.05.
//
//nolint:unparam // alpha is kept for future support of different significance levels.
func chiSquareCriticalValue(df int, _ float64) float64 {
	// Critical values for alpha = 0.05.
	criticalValues := map[int]float64{
		1:  3.841,
		2:  5.991,
		3:  7.815,
		4:  9.488,
		5:  11.070,
		6:  12.592,
		7:  14.067,
		8:  15.507,
		9:  16.919,
		10: 18.307,
		15: 24.996,
		20: 31.410,
		25: 37.652,
		30: 43.773,
	}

	if val, ok := criticalValues[df]; ok {
		return val
	}

	// Approximate for large df using Wilson-Hilferty transformation.
	// chi^2_{alpha,df} ≈ df * (1 - 2/(9*df) + z_alpha * sqrt(2/(9*df)))^3
	// where z_alpha for 0.05 is approximately 1.645.
	if df > 0 {
		z := 1.645 // z-value for alpha = 0.05 (one-tailed).
		term := 1 - 2.0/(9.0*float64(df)) + z*math.Sqrt(2.0/(9.0*float64(df)))
		return float64(df) * term * term * term
	}

	return 0
}

// chiSquarePValue approximates the p-value for chi-square distribution.
// Uses the regularized incomplete gamma function approximation.
func chiSquarePValue(chiSquare float64, df int) float64 {
	if df <= 0 || chiSquare < 0 {
		return 1.0
	}

	// Use the regularized incomplete gamma function.
	// P(X > chiSquare) = 1 - P(df/2, chiSquare/2) / Gamma(df/2)
	// Simplified approximation for practical use.
	k := float64(df) / 2.0
	x := chiSquare / 2.0

	// Use simple approximation based on normal distribution for large df.
	if df > 30 {
		// Wilson-Hilferty approximation.
		z := math.Pow(chiSquare/float64(df), 1.0/3.0) - (1 - 2.0/(9.0*float64(df)))
		z /= math.Sqrt(2.0 / (9.0 * float64(df)))
		// Standard normal CDF approximation.
		return 0.5 * (1 - math.Erf(z/math.Sqrt2))
	}

	// For smaller df, use series approximation of incomplete gamma.
	return incompleteGammaUpperTail(k, x)
}

// incompleteGammaUpperTail computes the upper tail of the incomplete gamma function.
// Q(a,x) = 1 - P(a,x) where P is the regularized incomplete gamma function.
func incompleteGammaUpperTail(a, x float64) float64 {
	if x < 0 || a <= 0 {
		return 1.0
	}
	if x == 0 {
		return 1.0
	}

	// Use continued fraction for x > a+1.
	if x > a+1 {
		return gammaCF(a, x)
	}

	// Use series expansion for x <= a+1.
	return 1.0 - gammaSeries(a, x)
}

// gammaSeries computes the incomplete gamma function using series expansion.
func gammaSeries(a, x float64) float64 {
	const maxIterations = 100
	const epsilon = 1e-10

	if x == 0 {
		return 0
	}

	ap := a
	sum := 1.0 / a
	delta := sum

	for n := 1; n < maxIterations; n++ {
		ap++
		delta *= x / ap
		sum += delta
		if math.Abs(delta) < math.Abs(sum)*epsilon {
			break
		}
	}

	return sum * math.Exp(-x+a*math.Log(x)-logGamma(a))
}

// gammaCF computes the incomplete gamma function using continued fraction.
func gammaCF(a, x float64) float64 {
	const maxIterations = 100
	const epsilon = 1e-10
	const tiny = 1e-30

	b := x + 1 - a
	c := 1.0 / tiny
	d := 1.0 / b
	h := d

	for n := 1; n < maxIterations; n++ {
		an := -float64(n) * (float64(n) - a)
		b += 2
		d = an*d + b
		if math.Abs(d) < tiny {
			d = tiny
		}
		c = b + an/c
		if math.Abs(c) < tiny {
			c = tiny
		}
		d = 1.0 / d
		delta := d * c
		h *= delta
		if math.Abs(delta-1.0) < epsilon {
			break
		}
	}

	return math.Exp(-x+a*math.Log(x)-logGamma(a)) * h
}

// logGamma computes the natural logarithm of the gamma function.
// Uses Stirling's approximation for efficiency.
func logGamma(x float64) float64 {
	if x <= 0 {
		return math.Inf(1)
	}

	// Use math.Lgamma for accuracy.
	lg, _ := math.Lgamma(x)
	return lg
}

// CalculatePercentile calculates the p-th percentile of a sorted slice.
func CalculatePercentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}

	rank := (p / 100.0) * float64(len(sorted)-1)
	lower := int(rank)
	upper := lower + 1
	if upper >= len(sorted) {
		return sorted[len(sorted)-1]
	}

	weight := rank - float64(lower)
	return sorted[lower]*(1-weight) + sorted[upper]*weight
}

// CalculateMedian calculates the median of a slice.
func CalculateMedian(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	n := len(sorted)
	if n%2 == 0 {
		return (sorted[n/2-1] + sorted[n/2]) / 2.0
	}
	return sorted[n/2]
}

// CalculateIQR calculates the interquartile range.
func CalculateIQR(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	q1 := CalculatePercentile(sorted, 25)
	q3 := CalculatePercentile(sorted, 75)
	return q3 - q1
}
