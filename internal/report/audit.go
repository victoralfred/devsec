// Package report provides functionality for aggregating and formatting security findings.
package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/victoralfred/gowritter/safepath"
)

const (
	// MaxOperations is the maximum number of operations to prevent memory exhaustion.
	MaxOperations = 10000
	// MaxContentHashes is the maximum number of content hashes to track.
	MaxContentHashes = 10000
)

// AuditTrail tracks audit information for a scan operation.
// Fields ordered for optimal memory alignment.
type AuditTrail struct {
	mu            sync.RWMutex
	operations    []Operation
	scannerInfo   map[string]ScannerInfo
	contentHashes map[string]string
	startTime     time.Time
	endTime       time.Time
	targetPath    string
	hostInfo      HostInfo
}

// Operation represents a single operation in the audit trail.
// Fields ordered for optimal memory alignment.
type Operation struct {
	Timestamp time.Time     `json:"timestamp"`
	Name      string        `json:"name"`
	Details   string        `json:"details,omitempty"`
	Status    string        `json:"status"`
	Duration  time.Duration `json:"duration,omitempty"`
}

// ScannerInfo contains information about a scanner used in the scan.
// Fields ordered for optimal memory alignment.
type ScannerInfo struct {
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	ConfigPath string    `json:"config_path,omitempty"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	Status     string    `json:"status"`
}

// HostInfo contains information about the host system.
// Fields ordered for optimal memory alignment.
type HostInfo struct {
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	NumCPU   int    `json:"num_cpu"`
}

// AuditReport represents the complete audit trail for a scan.
// Fields ordered for optimal memory alignment.
type AuditReport struct {
	StartTime     time.Time              `json:"start_time"`
	EndTime       time.Time              `json:"end_time"`
	Scanners      map[string]ScannerInfo `json:"scanners"`
	ContentHashes map[string]string      `json:"content_hashes"`
	TargetPath    string                 `json:"target_path"`
	Version       string                 `json:"version"`
	Host          HostInfo               `json:"host"`
	Operations    []Operation            `json:"operations"`
	Duration      time.Duration          `json:"duration"`
}

// NewAuditTrail creates a new audit trail for the given target path.
func NewAuditTrail(targetPath string) *AuditTrail {
	return &AuditTrail{
		operations:    make([]Operation, 0),
		scannerInfo:   make(map[string]ScannerInfo),
		contentHashes: make(map[string]string),
		startTime:     time.Now(),
		targetPath:    targetPath,
		hostInfo:      getHostInfo(),
	}
}

// getHostInfo collects information about the host system.
func getHostInfo() HostInfo {
	return HostInfo{
		OS:     runtime.GOOS,
		Arch:   runtime.GOARCH,
		NumCPU: runtime.NumCPU(),
	}
}

// RecordOperation records an operation in the audit trail.
func (a *AuditTrail) RecordOperation(name, status, details string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.operations) >= MaxOperations {
		// Drop oldest operation if limit reached
		a.operations = a.operations[1:]
	}

	op := Operation{
		Timestamp: time.Now(),
		Name:      name,
		Status:    status,
		Details:   details,
	}
	a.operations = append(a.operations, op)
}

// StartOperation starts tracking an operation and returns a function to complete it.
func (a *AuditTrail) StartOperation(name string) func(status, details string) {
	startTime := time.Now()
	return func(status, details string) {
		a.mu.Lock()
		defer a.mu.Unlock()

		if len(a.operations) >= MaxOperations {
			// Drop oldest operation if limit reached
			a.operations = a.operations[1:]
		}

		op := Operation{
			Timestamp: startTime,
			Name:      name,
			Status:    status,
			Details:   details,
			Duration:  time.Since(startTime),
		}
		a.operations = append(a.operations, op)
	}
}

// RecordScanner records information about a scanner used in the scan.
func (a *AuditTrail) RecordScanner(info ScannerInfo) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.scannerInfo[info.Name] = info
}

// StartScanner starts tracking a scanner and returns a function to complete it.
func (a *AuditTrail) StartScanner(name, version string) func(status string) {
	startTime := time.Now()
	return func(status string) {
		a.mu.Lock()
		defer a.mu.Unlock()

		info := ScannerInfo{
			Name:      name,
			Version:   version,
			StartTime: startTime,
			EndTime:   time.Now(),
			Status:    status,
		}
		a.scannerInfo[name] = info
	}
}

// HashFile calculates and records the SHA-256 hash of a file.
func (a *AuditTrail) HashFile(ctx context.Context, filePath string) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	// Get directory and filename for safepath
	dir := filepath.Dir(filePath)
	filename := filepath.Base(filePath)

	sp, err := safepath.New(dir)
	if err != nil {
		return "", fmt.Errorf("create safepath: %w", err)
	}

	data, err := sp.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}

	hash := sha256.Sum256(data)
	hashStr := hex.EncodeToString(hash[:])

	a.mu.Lock()
	if len(a.contentHashes) >= MaxContentHashes {
		// Remove oldest entry (simple FIFO, could be improved)
		for k := range a.contentHashes {
			delete(a.contentHashes, k)
			break
		}
	}
	a.contentHashes[filePath] = hashStr
	a.mu.Unlock()

	return hashStr, nil
}

// HashContent calculates and records the SHA-256 hash of content.
func (a *AuditTrail) HashContent(name string, content []byte) string {
	hash := sha256.Sum256(content)
	hashStr := hex.EncodeToString(hash[:])

	a.mu.Lock()
	if len(a.contentHashes) >= MaxContentHashes {
		// Remove oldest entry (simple FIFO, could be improved)
		for k := range a.contentHashes {
			delete(a.contentHashes, k)
			break
		}
	}
	a.contentHashes[name] = hashStr
	a.mu.Unlock()

	return hashStr
}

// HashReader calculates the SHA-256 hash from a reader.
func HashReader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", fmt.Errorf("hash content: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Complete marks the audit trail as complete and finalizes timing.
func (a *AuditTrail) Complete() {
	a.endTime = time.Now()
}

// GenerateReport generates the complete audit report.
func (a *AuditTrail) GenerateReport(version string) *AuditReport {
	if a.endTime.IsZero() {
		a.Complete()
	}

	a.mu.RLock()
	operations := make([]Operation, len(a.operations))
	copy(operations, a.operations)
	scanners := make(map[string]ScannerInfo, len(a.scannerInfo))
	for k, v := range a.scannerInfo {
		scanners[k] = v
	}
	contentHashes := make(map[string]string, len(a.contentHashes))
	for k, v := range a.contentHashes {
		contentHashes[k] = v
	}
	a.mu.RUnlock()

	return &AuditReport{
		Operations:    operations,
		Scanners:      scanners,
		ContentHashes: contentHashes,
		StartTime:     a.startTime,
		EndTime:       a.endTime,
		TargetPath:    a.targetPath,
		Host:          a.hostInfo,
		Duration:      a.endTime.Sub(a.startTime),
		Version:       version,
	}
}

// GetOperations returns all recorded operations.
func (a *AuditTrail) GetOperations() []Operation {
	a.mu.RLock()
	defer a.mu.RUnlock()

	operations := make([]Operation, len(a.operations))
	copy(operations, a.operations)
	return operations
}

// GetScannerInfo returns information about all scanners.
func (a *AuditTrail) GetScannerInfo() map[string]ScannerInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()

	scanners := make(map[string]ScannerInfo, len(a.scannerInfo))
	for k, v := range a.scannerInfo {
		scanners[k] = v
	}
	return scanners
}

// GetContentHashes returns all recorded content hashes.
func (a *AuditTrail) GetContentHashes() map[string]string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	hashes := make(map[string]string, len(a.contentHashes))
	for k, v := range a.contentHashes {
		hashes[k] = v
	}
	return hashes
}

// GetDuration returns the total duration of the scan.
func (a *AuditTrail) GetDuration() time.Duration {
	if a.endTime.IsZero() {
		return time.Since(a.startTime)
	}
	return a.endTime.Sub(a.startTime)
}

// FormatAuditSummary formats a human-readable summary of the audit trail.
func (a *AuditTrail) FormatAuditSummary() string {
	a.mu.RLock()
	operations := make([]Operation, len(a.operations))
	copy(operations, a.operations)
	scannerInfo := make(map[string]ScannerInfo, len(a.scannerInfo))
	for k, v := range a.scannerInfo {
		scannerInfo[k] = v
	}
	contentHashes := make(map[string]string, len(a.contentHashes))
	for k, v := range a.contentHashes {
		contentHashes[k] = v
	}
	a.mu.RUnlock()

	var sb strings.Builder
	sb.Grow(2048) // Pre-allocate capacity

	sb.WriteString("Audit Trail Summary\n")
	sb.WriteString("===================\n\n")

	sb.WriteString(fmt.Sprintf("Target: %s\n", a.targetPath))
	sb.WriteString(fmt.Sprintf("Start Time: %s\n", a.startTime.Format(time.RFC3339)))
	if !a.endTime.IsZero() {
		sb.WriteString(fmt.Sprintf("End Time: %s\n", a.endTime.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("Duration: %s\n", a.GetDuration()))
	}
	sb.WriteString(fmt.Sprintf("Host: %s/%s (%d CPUs)\n\n", a.hostInfo.OS, a.hostInfo.Arch, a.hostInfo.NumCPU))

	// Scanners
	if len(scannerInfo) > 0 {
		sb.WriteString("Scanners Used:\n")
		scanners := make([]string, 0, len(scannerInfo))
		for name := range scannerInfo {
			scanners = append(scanners, name)
		}
		sort.Strings(scanners)
		for _, name := range scanners {
			info := scannerInfo[name]
			sb.WriteString(fmt.Sprintf("  - %s v%s [%s]\n", info.Name, info.Version, info.Status))
		}
		sb.WriteString("\n")
	}

	// Operations
	if len(operations) > 0 {
		sb.WriteString("Operations:\n")
		for i := range operations {
			op := &operations[i]
			duration := ""
			if op.Duration > 0 {
				duration = fmt.Sprintf(" (%s)", op.Duration)
			}
			sb.WriteString(fmt.Sprintf("  - [%s] %s: %s%s\n", op.Timestamp.Format("15:04:05"), op.Name, op.Status, duration))
		}
		sb.WriteString("\n")
	}

	// Content Hashes
	if len(contentHashes) > 0 {
		sb.WriteString("Content Hashes (SHA-256):\n")
		files := make([]string, 0, len(contentHashes))
		for file := range contentHashes {
			files = append(files, file)
		}
		sort.Strings(files)
		for _, file := range files {
			hash := contentHashes[file]
			if len(hash) > 16 {
				sb.WriteString(fmt.Sprintf("  %s: %s\n", file, hash[:16]+"..."))
			} else {
				sb.WriteString(fmt.Sprintf("  %s: %s\n", file, hash))
			}
		}
	}

	return sb.String()
}
