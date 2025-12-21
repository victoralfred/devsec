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
	"time"

	"github.com/victoralfred/gowritter/safepath"
)

// AuditTrail tracks audit information for a scan operation.
// Fields ordered for optimal memory alignment.
type AuditTrail struct {
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
	a.scannerInfo[info.Name] = info
}

// StartScanner starts tracking a scanner and returns a function to complete it.
func (a *AuditTrail) StartScanner(name, version string) func(status string) {
	startTime := time.Now()
	return func(status string) {
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
	a.contentHashes[filePath] = hashStr

	return hashStr, nil
}

// HashContent calculates and records the SHA-256 hash of content.
func (a *AuditTrail) HashContent(name string, content []byte) string {
	hash := sha256.Sum256(content)
	hashStr := hex.EncodeToString(hash[:])
	a.contentHashes[name] = hashStr
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

	return &AuditReport{
		Operations:    a.operations,
		Scanners:      a.scannerInfo,
		ContentHashes: a.contentHashes,
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
	return a.operations
}

// GetScannerInfo returns information about all scanners.
func (a *AuditTrail) GetScannerInfo() map[string]ScannerInfo {
	return a.scannerInfo
}

// GetContentHashes returns all recorded content hashes.
func (a *AuditTrail) GetContentHashes() map[string]string {
	return a.contentHashes
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
	var sb strings.Builder

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
	if len(a.scannerInfo) > 0 {
		sb.WriteString("Scanners Used:\n")
		scanners := make([]string, 0, len(a.scannerInfo))
		for name := range a.scannerInfo {
			scanners = append(scanners, name)
		}
		sort.Strings(scanners)
		for _, name := range scanners {
			info := a.scannerInfo[name]
			sb.WriteString(fmt.Sprintf("  - %s v%s [%s]\n", info.Name, info.Version, info.Status))
		}
		sb.WriteString("\n")
	}

	// Operations
	if len(a.operations) > 0 {
		sb.WriteString("Operations:\n")
		for i := range a.operations {
			op := &a.operations[i]
			duration := ""
			if op.Duration > 0 {
				duration = fmt.Sprintf(" (%s)", op.Duration)
			}
			sb.WriteString(fmt.Sprintf("  - [%s] %s: %s%s\n", op.Timestamp.Format("15:04:05"), op.Name, op.Status, duration))
		}
		sb.WriteString("\n")
	}

	// Content Hashes
	if len(a.contentHashes) > 0 {
		sb.WriteString("Content Hashes (SHA-256):\n")
		files := make([]string, 0, len(a.contentHashes))
		for file := range a.contentHashes {
			files = append(files, file)
		}
		sort.Strings(files)
		for _, file := range files {
			sb.WriteString(fmt.Sprintf("  %s: %s\n", file, a.contentHashes[file][:16]+"..."))
		}
	}

	return sb.String()
}
