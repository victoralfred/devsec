package pipeline

import (
	"strings"
	"testing"
	"time"
)

func TestStageKind_IsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		kind  StageKind
		valid bool
	}{
		{"scan", StageKindScan, true},
		{"policy", StageKindPolicy, true},
		{"report", StageKindReport, true},
		{"compliance", StageKindCompliance, true},
		{"custom", StageKindCustom, true},
		{"empty", StageKind(""), false},
		{"invalid", StageKind("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.kind.IsValid(); got != tt.valid {
				t.Errorf("StageKind.IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestStageKind_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		kind StageKind
		want string
	}{
		{StageKindScan, "scan"},
		{StageKindPolicy, "policy"},
		{StageKindReport, "report"},
		{StageKindCompliance, "compliance"},
		{StageKindCustom, "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.kind.String(); got != tt.want {
				t.Errorf("StageKind.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStageStatus_IsTerminal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status   StageStatus
		terminal bool
	}{
		{StageStatusPending, false},
		{StageStatusRunning, false},
		{StageStatusSuccess, true},
		{StageStatusFailed, true},
		{StageStatusSkipped, true},
		{StageStatusCanceled, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			t.Parallel()
			if got := tt.status.IsTerminal(); got != tt.terminal {
				t.Errorf("StageStatus.IsTerminal() = %v, want %v", got, tt.terminal)
			}
		})
	}
}

func TestStageStatus_IsSuccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status  StageStatus
		success bool
	}{
		{StageStatusSuccess, true},
		{StageStatusFailed, false},
		{StageStatusPending, false},
		{StageStatusRunning, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			t.Parallel()
			if got := tt.status.IsSuccess(); got != tt.success {
				t.Errorf("StageStatus.IsSuccess() = %v, want %v", got, tt.success)
			}
		})
	}
}

func TestContinueCondition_IsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		cond  ContinueCondition
		valid bool
	}{
		{ContinueOnSuccess, true},
		{ContinueOnFailure, true},
		{ContinueAlways, true},
		{"", true}, // empty is valid (defaults to success)
		{ContinueCondition("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.cond), func(t *testing.T) {
			t.Parallel()
			if got := tt.cond.IsValid(); got != tt.valid {
				t.Errorf("ContinueCondition.IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestStage_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		wantErr error
		stage   *Stage
		name    string
	}{
		{
			name:    "nil stage",
			stage:   nil,
			wantErr: ErrNilStage,
		},
		{
			name:    "empty name",
			stage:   &Stage{Kind: StageKindScan},
			wantErr: ErrEmptyStageName,
		},
		{
			name: "name too long",
			stage: &Stage{
				Name: strings.Repeat("a", MaxStageNameLen+1),
				Kind: StageKindScan,
			},
			wantErr: ErrStageNameTooLong,
		},
		{
			name: "invalid kind",
			stage: &Stage{
				Name: "test",
				Kind: StageKind("invalid"),
			},
			wantErr: ErrInvalidStageKind,
		},
		{
			name: "invalid continue condition",
			stage: &Stage{
				Name:       "test",
				Kind:       StageKindScan,
				ContinueOn: ContinueCondition("invalid"),
			},
			wantErr: ErrInvalidContinueCondition,
		},
		{
			name: "too many dependencies",
			stage: &Stage{
				Name:      "test",
				Kind:      StageKindScan,
				DependsOn: make([]string, MaxDependencies+1),
			},
			wantErr: ErrTooManyDependencies,
		},
		{
			name: "too many config entries",
			stage: &Stage{
				Name:   "test",
				Kind:   StageKindScan,
				Config: makeConfig(MaxConfigEntries + 1),
			},
			wantErr: ErrTooManyConfigEntries,
		},
		{
			name: "config key too long",
			stage: &Stage{
				Name: "test",
				Kind: StageKindScan,
				Config: map[string]string{
					strings.Repeat("k", MaxConfigKeyLen+1): "value",
				},
			},
			wantErr: ErrConfigKeyTooLong,
		},
		{
			name: "config value too long",
			stage: &Stage{
				Name: "test",
				Kind: StageKindScan,
				Config: map[string]string{
					"key": strings.Repeat("v", MaxConfigValueLen+1),
				},
			},
			wantErr: ErrConfigValueTooLong,
		},
		{
			name: "valid stage",
			stage: &Stage{
				Name:      "test",
				Kind:      StageKindScan,
				DependsOn: []string{"dep1"},
				Timeout:   5 * time.Minute,
				Config:    map[string]string{"key": "value"},
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.stage.Validate()
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("Stage.Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("Stage.Validate() unexpected error = %v", err)
			}
		})
	}
}

func TestStage_GetTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"zero", 0, DefaultStageTimeout},
		{"negative", -1, DefaultStageTimeout},
		{"positive", 5 * time.Minute, 5 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := &Stage{Timeout: tt.timeout}
			if got := s.GetTimeout(); got != tt.want {
				t.Errorf("Stage.GetTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPipeline_Validate(t *testing.T) {
	t.Parallel()

	validStage := Stage{Name: "stage1", Kind: StageKindScan}

	tests := []struct {
		wantErr  error
		pipeline *Pipeline
		name     string
	}{
		{
			name:     "nil pipeline",
			pipeline: nil,
			wantErr:  ErrNilPipeline,
		},
		{
			name:     "empty name",
			pipeline: &Pipeline{Stages: []Stage{validStage}},
			wantErr:  ErrEmptyPipelineName,
		},
		{
			name: "name too long",
			pipeline: &Pipeline{
				Name:   strings.Repeat("a", MaxPipelineNameLen+1),
				Stages: []Stage{validStage},
			},
			wantErr: ErrPipelineNameTooLong,
		},
		{
			name:     "no stages",
			pipeline: &Pipeline{Name: "test"},
			wantErr:  ErrNoStages,
		},
		{
			name: "too many stages",
			pipeline: &Pipeline{
				Name:   "test",
				Stages: makeStages(MaxStages + 1),
			},
			wantErr: ErrTooManyStages,
		},
		{
			name: "too many metadata",
			pipeline: &Pipeline{
				Name:     "test",
				Stages:   []Stage{validStage},
				Metadata: makeConfig(MaxMetadataEntries + 1),
			},
			wantErr: ErrTooManyMetadataEntries,
		},
		{
			name: "duplicate stage name",
			pipeline: &Pipeline{
				Name: "test",
				Stages: []Stage{
					{Name: "stage1", Kind: StageKindScan},
					{Name: "stage1", Kind: StageKindPolicy},
				},
			},
			wantErr: ErrDuplicateStageName,
		},
		{
			name: "invalid dependency",
			pipeline: &Pipeline{
				Name: "test",
				Stages: []Stage{
					{Name: "stage1", Kind: StageKindScan, DependsOn: []string{"nonexistent"}},
				},
			},
			wantErr: ErrInvalidDependency,
		},
		{
			name: "self dependency",
			pipeline: &Pipeline{
				Name: "test",
				Stages: []Stage{
					{Name: "stage1", Kind: StageKindScan, DependsOn: []string{"stage1"}},
				},
			},
			wantErr: ErrSelfDependency,
		},
		{
			name: "circular dependency",
			pipeline: &Pipeline{
				Name: "test",
				Stages: []Stage{
					{Name: "stage1", Kind: StageKindScan, DependsOn: []string{"stage2"}},
					{Name: "stage2", Kind: StageKindPolicy, DependsOn: []string{"stage1"}},
				},
			},
			wantErr: ErrCircularDependency,
		},
		{
			name: "valid pipeline",
			pipeline: &Pipeline{
				Name: "test",
				Stages: []Stage{
					{Name: "stage1", Kind: StageKindScan},
					{Name: "stage2", Kind: StageKindPolicy, DependsOn: []string{"stage1"}},
				},
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.pipeline.Validate()
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("Pipeline.Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("Pipeline.Validate() unexpected error = %v", err)
			}
		})
	}
}

func TestPipeline_GetTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"zero", 0, DefaultTimeout},
		{"negative", -1, DefaultTimeout},
		{"positive", 1 * time.Hour, 1 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := &Pipeline{Timeout: tt.timeout}
			if got := p.GetTimeout(); got != tt.want {
				t.Errorf("Pipeline.GetTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPipeline_GetStage(t *testing.T) {
	t.Parallel()

	p := &Pipeline{
		Name: "test",
		Stages: []Stage{
			{Name: "stage1", Kind: StageKindScan},
			{Name: "stage2", Kind: StageKindPolicy},
		},
	}

	t.Run("existing stage", func(t *testing.T) {
		t.Parallel()
		stage, ok := p.GetStage("stage1")
		if !ok {
			t.Fatal("expected to find stage")
		}
		if stage.Name != "stage1" {
			t.Errorf("got stage %q, want stage1", stage.Name)
		}
	})

	t.Run("non-existing stage", func(t *testing.T) {
		t.Parallel()
		_, ok := p.GetStage("nonexistent")
		if ok {
			t.Error("expected stage not found")
		}
	})
}

func TestPipeline_GetStageIndex(t *testing.T) {
	t.Parallel()

	p := &Pipeline{
		Name: "test",
		Stages: []Stage{
			{Name: "stage1", Kind: StageKindScan},
			{Name: "stage2", Kind: StageKindPolicy},
		},
	}

	t.Run("existing stage", func(t *testing.T) {
		t.Parallel()
		idx, ok := p.GetStageIndex("stage2")
		if !ok {
			t.Fatal("expected to find stage")
		}
		if idx != 1 {
			t.Errorf("got index %d, want 1", idx)
		}
	})

	t.Run("non-existing stage", func(t *testing.T) {
		t.Parallel()
		idx, ok := p.GetStageIndex("nonexistent")
		if ok {
			t.Error("expected stage not found")
		}
		if idx != -1 {
			t.Errorf("got index %d, want -1", idx)
		}
	})
}

func TestHasCycle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		stages []Stage
		cycle  bool
	}{
		{
			name:   "no stages",
			stages: nil,
			cycle:  false,
		},
		{
			name: "single stage no deps",
			stages: []Stage{
				{Name: "a"},
			},
			cycle: false,
		},
		{
			name: "linear chain",
			stages: []Stage{
				{Name: "a"},
				{Name: "b", DependsOn: []string{"a"}},
				{Name: "c", DependsOn: []string{"b"}},
			},
			cycle: false,
		},
		{
			name: "diamond",
			stages: []Stage{
				{Name: "a"},
				{Name: "b", DependsOn: []string{"a"}},
				{Name: "c", DependsOn: []string{"a"}},
				{Name: "d", DependsOn: []string{"b", "c"}},
			},
			cycle: false,
		},
		{
			name: "simple cycle",
			stages: []Stage{
				{Name: "a", DependsOn: []string{"b"}},
				{Name: "b", DependsOn: []string{"a"}},
			},
			cycle: true,
		},
		{
			name: "long cycle",
			stages: []Stage{
				{Name: "a", DependsOn: []string{"d"}},
				{Name: "b", DependsOn: []string{"a"}},
				{Name: "c", DependsOn: []string{"b"}},
				{Name: "d", DependsOn: []string{"c"}},
			},
			cycle: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := hasCycle(tt.stages); got != tt.cycle {
				t.Errorf("hasCycle() = %v, want %v", got, tt.cycle)
			}
		})
	}
}

func TestPipelineResult_GetStageResult(t *testing.T) {
	t.Parallel()

	pr := &PipelineResult{
		Stages: []StageResult{
			{Name: "stage1", Status: StageStatusSuccess},
			{Name: "stage2", Status: StageStatusFailed},
		},
	}

	t.Run("existing result", func(t *testing.T) {
		t.Parallel()
		result, ok := pr.GetStageResult("stage1")
		if !ok {
			t.Fatal("expected to find result")
		}
		if result.Status != StageStatusSuccess {
			t.Errorf("got status %v, want success", result.Status)
		}
	})

	t.Run("non-existing result", func(t *testing.T) {
		t.Parallel()
		_, ok := pr.GetStageResult("nonexistent")
		if ok {
			t.Error("expected result not found")
		}
	})
}

func TestPipelineResult_SuccessCount(t *testing.T) {
	t.Parallel()

	pr := &PipelineResult{
		Stages: []StageResult{
			{Name: "stage1", Status: StageStatusSuccess},
			{Name: "stage2", Status: StageStatusFailed},
			{Name: "stage3", Status: StageStatusSuccess},
			{Name: "stage4", Status: StageStatusSkipped},
		},
	}

	if got := pr.SuccessCount(); got != 2 {
		t.Errorf("SuccessCount() = %v, want 2", got)
	}
}

func TestPipelineResult_FailedCount(t *testing.T) {
	t.Parallel()

	pr := &PipelineResult{
		Stages: []StageResult{
			{Name: "stage1", Status: StageStatusSuccess},
			{Name: "stage2", Status: StageStatusFailed},
			{Name: "stage3", Status: StageStatusFailed},
		},
	}

	if got := pr.FailedCount(); got != 2 {
		t.Errorf("FailedCount() = %v, want 2", got)
	}
}

func TestPipelineResult_Summarize(t *testing.T) {
	t.Parallel()

	pr := &PipelineResult{
		Duration: 10 * time.Second,
		Stages: []StageResult{
			{Name: "stage1", Status: StageStatusSuccess},
			{Name: "stage2", Status: StageStatusFailed},
			{Name: "stage3", Status: StageStatusSkipped},
			{Name: "stage4", Status: StageStatusCanceled},
		},
	}

	summary := pr.Summarize()

	if summary.TotalStages != 4 {
		t.Errorf("TotalStages = %v, want 4", summary.TotalStages)
	}
	if summary.SuccessCount != 1 {
		t.Errorf("SuccessCount = %v, want 1", summary.SuccessCount)
	}
	if summary.FailedCount != 1 {
		t.Errorf("FailedCount = %v, want 1", summary.FailedCount)
	}
	if summary.SkippedCount != 1 {
		t.Errorf("SkippedCount = %v, want 1", summary.SkippedCount)
	}
	if summary.CanceledCount != 1 {
		t.Errorf("CanceledCount = %v, want 1", summary.CanceledCount)
	}
	if summary.TotalDuration != 10*time.Second {
		t.Errorf("TotalDuration = %v, want 10s", summary.TotalDuration)
	}
}

func TestValidStageKinds(t *testing.T) {
	t.Parallel()

	kinds := ValidStageKinds()
	if len(kinds) != 5 {
		t.Errorf("expected 5 stage kinds, got %d", len(kinds))
	}

	expectedKinds := map[StageKind]bool{
		StageKindScan:       true,
		StageKindPolicy:     true,
		StageKindReport:     true,
		StageKindCompliance: true,
		StageKindCustom:     true,
	}

	for _, k := range kinds {
		if !expectedKinds[k] {
			t.Errorf("unexpected stage kind: %v", k)
		}
	}
}

// Helper functions.
func makeConfig(n int) map[string]string {
	m := make(map[string]string, n)
	for i := 0; i < n; i++ {
		m[string(rune('a'+i%26))+string(rune('0'+i/26))] = "value"
	}
	return m
}

func makeStages(n int) []Stage {
	stages := make([]Stage, n)
	for i := 0; i < n; i++ {
		stages[i] = Stage{
			Name: string(rune('a'+i%26)) + string(rune('0'+i/26)),
			Kind: StageKindScan,
		}
	}
	return stages
}
