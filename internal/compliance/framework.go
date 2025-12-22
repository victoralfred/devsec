package compliance

// Framework represents a complete compliance framework.
// Fields ordered for optimal memory alignment.
type Framework struct {
	Metadata    map[string]string `json:"metadata,omitempty"`
	Name        string            `json:"name"`
	ID          FrameworkID       `json:"id"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Controls    []Control         `json:"controls"`
	Categories  []string          `json:"categories"`
}

// NewFramework creates a new framework with the given ID and name.
func NewFramework(id FrameworkID, name, version, description string) *Framework {
	return &Framework{
		ID:          id,
		Name:        name,
		Version:     version,
		Description: description,
		Controls:    make([]Control, 0),
		Categories:  make([]string, 0),
		Metadata:    make(map[string]string),
	}
}

// AddControl adds a control to the framework.
func (f *Framework) AddControl(ctrl Control) {
	ctrl.Framework = string(f.ID)
	f.Controls = append(f.Controls, ctrl)
}

// GetControl returns a control by ID.
func (f *Framework) GetControl(id string) (Control, bool) {
	for i := range f.Controls {
		if f.Controls[i].ID == id {
			return f.Controls[i], true
		}
	}
	return Control{}, false
}

// GetControlsByCategory returns all controls in a category.
func (f *Framework) GetControlsByCategory(category string) []Control {
	var result []Control
	for i := range f.Controls {
		if f.Controls[i].Category == category {
			result = append(result, f.Controls[i])
		}
	}
	return result
}

// GetControlsByCWE returns controls mapped to a CWE ID.
func (f *Framework) GetControlsByCWE(cweID string) []Control {
	var result []Control
	for i := range f.Controls {
		for _, cwe := range f.Controls[i].CWEMappings {
			if cwe == cweID {
				result = append(result, f.Controls[i])
				break
			}
		}
	}
	return result
}

// NewSOC2Framework returns the SOC 2 Trust Services Criteria framework.
func NewSOC2Framework() *Framework {
	f := NewFramework(
		FrameworkSOC2,
		"SOC 2 Type II",
		"2017",
		"AICPA Trust Services Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy",
	)

	f.Categories = []string{
		"Common Criteria",
		"Availability",
		"Processing Integrity",
		"Confidentiality",
		"Privacy",
	}

	// CC6 - Logical and Physical Access Controls.
	f.AddControl(Control{
		ID:          "CC6.1",
		Title:       "Logical Access Security Software",
		Description: "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.",
		Category:    "Common Criteria",
		Subcategory: "Logical and Physical Access",
		CWEMappings: []string{"CWE-287", "CWE-306", "CWE-798", "CWE-200", "CWE-312", "CWE-532"},
		Required:    true,
	})

	f.AddControl(Control{
		ID:          "CC6.6",
		Title:       "User Registration and Authorization",
		Description: "The entity implements logical access security measures to protect against threats from sources outside its system boundaries.",
		Category:    "Common Criteria",
		Subcategory: "Logical and Physical Access",
		CWEMappings: []string{"CWE-287", "CWE-306", "CWE-862", "CWE-863"},
		Required:    true,
	})

	f.AddControl(Control{
		ID:          "CC6.7",
		Title:       "Data Transmission Protection",
		Description: "The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes.",
		Category:    "Common Criteria",
		Subcategory: "Logical and Physical Access",
		CWEMappings: []string{"CWE-311", "CWE-319", "CWE-326", "CWE-327", "CWE-328"},
		Required:    true,
	})

	// CC7 - System Operations.
	f.AddControl(Control{
		ID:          "CC7.1",
		Title:       "Security Incident Detection",
		Description: "To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities.",
		Category:    "Common Criteria",
		Subcategory: "System Operations",
		CWEMappings: []string{"CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-502"},
		Required:    true,
	})

	f.AddControl(Control{
		ID:          "CC7.2",
		Title:       "Security Event Monitoring",
		Description: "The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors.",
		Category:    "Common Criteria",
		Subcategory: "System Operations",
		CWEMappings: []string{"CWE-778", "CWE-779"},
		Required:    true,
	})

	// CC8 - Change Management.
	f.AddControl(Control{
		ID:          "CC8.1",
		Title:       "Change Management Process",
		Description: "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures.",
		Category:    "Common Criteria",
		Subcategory: "Change Management",
		CWEMappings: []string{"CWE-829", "CWE-494"},
		Required:    true,
	})

	// CC9 - Risk Mitigation.
	f.AddControl(Control{
		ID:          "CC9.1",
		Title:       "Risk Identification and Assessment",
		Description: "The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions.",
		Category:    "Common Criteria",
		Subcategory: "Risk Mitigation",
		Required:    true,
	})

	return f
}

// NewISO27001Framework returns the ISO/IEC 27001:2022 framework.
func NewISO27001Framework() *Framework {
	f := NewFramework(
		FrameworkISO27001,
		"ISO/IEC 27001:2022",
		"2022",
		"Information security, cybersecurity and privacy protection - Information security management systems - Requirements",
	)

	f.Categories = []string{
		"Organizational Controls",
		"People Controls",
		"Physical Controls",
		"Technological Controls",
	}

	// A.5 - Organizational Controls.
	f.AddControl(Control{
		ID:          "A.5.1",
		Title:       "Policies for Information Security",
		Description: "Information security policy and topic-specific policies shall be defined, approved by management, published, communicated to and acknowledged by relevant personnel.",
		Category:    "Organizational Controls",
		Required:    true,
	})

	// A.8 - Asset Management.
	f.AddControl(Control{
		ID:          "A.8.9",
		Title:       "Configuration Management",
		Description: "Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed.",
		Category:    "Technological Controls",
		CWEMappings: []string{"CWE-16", "CWE-1188"},
		Required:    true,
	})

	// A.8.24 - Use of Cryptography.
	f.AddControl(Control{
		ID:          "A.8.24",
		Title:       "Use of Cryptography",
		Description: "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.",
		Category:    "Technological Controls",
		CWEMappings: []string{"CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-338"},
		Required:    true,
	})

	// A.8.25 - Secure Development Life Cycle.
	f.AddControl(Control{
		ID:          "A.8.25",
		Title:       "Secure Development Life Cycle",
		Description: "Rules for the secure development of software and systems shall be established and applied.",
		Category:    "Technological Controls",
		CWEMappings: []string{"CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-502"},
		Required:    true,
	})

	// A.8.26 - Application Security Requirements.
	f.AddControl(Control{
		ID:          "A.8.26",
		Title:       "Application Security Requirements",
		Description: "Information security requirements shall be identified, specified and approved when developing or acquiring applications.",
		Category:    "Technological Controls",
		CWEMappings: []string{"CWE-20", "CWE-77", "CWE-78", "CWE-79", "CWE-89"},
		Required:    true,
	})

	// A.8.28 - Secure Coding.
	f.AddControl(Control{
		ID:          "A.8.28",
		Title:       "Secure Coding",
		Description: "Secure coding principles shall be applied to software development.",
		Category:    "Technological Controls",
		CWEMappings: []string{"CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-119", "CWE-120", "CWE-502"},
		Required:    true,
	})

	// A.5.33 - Protection of Records.
	f.AddControl(Control{
		ID:          "A.5.33",
		Title:       "Protection of Records",
		Description: "Records shall be protected from loss, destruction, falsification, unauthorized access and unauthorized release.",
		Category:    "Organizational Controls",
		CWEMappings: []string{"CWE-200", "CWE-312", "CWE-359", "CWE-538"},
		Required:    true,
	})

	// A.5.34 - Privacy and Protection of PII.
	f.AddControl(Control{
		ID:          "A.5.34",
		Title:       "Privacy and Protection of PII",
		Description: "The organization shall identify and meet the requirements regarding the preservation of privacy and protection of PII.",
		Category:    "Organizational Controls",
		CWEMappings: []string{"CWE-359", "CWE-200", "CWE-312"},
		Required:    true,
	})

	// A.8.5 - Secure Authentication.
	f.AddControl(Control{
		ID:          "A.8.5",
		Title:       "Secure Authentication",
		Description: "Secure authentication technologies and procedures shall be implemented.",
		Category:    "Technological Controls",
		CWEMappings: []string{"CWE-287", "CWE-306", "CWE-798", "CWE-521"},
		Required:    true,
	})

	return f
}

// NewGDPRFramework returns the GDPR compliance framework.
func NewGDPRFramework() *Framework {
	f := NewFramework(
		FrameworkGDPR,
		"General Data Protection Regulation",
		"2016/679",
		"Regulation on the protection of natural persons with regard to the processing of personal data and on the free movement of such data",
	)

	f.Categories = []string{
		"Principles",
		"Rights of Data Subjects",
		"Controller and Processor",
		"Security",
		"Data Breach",
	}

	// Article 5 - Principles.
	f.AddControl(Control{
		ID:          "Art.5",
		Title:       "Principles Relating to Processing of Personal Data",
		Description: "Personal data shall be processed lawfully, fairly and in a transparent manner; collected for specified, explicit and legitimate purposes; adequate, relevant and limited to what is necessary.",
		Category:    "Principles",
		CWEMappings: []string{"CWE-359", "CWE-200", "CWE-312", "CWE-538"},
		Required:    true,
	})

	// Article 25 - Data Protection by Design.
	f.AddControl(Control{
		ID:          "Art.25",
		Title:       "Data Protection by Design and by Default",
		Description: "The controller shall implement appropriate technical and organizational measures for ensuring that, by default, only personal data which are necessary for each specific purpose are processed.",
		Category:    "Controller and Processor",
		CWEMappings: []string{"CWE-359", "CWE-200", "CWE-312"},
		Required:    true,
	})

	// Article 32 - Security of Processing.
	f.AddControl(Control{
		ID:          "Art.32",
		Title:       "Security of Processing",
		Description: "The controller and the processor shall implement appropriate technical and organizational measures to ensure a level of security appropriate to the risk.",
		Category:    "Security",
		CWEMappings: []string{
			"CWE-78", "CWE-79", "CWE-89", "CWE-94",
			"CWE-287", "CWE-306", "CWE-798",
			"CWE-326", "CWE-327", "CWE-328",
			"CWE-200", "CWE-312", "CWE-532",
		},
		Required: true,
	})

	// Article 33 - Notification of Data Breach.
	f.AddControl(Control{
		ID:          "Art.33",
		Title:       "Notification of a Personal Data Breach to the Supervisory Authority",
		Description: "In the case of a personal data breach, the controller shall without undue delay notify the personal data breach to the supervisory authority.",
		Category:    "Data Breach",
		CWEMappings: []string{"CWE-200", "CWE-312", "CWE-532"},
		Required:    true,
	})

	// Article 34 - Communication of Data Breach.
	f.AddControl(Control{
		ID:          "Art.34",
		Title:       "Communication of a Personal Data Breach to the Data Subject",
		Description: "When the personal data breach is likely to result in a high risk to the rights and freedoms of natural persons, the controller shall communicate the personal data breach to the data subject.",
		Category:    "Data Breach",
		CWEMappings: []string{"CWE-200", "CWE-312"},
		Required:    true,
	})

	return f
}

// AllFrameworks returns all supported compliance frameworks.
func AllFrameworks() []*Framework {
	return []*Framework{
		NewSOC2Framework(),
		NewISO27001Framework(),
		NewGDPRFramework(),
	}
}

// GetFramework returns a framework by ID.
func GetFramework(id FrameworkID) (*Framework, bool) {
	switch id {
	case FrameworkSOC2:
		return NewSOC2Framework(), true
	case FrameworkISO27001:
		return NewISO27001Framework(), true
	case FrameworkGDPR:
		return NewGDPRFramework(), true
	default:
		return nil, false
	}
}

// SupportedFrameworks returns a list of supported framework IDs.
func SupportedFrameworks() []FrameworkID {
	return []FrameworkID{
		FrameworkSOC2,
		FrameworkISO27001,
		FrameworkGDPR,
	}
}
