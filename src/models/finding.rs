use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub category: Category,
    pub description: String,
    pub evidence: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Category {
    CommandInjection,
    PathTraversal,
    Authentication,
    NetworkExposure,
    InformationDisclosure,
    CredentialExposure,
    SSRF,
    ToolPoisoning,
}