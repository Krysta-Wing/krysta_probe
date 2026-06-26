use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub category: Category,
    pub description: String,
    pub evidence: String,
    pub remediation: String,
    
    #[serde(default)]
    pub source: FindingSource,
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FindingSource {
    
    Static,
    
    Dynamic,
    
    SourceCode,
    
    Package,
}

impl Default for FindingSource {
    fn default() -> Self {
        FindingSource::Static
    }
}

impl fmt::Display for FindingSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindingSource::Static => write!(f, "Static"),
            FindingSource::Dynamic => write!(f, "Dynamic"),
            FindingSource::SourceCode => write!(f, "Source Code"),
            FindingSource::Package => write!(f, "Package"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "Critical"),
            Severity::High => write!(f, "High"),
            Severity::Medium => write!(f, "Medium"),
            Severity::Low => write!(f, "Low"),
        }
    }
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
    SourceCode,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Category::CommandInjection => write!(f, "Command Injection"),
            Category::PathTraversal => write!(f, "Path Traversal"),
            Category::Authentication => write!(f, "Authentication"),
            Category::NetworkExposure => write!(f, "Network Exposure"),
            Category::InformationDisclosure => write!(f, "Information Disclosure"),
            Category::CredentialExposure => write!(f, "Credential Exposure"),
            Category::SSRF => write!(f, "SSRF"),
            Category::ToolPoisoning => write!(f, "Tool Poisoning"),
            Category::SourceCode => write!(f, "Source Code"),
        }
    }
}