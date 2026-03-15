use atlas_drift::{Criticality, DriftFinding, DriftReport, TimelineReport};

pub trait ReportPlugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn process_finding(&self, finding: &mut DriftFinding);
}

pub struct PluginRegistry {
    plugins: Vec<Box<dyn ReportPlugin>>,
}

impl PluginRegistry {
    pub fn new(plugins: Vec<Box<dyn ReportPlugin>>) -> Self {
        Self { plugins }
    }

    pub fn apply_drift_report(&self, report: &mut DriftReport) {
        for finding in &mut report.findings {
            self.apply_finding(finding);
        }

        for finding in &mut report.suppressed_findings {
            self.apply_finding(finding);
        }

        for group in &mut report.groups {
            for finding in &mut group.findings {
                self.apply_finding(finding);
            }
        }
    }

    pub fn apply_timeline_report(&self, report: &mut TimelineReport) {
        for transition in &mut report.transitions {
            self.apply_drift_report(&mut transition.report);
        }
    }

    fn apply_finding(&self, finding: &mut DriftFinding) {
        for plugin in &self.plugins {
            plugin.process_finding(finding);
        }
    }
}

pub fn default_registry_for(enabled: &[String]) -> PluginRegistry {
    let mut plugins: Vec<Box<dyn ReportPlugin>> = Vec::new();

    if enabled.iter().any(|p| p == "criticality-tag") {
        plugins.push(Box::new(CriticalityTagPlugin));
    }

    if enabled.iter().any(|p| p == "state-tag") {
        plugins.push(Box::new(StateTagPlugin));
    }

    if enabled.iter().any(|p| p == "normalize-tags") {
        plugins.push(Box::new(NormalizeTagsPlugin));
    }

    PluginRegistry::new(plugins)
}

struct CriticalityTagPlugin;

impl ReportPlugin for CriticalityTagPlugin {
    fn name(&self) -> &'static str {
        "criticality-tag"
    }

    fn process_finding(&self, finding: &mut DriftFinding) {
        if matches!(finding.criticality, Criticality::Critical)
            && !finding.tags.iter().any(|t| t == "critical-resource")
        {
            finding.tags.push("critical-resource".to_string());
        }
    }
}

struct StateTagPlugin;

impl ReportPlugin for StateTagPlugin {
    fn name(&self) -> &'static str {
        "state-tag"
    }

    fn process_finding(&self, finding: &mut DriftFinding) {
        let state_tag = format!("state:{}", finding.state.to_string().to_lowercase());

        if !finding.tags.iter().any(|t| t == &state_tag) {
            finding.tags.push(state_tag);
        }
    }
}

struct NormalizeTagsPlugin;

impl ReportPlugin for NormalizeTagsPlugin {
    fn name(&self) -> &'static str {
        "normalize-tags"
    }

    fn process_finding(&self, finding: &mut DriftFinding) {
        finding.tags.sort();
        finding.tags.dedup();
    }
}
