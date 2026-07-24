use crate::report::Severity;

pub fn severity_from_cvss(score: f32) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else if score >= 0.1 {
        Severity::Low
    } else {
        Severity::Informational
    }
}

pub fn aggregate_cvss(findings: &[f32]) -> f32 {
    if findings.is_empty() {
        return 0.0;
    }

    let mut max_score = 0.0;
    let mut high_critical_count = 0;

    for &score in findings {
        if score > max_score {
            max_score = score;
        }
        if score >= 7.0 {
            high_critical_count += 1;
        }
    }

    // Max-of-critical escalation: add 0.15 for each high/critical vulnerability beyond the first
    let adjustment = if high_critical_count > 1 {
        (high_critical_count - 1) as f32 * 0.15
    } else {
        0.0
    };

    let combined = max_score + adjustment;
    if combined > 10.0 {
        10.0
    } else {
        combined
    }
}
