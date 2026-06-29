use ares_core::{Finding, Severity};
use crate::state::WebhookConfig;
use std::time::Duration;

/// Dispatch webhook notifications for new findings
pub async fn dispatch_webhooks(
    webhooks: &[WebhookConfig],
    finding: &Finding,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|e| {
            tracing::warn!("Failed to build hardened webhook client ({}), falling back to default", e);
            reqwest::Client::new()
        });

    for hook in webhooks {
        // Check severity filter
        let min_sev = Severity::from_label(&hook.min_severity);
        if let Some(min) = min_sev {
            if finding.severity.numeric() < min.numeric() {
                continue;
            }
        }

        // Check event type filter
        if !hook.event_types.iter().any(|t| t == "finding" || t == "*") {
            continue;
        }

        let payload = serde_json::json!({
            "event": "finding",
            "finding_id": finding.id,
            "program_id": finding.program_id,
            "severity": finding.severity.label(),
            "class": finding.class.code(),
            "title": finding.title,
            "description": finding.description,
        });

        match client.post(&hook.url).json(&payload).send().await {
            Ok(resp) => {
                tracing::info!(
                    "Webhook {} dispatched: status {}",
                    hook.id,
                    resp.status()
                );
            }
            Err(e) => {
                tracing::warn!("Webhook {} failed: {}", hook.id, e);
            }
        }
    }
}
