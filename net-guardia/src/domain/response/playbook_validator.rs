use std::str::FromStr;

use crate::domain::common::event::DetectionSource;
use crate::domain::response::condition::{ConditionType, is_valid_ip_pattern, is_valid_operator};
use crate::domain::response::error::SoarError;
use crate::domain::response::playbook::ActionType;
use crate::interface::response::playbook_data::CreateConditionInput;

const RATE_LIMIT_FACTOR_MIN: f64 = 0.01;
const RATE_LIMIT_FACTOR_MAX: f64 = 1.0;

pub fn validate_optional_positive_i64(field: &str, value: Option<i64>) -> Result<(), SoarError> {
    if value.is_some_and(|value| value <= 0) {
        return Err(SoarError::ValidationFailed(format!("{field} must be greater than 0")));
    }
    Ok(())
}

pub fn validate_cooldown_secs(cooldown_secs: i64) -> Result<(), SoarError> {
    if cooldown_secs < 0 {
        return Err(SoarError::ValidationFailed(
            "cooldown_secs must be greater than or equal to 0".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_condition_input(condition: &CreateConditionInput) -> Result<(), SoarError> {
    let condition_type = condition
        .condition_type
        .parse::<ConditionType>()
        .map_err(|_| SoarError::ValidationFailed(format!("unknown condition_type: {}", condition.condition_type)))?;
    if !is_valid_operator(&condition_type, &condition.operator) {
        return Err(SoarError::ValidationFailed(format!(
            "invalid operator '{}' for condition_type '{}'",
            condition.operator, condition.condition_type
        )));
    }
    validate_condition_value(&condition_type, condition)
}

fn validate_condition_value(condition_type: &ConditionType, condition: &CreateConditionInput) -> Result<(), SoarError> {
    match condition_type {
        ConditionType::Threshold | ConditionType::FusedConfidenceAbove => {
            parse_finite_f64(&condition.value, &condition.condition_type)?;
        }
        ConditionType::Frequency | ConditionType::MultiSourceMin => {
            parse_positive_usize(&condition.value, &condition.condition_type)?;
            if let Some(value2) = &condition.value2 {
                parse_positive_u64(value2, "value2")?;
            }
        }
        ConditionType::SourceCountry => {
            if condition.value.split(',').all(|part| part.trim().is_empty()) {
                return Err(SoarError::ValidationFailed(
                    "source_country value must contain at least one country code".to_string(),
                ));
            }
        }
        ConditionType::IpPattern => {
            if !is_valid_ip_pattern(&condition.value) {
                return Err(SoarError::ValidationFailed(format!(
                    "ip_pattern value must be a valid CIDR: {}",
                    condition.value
                )));
            }
        }
        ConditionType::RepeatOffender => {
            parse_bool_literal(&condition.value, &condition.condition_type)?;
        }
        ConditionType::SingleSourceHigh => {
            DetectionSource::from_str(&condition.value).map_err(|_| {
                SoarError::ValidationFailed(format!(
                    "single_source_high value must be a valid DetectionSource: {}",
                    condition.value
                ))
            })?;
            if let Some(value2) = &condition.value2 {
                parse_finite_f64(value2, "value2")?;
            }
        }
    }
    Ok(())
}

pub fn validate_action(
    action_type: &str,
    params: Option<&serde_json::Value>,
    max_ttl_secs: u64,
) -> Result<(), SoarError> {
    if let Some(params) = params
        && !params.is_object()
    {
        return Err(SoarError::ValidationFailed(format!(
            "action '{}' params must be a JSON object",
            action_type
        )));
    }

    match action_type.parse::<ActionType>() {
        Ok(ActionType::BlockIp) => {
            let ttl_secs = params.and_then(|p| p.get("ttl_secs"));
            validate_optional_positive_u64("ttl_secs", ttl_secs)?;
            validate_optional_max_u64("ttl_secs", ttl_secs, max_ttl_secs)
        }
        Ok(ActionType::AdjustRateLimit) => {
            let ttl_secs = params.and_then(|p| p.get("ttl_secs"));
            validate_optional_positive_u64("ttl_secs", ttl_secs)?;
            validate_optional_max_u64("ttl_secs", ttl_secs, max_ttl_secs)?;
            validate_optional_rate_limit_factor(params.and_then(|p| p.get("factor")))
        }
        Ok(ActionType::SendTelegram | ActionType::SendEmail) => Ok(()),
        Ok(ActionType::Webhook) => {
            validate_required_non_empty_string("url", params.and_then(|p| p.get("url")))?;
            validate_optional_positive_u64("timeout_secs", params.and_then(|p| p.get("timeout_secs")))
        }
        Ok(ActionType::Log) => validate_optional_string("level", params.and_then(|p| p.get("level"))),
        Err(_) => Err(SoarError::ValidationFailed(format!(
            "unknown action_type: {}",
            action_type
        ))),
    }
}

fn parse_finite_f64(value: &str, field: &str) -> Result<f64, SoarError> {
    match value.parse::<f64>() {
        Ok(parsed) if parsed.is_finite() => Ok(parsed),
        _ => Err(SoarError::ValidationFailed(format!(
            "{field} value must be a finite number"
        ))),
    }
}

fn parse_positive_usize(value: &str, field: &str) -> Result<usize, SoarError> {
    match value.parse::<usize>() {
        Ok(parsed) if parsed > 0 => Ok(parsed),
        _ => Err(SoarError::ValidationFailed(format!(
            "{field} value must be a positive integer"
        ))),
    }
}

fn parse_positive_u64(value: &str, field: &str) -> Result<u64, SoarError> {
    match value.parse::<u64>() {
        Ok(parsed) if parsed > 0 => Ok(parsed),
        _ => Err(SoarError::ValidationFailed(format!(
            "{field} must be a positive integer"
        ))),
    }
}

fn parse_bool_literal(value: &str, field: &str) -> Result<bool, SoarError> {
    match value.to_ascii_lowercase().as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(SoarError::ValidationFailed(format!(
            "{field} value must be 'true' or 'false'"
        ))),
    }
}

fn validate_optional_positive_u64(field: &str, value: Option<&serde_json::Value>) -> Result<(), SoarError> {
    let Some(value) = value else {
        return Ok(());
    };
    match value.as_u64() {
        Some(value) if value > 0 => Ok(()),
        Some(_) => Err(SoarError::ValidationFailed(format!("{field} must be greater than 0"))),
        None => Err(SoarError::ValidationFailed(format!(
            "{field} must be a positive integer"
        ))),
    }
}

fn validate_optional_max_u64(field: &str, value: Option<&serde_json::Value>, max: u64) -> Result<(), SoarError> {
    let Some(value) = value.and_then(|value| value.as_u64()) else {
        return Ok(());
    };
    if value > max {
        return Err(SoarError::ValidationFailed(format!(
            "{field} must be less than or equal to {max}"
        )));
    }
    Ok(())
}

fn validate_optional_rate_limit_factor(value: Option<&serde_json::Value>) -> Result<(), SoarError> {
    let Some(value) = value else {
        return Ok(());
    };
    match value.as_f64() {
        Some(value) if (RATE_LIMIT_FACTOR_MIN..=RATE_LIMIT_FACTOR_MAX).contains(&value) => Ok(()),
        Some(_) => Err(SoarError::ValidationFailed(format!(
            "factor must be between {RATE_LIMIT_FACTOR_MIN} and {RATE_LIMIT_FACTOR_MAX}"
        ))),
        None => Err(SoarError::ValidationFailed("factor must be a number".to_string())),
    }
}

fn validate_required_non_empty_string(field: &str, value: Option<&serde_json::Value>) -> Result<(), SoarError> {
    match value.and_then(|value| value.as_str()) {
        Some(value) if !value.trim().is_empty() => Ok(()),
        Some(_) => Err(SoarError::ValidationFailed(format!("{field} must not be empty"))),
        None => Err(SoarError::ValidationFailed(format!("{field} is required"))),
    }
}

fn validate_optional_string(field: &str, value: Option<&serde_json::Value>) -> Result<(), SoarError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.is_string() {
        Ok(())
    } else {
        Err(SoarError::ValidationFailed(format!("{field} must be a string")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_negative_cooldown() {
        let err = validate_cooldown_secs(-1).unwrap_err();
        assert_eq!(err.to_string(), "cooldown_secs must be greater than or equal to 0");
    }

    #[test]
    fn accepts_zero_cooldown() {
        validate_cooldown_secs(0).unwrap();
    }

    #[test]
    fn rejects_non_positive_condition_count() {
        let err = validate_optional_positive_i64("condition_count", Some(0)).unwrap_err();
        assert_eq!(err.to_string(), "condition_count must be greater than 0");
    }

    #[test]
    fn accepts_none_condition_count() {
        validate_optional_positive_i64("condition_count", None).unwrap();
    }

    #[test]
    fn rejects_unknown_action_type() {
        let err = validate_action("typo", None, 3_600).unwrap_err();
        assert_eq!(err.to_string(), "unknown action_type: typo");
    }

    #[test]
    fn rejects_block_ip_zero_ttl() {
        let params = serde_json::json!({"ttl_secs": 0});
        let err = validate_action("block_ip", Some(&params), 3_600).unwrap_err();
        assert_eq!(err.to_string(), "ttl_secs must be greater than 0");
    }

    #[test]
    fn rejects_block_ip_exceeding_max_ttl() {
        let params = serde_json::json!({"ttl_secs": 3_601});
        let err = validate_action("block_ip", Some(&params), 3_600).unwrap_err();
        assert_eq!(err.to_string(), "ttl_secs must be less than or equal to 3600");
    }

    #[test]
    fn rejects_webhook_missing_url() {
        let params = serde_json::json!({"timeout_secs": 5});
        let err = validate_action("webhook", Some(&params), 3_600).unwrap_err();
        assert_eq!(err.to_string(), "url is required");
    }

    #[test]
    fn rejects_webhook_zero_timeout() {
        let params = serde_json::json!({"url": "https://example.test/hook", "timeout_secs": 0});
        let err = validate_action("webhook", Some(&params), 3_600).unwrap_err();
        assert_eq!(err.to_string(), "timeout_secs must be greater than 0");
    }

    #[test]
    fn rejects_unknown_condition_type() {
        let input = CreateConditionInput {
            condition_type: "typo".to_string(),
            operator: ">=".to_string(),
            value: "0.9".to_string(),
            value2: None,
        };
        let err = validate_condition_input(&input).unwrap_err();
        assert!(err.to_string().contains("typo"));
    }

    #[test]
    fn rejects_invalid_condition_operator() {
        let input = CreateConditionInput {
            condition_type: "threshold".to_string(),
            operator: "in".to_string(),
            value: "0.9".to_string(),
            value2: None,
        };
        let err = validate_condition_input(&input).unwrap_err();
        assert!(err.to_string().contains("in"));
        assert!(err.to_string().contains("threshold"));
    }

    #[test]
    fn rejects_invalid_threshold_value() {
        let input = CreateConditionInput {
            condition_type: "threshold".to_string(),
            operator: ">=".to_string(),
            value: "not-a-number".to_string(),
            value2: None,
        };
        let err = validate_condition_input(&input).unwrap_err();
        assert_eq!(err.to_string(), "threshold value must be a finite number");
    }

    #[test]
    fn rejects_invalid_frequency_value() {
        let input = CreateConditionInput {
            condition_type: "frequency".to_string(),
            operator: ">=".to_string(),
            value: "0".to_string(),
            value2: None,
        };
        let err = validate_condition_input(&input).unwrap_err();
        assert_eq!(err.to_string(), "frequency value must be a positive integer");
    }

    #[test]
    fn rejects_invalid_ip_pattern() {
        let input = CreateConditionInput {
            condition_type: "ip_pattern".to_string(),
            operator: "in".to_string(),
            value: "not-cidr".to_string(),
            value2: None,
        };
        let err = validate_condition_input(&input).unwrap_err();
        assert_eq!(err.to_string(), "ip_pattern value must be a valid CIDR: not-cidr");
    }

    #[test]
    fn rejects_invalid_repeat_offender_value() {
        let input = CreateConditionInput {
            condition_type: "repeat_offender".to_string(),
            operator: "==".to_string(),
            value: "maybe".to_string(),
            value2: None,
        };
        let err = validate_condition_input(&input).unwrap_err();
        assert_eq!(err.to_string(), "repeat_offender value must be 'true' or 'false'");
    }

    #[test]
    fn accepts_false_repeat_offender() {
        let input = CreateConditionInput {
            condition_type: "repeat_offender".to_string(),
            operator: "==".to_string(),
            value: "false".to_string(),
            value2: None,
        };
        validate_condition_input(&input).unwrap();
    }

    #[test]
    fn rejects_invalid_single_source_high_value() {
        let input = CreateConditionInput {
            condition_type: "single_source_high".to_string(),
            operator: ">=".to_string(),
            value: "UnknownSource".to_string(),
            value2: None,
        };
        let err = validate_condition_input(&input).unwrap_err();
        assert_eq!(
            err.to_string(),
            "single_source_high value must be a valid DetectionSource: UnknownSource"
        );
    }
}
