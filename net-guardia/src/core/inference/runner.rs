use std::cmp::Ordering as CmpOrdering;
use std::collections::{BTreeMap, HashMap};
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use macros::log;

use crate::core::inference::model_adapter::{MLModelAdapter, ModelSourceState, PipelineStageAdapter};
use crate::domain::common::config::AppConfig;
use crate::domain::common::event::DetectionSource;
use crate::domain::detection::attack_type::{CanonicalAttackType, translate};
use crate::domain::detection::error::MLError;
use crate::domain::detection::flow_tracker::FlowSnapshot;
use crate::domain::detection::log::MLLog;
use crate::domain::detection::manifest::{
    AttackMappingSpec, DetectionRuleSpec, LabelSpec, OutputRole, PipelineOutputSpec, PreprocessingStep,
    StageInputSource, output_matches_ref, stage_output_key,
};
use crate::domain::detection::ml_detection::DetectionResult;
use crate::domain::detection::ml_inference_config::MLInferenceConfig;
use crate::domain::detection::model_source::ModelSourceStatus;
use crate::interface::detection::model_runtime::RuntimeTensor;

pub struct Inference {
    state: ArcSwap<ModelSourceState>,
    pub config: Arc<MLInferenceConfig>,
    app_config: Arc<ArcSwap<AppConfig>>,
    qps_recent: AtomicU32,
    cb_phase: AtomicU8,
    cb_failure_count: AtomicU32,
    cb_window_start_secs: AtomicU64,
    cb_open_since_secs: AtomicU64,
}

const CB_CLOSED: u8 = 0;
const CB_OPEN: u8 = 1;
const CB_HALF_OPEN: u8 = 2;

impl Inference {
    pub fn new(
        initial_state: ModelSourceState,
        config: Arc<MLInferenceConfig>,
        app_config: Arc<ArcSwap<AppConfig>>,
    ) -> Self {
        Self {
            state: ArcSwap::from_pointee(initial_state),
            config,
            app_config,
            qps_recent: AtomicU32::new(0),
            cb_phase: AtomicU8::new(CB_CLOSED),
            cb_failure_count: AtomicU32::new(0),
            cb_window_start_secs: AtomicU64::new(0),
            cb_open_since_secs: AtomicU64::new(0),
        }
    }

    pub fn swap_state(&self, new_state: ModelSourceState) {
        let new_is_active = new_state.is_active();
        self.state.store(Arc::new(new_state));
        if new_is_active {
            self.record_success();
        }
    }

    pub fn model_source_state(&self) -> ModelSourceState {
        self.state.load().as_ref().clone()
    }

    pub fn model_source_status(&self) -> ModelSourceStatus {
        let guard = self.state.load();
        let mut status = guard.to_status();
        if let ModelSourceStatus::Active { ref mut info } = status {
            info.qps_recent = self.qps_recent.load(Ordering::Relaxed) as f32;
        }
        status
    }

    pub fn is_active(&self) -> bool {
        self.state.load().is_active()
    }

    pub fn confirmations_for_attack_type(&self, attack_type: CanonicalAttackType) -> Option<usize> {
        match self.state.load().as_ref() {
            ModelSourceState::Active { adapter, .. } => adapter.confirmations_for(attack_type),
            ModelSourceState::Dormant | ModelSourceState::Error { .. } => None,
        }
    }

    pub fn attack_type_count(&self) -> usize {
        match self.state.load().as_ref() {
            ModelSourceState::Active { adapter, .. } => match adapter {
                MLModelAdapter::Pipeline { labels, .. } => labels.len(),
            },
            ModelSourceState::Dormant | ModelSourceState::Error { .. } => 0,
        }
    }

    pub fn infer_batch(&self, flows: &[FlowSnapshot]) -> Vec<DetectionResult> {
        if self.is_circuit_open() {
            return Vec::new();
        }

        let guard = self.state.load();
        let adapter = match guard.as_ref() {
            ModelSourceState::Active { adapter, .. } => adapter,
            ModelSourceState::Dormant | ModelSourceState::Error { .. } => {
                return Vec::new();
            }
        };

        match panic::catch_unwind(AssertUnwindSafe(|| self.infer_batch_inner(adapter, flows))) {
            Ok(results) => {
                self.record_success();
                results
            }
            Err(_) => {
                log!(MLLog::InferenceFailed(
                    "ONNX".to_string(),
                    "batch inference panicked (caught)".to_string(),
                ));
                self.record_failure();
                Vec::new()
            }
        }
    }

    fn infer_batch_inner(&self, adapter: &MLModelAdapter, flows: &[FlowSnapshot]) -> Vec<DetectionResult> {
        match adapter {
            MLModelAdapter::Pipeline {
                stages,
                outputs,
                detection_rules,
                labels,
                normal_label,
            } => self.infer_pipeline(stages, outputs, detection_rules, labels, normal_label, flows),
        }
    }

    fn infer_pipeline(
        &self,
        stages: &[PipelineStageAdapter],
        outputs: &[PipelineOutputSpec],
        detection_rules: &[DetectionRuleSpec],
        labels: &BTreeMap<String, LabelSpec>,
        normal_label: &str,
        flows: &[FlowSnapshot],
    ) -> Vec<DetectionResult> {
        let n = flows.len();
        let mut scalar_outputs: HashMap<String, Vec<f32>> = HashMap::new();
        let mut matrix_outputs: HashMap<String, Vec<Vec<f32>>> = HashMap::new();
        let mut thresholds: HashMap<String, f32> = HashMap::new();
        let mut min_confidences: HashMap<String, f32> = HashMap::new();

        for stage in stages {
            let rows = match self.pipeline_stage_rows(stage, flows, &scalar_outputs) {
                Ok(rows) => rows,
                Err(err) => {
                    log!(MLLog::InferenceFailed(stage.id.clone(), err.to_string()));
                    self.record_failure();
                    return Vec::new();
                }
            };

            let mut chunk_start = 0usize;
            let mut stage_scalars: HashMap<String, Vec<f32>> = HashMap::new();
            let mut stage_matrices: HashMap<String, Vec<Vec<f32>>> = HashMap::new();
            while chunk_start < n {
                let chunk_end = (chunk_start + stage.batch_size).min(n);
                let chunk = &rows[chunk_start..chunk_end];
                let tensors = match stage.model.run_stage_batch(
                    chunk,
                    stage.batch_size,
                    stage.n_features,
                    stage.kind.clone(),
                    &stage.output_heads,
                ) {
                    Ok(tensors) => tensors,
                    Err(err) => {
                        log!(MLLog::InferenceFailed(stage.id.clone(), err.to_string()));
                        self.record_failure();
                        return Vec::new();
                    }
                };
                append_stage_tensors(&mut stage_scalars, &mut stage_matrices, tensors);
                chunk_start = chunk_end;
            }
            for head in &stage.output_heads {
                let key = stage_output_key(&stage.id, &head.name);
                if let Some(threshold) = head.threshold {
                    thresholds.insert(key.clone(), threshold);
                }
                if let Some(min_confidence) = head.min_confidence {
                    min_confidences.insert(key.clone(), min_confidence);
                }
                if let Some(values) = stage_scalars.remove(&head.name) {
                    scalar_outputs.insert(key, values);
                } else if let Some(rows) = stage_matrices.remove(&head.name) {
                    matrix_outputs.insert(key, rows);
                }
            }
        }

        self.pipeline_detection_results(
            flows,
            outputs,
            detection_rules,
            labels,
            normal_label,
            PipelineOutputs {
                scalars: &scalar_outputs,
                matrices: &matrix_outputs,
                thresholds: &thresholds,
                min_confidences: &min_confidences,
            },
        )
    }

    fn pipeline_stage_rows(
        &self,
        stage: &PipelineStageAdapter,
        flows: &[FlowSnapshot],
        scalar_outputs: &HashMap<String, Vec<f32>>,
    ) -> Result<Vec<Vec<f32>>, MLError> {
        let mut rows = Vec::with_capacity(flows.len());
        for (row_idx, flow) in flows.iter().enumerate() {
            let mut row = Vec::with_capacity(stage.inputs.len());
            for input in &stage.inputs {
                match input.source {
                    StageInputSource::Feature => {
                        row.push(self.preprocess_pipeline_feature(flow, &input.name, &stage.preprocessing)? as f32);
                    }
                    StageInputSource::StageOutput => {
                        let Some(source_stage) = input.stage.as_ref() else {
                            return Err(MLError::ConfigInvalid("pipeline input missing source stage"));
                        };
                        let Some(source_output) = input.output.as_ref() else {
                            return Err(MLError::ConfigInvalid("pipeline input missing source output"));
                        };
                        let key = stage_output_key(source_stage, source_output);
                        let Some(values) = scalar_outputs.get(&key) else {
                            return Err(MLError::ConfigInvalid(format!(
                                "pipeline input references missing scalar output {key}"
                            )));
                        };
                        let Some(value) = values.get(row_idx).copied() else {
                            return Err(MLError::ConfigInvalid(format!(
                                "pipeline output {key} has no value for row {row_idx}"
                            )));
                        };
                        row.push(value);
                    }
                }
            }
            rows.push(row);
        }
        Ok(rows)
    }

    fn preprocess_pipeline_feature(
        &self,
        flow: &FlowSnapshot,
        feature_name: &str,
        steps: &[PreprocessingStep],
    ) -> Result<f64, MLError> {
        let mut value = flow.feature_stats.get(feature_name);
        for step in steps {
            value = self.apply_preprocessing_step(feature_name, value, step)?;
        }
        Ok(value)
    }

    fn apply_preprocessing_step(
        &self,
        feature_name: &str,
        value: f64,
        step: &PreprocessingStep,
    ) -> Result<f64, MLError> {
        match step {
            PreprocessingStep::StandardScaler { .. } => {
                let Some(idx) = self
                    .config
                    .ae_feature_names
                    .iter()
                    .position(|name| name == feature_name)
                else {
                    return Err(MLError::ConfigInvalid(format!(
                        "standard_scaler missing feature '{feature_name}' in sidecar"
                    )));
                };
                let Some(mean) = self.config.ae_scaler_mean.get(idx) else {
                    return Err(MLError::ConfigInvalid(format!(
                        "standard_scaler missing mean for feature '{feature_name}'"
                    )));
                };
                let Some(std) = self.config.ae_scaler_std.get(idx) else {
                    return Err(MLError::ConfigInvalid(format!(
                        "standard_scaler missing std for feature '{feature_name}'"
                    )));
                };
                if *std > 0.0 { Ok((value - mean) / std) } else { Ok(0.0) }
            }
            PreprocessingStep::MinMaxScaler { .. } => {
                let Some(params) = self.config.minmax_params.get(feature_name) else {
                    return Err(MLError::ConfigInvalid(format!(
                        "minmax_scaler missing params for feature '{feature_name}'"
                    )));
                };
                let range = params.max - params.min;
                if range > 0.0 {
                    Ok((value - params.min) / range)
                } else {
                    Ok(0.0)
                }
            }
            PreprocessingStep::RobustScaler { .. } => {
                let Some(params) = self.config.robust_params.get(feature_name) else {
                    return Err(MLError::ConfigInvalid(format!(
                        "robust_scaler missing params for feature '{feature_name}'"
                    )));
                };
                if params.scale > 0.0 {
                    Ok((value - params.center) / params.scale)
                } else {
                    Ok(0.0)
                }
            }
            PreprocessingStep::LogTransform { offset } => {
                let shifted = value + f64::from(*offset);
                if shifted <= 0.0 {
                    return Err(MLError::ConfigInvalid(format!(
                        "log_transform input for feature '{feature_name}' must be > 0 after offset"
                    )));
                }
                Ok(shifted.ln())
            }
            PreprocessingStep::Clip { min, max } => Ok(value.clamp(f64::from(*min), f64::from(*max))),
            PreprocessingStep::Quantile { .. } => {
                let Some(params) = self.config.quantile_params.get(feature_name) else {
                    return Err(MLError::ConfigInvalid(format!(
                        "quantile preprocessing missing params for feature '{feature_name}'"
                    )));
                };
                quantile_transform(value, &params.values, &params.quantiles, feature_name)
            }
        }
    }

    fn pipeline_detection_results(
        &self,
        flows: &[FlowSnapshot],
        outputs: &[PipelineOutputSpec],
        detection_rules: &[DetectionRuleSpec],
        labels: &BTreeMap<String, LabelSpec>,
        normal_label: &str,
        pipeline_outputs: PipelineOutputs<'_>,
    ) -> Vec<DetectionResult> {
        let mut results = Vec::with_capacity(flows.len());
        for (idx, flow) in flows.iter().enumerate() {
            let scores = detection_scores_from_roles(outputs, pipeline_outputs, idx);
            let candidate = best_rule_candidate(detection_rules, outputs, labels, normal_label, pipeline_outputs, idx);

            results.push(detection_result(
                flow,
                candidate.is_some(),
                candidate.as_ref().map(|c| c.attack_type),
                DetectionScores {
                    confidence: candidate.as_ref().map(|c| c.confidence).unwrap_or(scores.confidence),
                    alert_threshold: candidate.as_ref().map(|c| c.alert_threshold).unwrap_or(1.0),
                    ae: scores.ae,
                    anomaly: scores.anomaly,
                    c2: scores.c2,
                },
            ));
        }
        results
    }

    pub fn record_tick_qps(&self, flows_per_second: f32) {
        self.qps_recent
            .store(flows_per_second.max(0.0) as u32, Ordering::Relaxed);
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn is_circuit_open(&self) -> bool {
        let phase = self.cb_phase.load(Ordering::Acquire);
        match phase {
            CB_OPEN => {
                let cooldown = self.app_config.load().ml.circuit_breaker.cooldown_secs;
                let since_secs = self.cb_open_since_secs.load(Ordering::Acquire);
                let elapsed = Self::now_secs().saturating_sub(since_secs);
                if elapsed >= cooldown {
                    if self
                        .cb_phase
                        .compare_exchange(CB_OPEN, CB_HALF_OPEN, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        log!(MLLog::CircuitBreakerReset(cooldown));
                    }
                    return false;
                }
                true
            }
            CB_HALF_OPEN => true,
            _ => false,
        }
    }

    fn record_success(&self) {
        self.cb_phase.store(CB_CLOSED, Ordering::Release);
        self.cb_failure_count.store(0, Ordering::Release);
        self.cb_window_start_secs.store(0, Ordering::Release);
    }

    fn record_failure(&self) {
        let now = Self::now_secs();
        let cfg = self.app_config.load();
        let window_secs = cfg.ml.circuit_breaker.window_secs;
        let threshold = cfg.ml.circuit_breaker.threshold;

        let phase = self.cb_phase.load(Ordering::Acquire);
        match phase {
            CB_OPEN => return,
            CB_HALF_OPEN => {
                if self
                    .cb_phase
                    .compare_exchange(CB_HALF_OPEN, CB_OPEN, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    self.cb_open_since_secs.store(now, Ordering::Release);
                    self.cb_failure_count.store(threshold.max(1), Ordering::Release);
                    self.cb_window_start_secs.store(now, Ordering::Release);
                    log!(MLLog::CircuitBreakerOpen(threshold.max(1), window_secs));
                }
                return;
            }
            _ => {}
        }

        let window_start = self.cb_window_start_secs.load(Ordering::Acquire);
        if window_start == 0 || now.saturating_sub(window_start) > window_secs {
            self.cb_window_start_secs.store(now, Ordering::Release);
            self.cb_failure_count.store(1, Ordering::Release);
        } else {
            self.cb_failure_count.fetch_add(1, Ordering::AcqRel);
        }

        let count = self.cb_failure_count.load(Ordering::Acquire);
        if count >= threshold
            && self
                .cb_phase
                .compare_exchange(CB_CLOSED, CB_OPEN, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            self.cb_open_since_secs.store(now, Ordering::Release);
            log!(MLLog::CircuitBreakerOpen(count, window_secs));
        }
    }
}

fn argmax(probs: &[f32]) -> (usize, f32) {
    probs
        .iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(CmpOrdering::Equal))
        .map(|(i, &p)| (i, p))
        .unwrap_or((0, 0.0))
}

fn quantile_transform(value: f64, values: &[f64], quantiles: &[f64], feature_name: &str) -> Result<f64, MLError> {
    if values.len() != quantiles.len() || values.len() < 2 {
        return Err(MLError::ConfigInvalid(format!(
            "quantile preprocessing for feature '{feature_name}' requires equal-length values/quantiles with at least two points"
        )));
    }
    if value <= values[0] {
        return Ok(quantiles[0]);
    }
    for idx in 1..values.len() {
        if value <= values[idx] {
            let low_value = values[idx - 1];
            let high_value = values[idx];
            let low_quantile = quantiles[idx - 1];
            let high_quantile = quantiles[idx];
            let span = high_value - low_value;
            if span <= 0.0 {
                return Ok(high_quantile);
            }
            let ratio = (value - low_value) / span;
            return Ok(low_quantile + ratio * (high_quantile - low_quantile));
        }
    }
    Ok(*quantiles.last().unwrap_or(&1.0))
}

#[derive(Clone, Copy)]
struct PipelineOutputs<'a> {
    scalars: &'a HashMap<String, Vec<f32>>,
    matrices: &'a HashMap<String, Vec<Vec<f32>>>,
    thresholds: &'a HashMap<String, f32>,
    min_confidences: &'a HashMap<String, f32>,
}

#[derive(Clone, Copy)]
struct RuleCandidate {
    confidence: f32,
    alert_threshold: f32,
    attack_type: CanonicalAttackType,
}

fn append_stage_tensors(
    scalars: &mut HashMap<String, Vec<f32>>,
    matrices: &mut HashMap<String, Vec<Vec<f32>>>,
    tensors: Vec<RuntimeTensor>,
) {
    for tensor in tensors {
        match tensor {
            RuntimeTensor::Scalar { name, values } => {
                scalars.entry(name).or_default().extend(values);
            }
            RuntimeTensor::Matrix { name, rows } => {
                matrices.entry(name).or_default().extend(rows);
            }
        }
    }
}

fn pipeline_output_key(outputs: &[PipelineOutputSpec], reference: &str) -> Option<String> {
    outputs
        .iter()
        .find(|output| output_matches_ref(output, reference))
        .map(|output| stage_output_key(&output.stage, &output.output))
}

fn detection_scores_from_roles(
    outputs: &[PipelineOutputSpec],
    pipeline_outputs: PipelineOutputs<'_>,
    row_idx: usize,
) -> DetectionScores {
    let mut scores = DetectionScores {
        confidence: 0.0,
        alert_threshold: 1.0,
        ae: 0.0,
        anomaly: 0.0,
        c2: 0.0,
    };
    for output in outputs {
        let key = stage_output_key(&output.stage, &output.output);
        let value = pipeline_outputs
            .scalars
            .get(&key)
            .and_then(|values| values.get(row_idx))
            .copied();
        match (output.role, value) {
            (OutputRole::AnomalyScore, Some(v)) => scores.ae = scores.ae.max(v),
            (OutputRole::BinaryScore, Some(v)) => scores.anomaly = scores.anomaly.max(v),
            (OutputRole::C2Score, Some(v)) => scores.c2 = scores.c2.max(v),
            _ => {}
        }
    }
    scores.confidence = scores.ae.max(scores.anomaly).max(scores.c2);
    scores
}

fn best_rule_candidate(
    rules: &[DetectionRuleSpec],
    outputs: &[PipelineOutputSpec],
    labels: &BTreeMap<String, LabelSpec>,
    normal_label: &str,
    pipeline_outputs: PipelineOutputs<'_>,
    row_idx: usize,
) -> Option<RuleCandidate> {
    rules
        .iter()
        .filter_map(|rule| evaluate_rule(rule, outputs, labels, normal_label, pipeline_outputs, row_idx))
        .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap_or(CmpOrdering::Equal))
}

fn evaluate_rule(
    rule: &DetectionRuleSpec,
    outputs: &[PipelineOutputSpec],
    labels: &BTreeMap<String, LabelSpec>,
    normal_label: &str,
    pipeline_outputs: PipelineOutputs<'_>,
    row_idx: usize,
) -> Option<RuleCandidate> {
    match rule {
        DetectionRuleSpec::Threshold { output, attack, .. } => {
            let key = pipeline_output_key(outputs, output)?;
            let value = pipeline_outputs.scalars.get(&key)?.get(row_idx).copied()?;
            let threshold = pipeline_outputs.thresholds.get(&key).copied()?;
            if value <= threshold {
                return None;
            }
            attack_type_from_mapping(attack, outputs, labels, normal_label, pipeline_outputs, row_idx).map(
                |attack_type| RuleCandidate {
                    confidence: value,
                    alert_threshold: threshold,
                    attack_type,
                },
            )
        }
        DetectionRuleSpec::ClassConfidence { output, attack, .. } => {
            let key = pipeline_output_key(outputs, output)?;
            let row = pipeline_outputs.matrices.get(&key)?.get(row_idx)?;
            let (_, confidence) = argmax(row);
            let min_confidence = pipeline_outputs.min_confidences.get(&key).copied()?;
            if confidence < min_confidence {
                return None;
            }
            attack_type_from_mapping(attack, outputs, labels, normal_label, pipeline_outputs, row_idx).map(
                |attack_type| RuleCandidate {
                    confidence,
                    alert_threshold: min_confidence,
                    attack_type,
                },
            )
        }
    }
}

fn attack_type_from_mapping(
    attack: &AttackMappingSpec,
    outputs: &[PipelineOutputSpec],
    labels: &BTreeMap<String, LabelSpec>,
    normal_label: &str,
    pipeline_outputs: PipelineOutputs<'_>,
    row_idx: usize,
) -> Option<CanonicalAttackType> {
    match attack {
        AttackMappingSpec::PredictedClass { output, exclude_normal } => {
            let key = pipeline_output_key(outputs, output)?;
            let row = pipeline_outputs.matrices.get(&key)?.get(row_idx)?;
            let (predicted_class, _) = argmax(row);
            let label = labels.get(&predicted_class.to_string())?;
            if *exclude_normal && label.name.eq_ignore_ascii_case(normal_label) {
                return None;
            }
            Some(translate(DetectionSource::ML, &label.name))
        }
        AttackMappingSpec::FixedLabel { label } => Some(translate(DetectionSource::ML, label)),
    }
}

fn build_flow_key_label(flow: &FlowSnapshot) -> String {
    format!(
        "{}:{} -> {}:{} (proto {}) [{}]",
        flow.flow_key.src_ip_string(),
        flow.flow_key.src_port,
        flow.flow_key.dst_ip_string(),
        flow.flow_key.dst_port,
        flow.flow_key.protocol,
        flow.direction
    )
}

struct DetectionScores {
    confidence: f32,
    alert_threshold: f32,
    ae: f32,
    anomaly: f32,
    c2: f32,
}

fn detection_result(
    flow: &FlowSnapshot,
    is_attack: bool,
    attack_type: Option<CanonicalAttackType>,
    scores: DetectionScores,
) -> DetectionResult {
    DetectionResult {
        flow_key: if is_attack {
            build_flow_key_label(flow)
        } else {
            String::new()
        },
        flow_key_raw: flow.flow_key,
        direction: flow.direction,
        is_attack,
        attack_type,
        confidence: scores.confidence,
        alert_threshold: scores.alert_threshold,
        ae_score: scores.ae,
        anomaly_score: scores.anomaly,
        c2_score: scores.c2,
        packet_count: flow.packet_count as u64,
        flow_duration_us: flow.duration_us(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use super::*;
    use crate::domain::detection::manifest::{
        AttackMappingSpec, DetectionRuleSpec, LabelSpec, OutputRole, PipelineOutputSpec,
    };
    use crate::domain::detection::ml_detection::ClipParams;
    use crate::domain::detection::ml_inference_config::{MinMaxParams, QuantileParams, RobustParams};

    #[test]
    fn argmax_picks_highest() {
        let (idx, val) = argmax(&[0.1, 0.5, 0.3, 0.4]);
        assert_eq!(idx, 1);
        assert!((val - 0.5).abs() < 1e-6);
    }

    #[test]
    fn argmax_empty_returns_zero() {
        assert_eq!(argmax(&[]), (0, 0.0));
    }

    #[test]
    fn argmax_equal_picks_last() {
        let (idx, _) = argmax(&[0.25, 0.25, 0.25, 0.25]);
        assert_eq!(idx, 3);
    }

    #[test]
    fn detection_rules_use_manifest_output_aliases() {
        let outputs = vec![
            PipelineOutputSpec {
                stage: "detector".to_string(),
                output: "raw_score".to_string(),
                alias: Some("threat_score".to_string()),
                role: OutputRole::BinaryScore,
            },
            PipelineOutputSpec {
                stage: "classifier".to_string(),
                output: "probabilities".to_string(),
                alias: Some("family_probs".to_string()),
                role: OutputRole::ClassProbabilities,
            },
        ];
        let rules = vec![DetectionRuleSpec::Threshold {
            id: "threat_score_threshold".to_string(),
            output: "threat_score".to_string(),
            attack: AttackMappingSpec::PredictedClass {
                output: "family_probs".to_string(),
                exclude_normal: true,
            },
        }];
        let labels = BTreeMap::from([
            (
                "0".to_string(),
                LabelSpec {
                    name: "Normal".to_string(),
                    confirmations: None,
                    playbook: None,
                },
            ),
            (
                "1".to_string(),
                LabelSpec {
                    name: "Bot".to_string(),
                    confirmations: Some(1),
                    playbook: None,
                },
            ),
        ]);
        let scalars = HashMap::from([("detector.raw_score".to_string(), vec![0.92])]);
        let matrices = HashMap::from([("classifier.probabilities".to_string(), vec![vec![0.1, 0.9]])]);
        let thresholds = HashMap::from([("detector.raw_score".to_string(), 0.7)]);
        let min_confidences = HashMap::new();
        let pipeline_outputs = PipelineOutputs {
            scalars: &scalars,
            matrices: &matrices,
            thresholds: &thresholds,
            min_confidences: &min_confidences,
        };

        let candidate = best_rule_candidate(&rules, &outputs, &labels, "Normal", pipeline_outputs, 0)
            .expect("threshold should fire");

        assert_eq!(candidate.attack_type, CanonicalAttackType::BotActivity);
        assert!((candidate.confidence - 0.92).abs() < 1e-6);
        assert!((candidate.alert_threshold - 0.7).abs() < 1e-6);
    }

    #[test]
    fn predicted_class_mapping_can_exclude_normal() {
        let outputs = vec![PipelineOutputSpec {
            stage: "classifier".to_string(),
            output: "probabilities".to_string(),
            alias: Some("family_probs".to_string()),
            role: OutputRole::ClassProbabilities,
        }];
        let rules = vec![DetectionRuleSpec::ClassConfidence {
            id: "class_confidence".to_string(),
            output: "family_probs".to_string(),
            attack: AttackMappingSpec::PredictedClass {
                output: "family_probs".to_string(),
                exclude_normal: true,
            },
        }];
        let labels = BTreeMap::from([(
            "0".to_string(),
            LabelSpec {
                name: "Normal".to_string(),
                confirmations: None,
                playbook: None,
            },
        )]);
        let scalars = HashMap::new();
        let matrices = HashMap::from([("classifier.probabilities".to_string(), vec![vec![0.99]])]);
        let thresholds = HashMap::new();
        let min_confidences = HashMap::from([("classifier.probabilities".to_string(), 0.4)]);
        let pipeline_outputs = PipelineOutputs {
            scalars: &scalars,
            matrices: &matrices,
            thresholds: &thresholds,
            min_confidences: &min_confidences,
        };

        assert!(best_rule_candidate(&rules, &outputs, &labels, "Normal", pipeline_outputs, 0).is_none());
    }

    #[test]
    fn manifest_preprocessing_steps_are_executed_in_order() {
        let mut config = test_inference_config();
        config.ae_feature_names = vec!["flow_duration".to_string()];
        config.ae_scaler_mean = vec![10.0];
        config.ae_scaler_std = vec![2.0];
        config
            .minmax_params
            .insert("flow_duration".to_string(), MinMaxParams { min: 0.0, max: 10.0 });
        config.robust_params.insert(
            "flow_duration".to_string(),
            RobustParams {
                center: 0.5,
                scale: 0.5,
            },
        );
        config.quantile_params.insert(
            "flow_duration".to_string(),
            QuantileParams {
                values: vec![0.0, 1.0],
                quantiles: vec![0.0, 100.0],
            },
        );
        let inference = Inference::new(
            ModelSourceState::Dormant,
            Arc::new(config),
            Arc::new(ArcSwap::from_pointee(AppConfig::defaults())),
        );

        let steps = [
            PreprocessingStep::StandardScaler {
                sidecar: "inference_config.json".to_string(),
            },
            PreprocessingStep::Clip { min: 0.0, max: 10.0 },
            PreprocessingStep::MinMaxScaler {
                sidecar: "inference_config.json".to_string(),
            },
            PreprocessingStep::RobustScaler {
                sidecar: "inference_config.json".to_string(),
            },
            PreprocessingStep::Quantile {
                sidecar: "inference_config.json".to_string(),
            },
        ];

        let value = steps.iter().try_fold(30.0, |value, step| {
            inference.apply_preprocessing_step("flow_duration", value, step)
        });

        assert_eq!(value.expect("preprocess"), 100.0);
    }

    #[test]
    fn first_failure_opens_circuit_when_threshold_is_one() {
        let mut app_config = AppConfig::defaults();
        app_config.ml.circuit_breaker.threshold = 1;
        app_config.ml.circuit_breaker.cooldown_secs = 60;

        let inference = Inference::new(
            ModelSourceState::Dormant,
            Arc::new(test_inference_config()),
            Arc::new(ArcSwap::from_pointee(app_config)),
        );

        inference.record_failure();

        assert!(inference.is_circuit_open());
    }

    #[test]
    fn cooldown_allows_only_one_half_open_trial() {
        let mut app_config = AppConfig::defaults();
        app_config.ml.circuit_breaker.threshold = 1;
        app_config.ml.circuit_breaker.cooldown_secs = 0;

        let inference = Inference::new(
            ModelSourceState::Dormant,
            Arc::new(test_inference_config()),
            Arc::new(ArcSwap::from_pointee(app_config)),
        );

        inference.record_failure();

        assert!(!inference.is_circuit_open());
        assert!(inference.is_circuit_open());
    }

    #[test]
    fn half_open_failure_reopens_circuit() {
        let mut app_config = AppConfig::defaults();
        app_config.ml.circuit_breaker.threshold = 1;
        app_config.ml.circuit_breaker.cooldown_secs = 0;

        let inference = Inference::new(
            ModelSourceState::Dormant,
            Arc::new(test_inference_config()),
            Arc::new(ArcSwap::from_pointee(app_config)),
        );

        inference.record_failure();
        assert!(!inference.is_circuit_open());
        inference.record_failure();

        assert!(!inference.is_circuit_open());
        assert!(inference.is_circuit_open());
    }

    fn test_inference_config() -> MLInferenceConfig {
        MLInferenceConfig {
            ae_feature_names: vec!["Destination Port".to_string()],
            ae_clip_params: HashMap::from([(
                "Destination Port".to_string(),
                ClipParams {
                    lower: 0.0,
                    upper: 65_535.0,
                },
            )]),
            ae_scaler_mean: vec![0.0],
            ae_scaler_std: vec![1.0],
            ae_post_clip_min: -5.0,
            ae_post_clip_max: 5.0,
            classifier_feature_names: vec!["Destination Port".to_string()],
            minmax_params: HashMap::new(),
            robust_params: HashMap::new(),
            quantile_params: HashMap::new(),
        }
    }
}
