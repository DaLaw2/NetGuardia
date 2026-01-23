use serde::{Deserialize, Serialize};
use tract_onnx::prelude::{Graph, SimplePlan, TypedFact, TypedOp};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipParams {
    pub lower: f64,
    pub upper: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AENormalization {
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub std: f64,
    pub median: f64,
    pub p90: f64,
    pub p95: f64,
    pub p99: f64,
}

pub type RunnableModel = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;