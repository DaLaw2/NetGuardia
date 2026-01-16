use serde::{Deserialize, Serialize};
use common::model::flow_stats::FlowStats;

#[derive(Debug, Clone, Serialize)]
pub struct FlowStatsWithGeo {
    #[serde(flatten)]
    pub stats: FlowStats,
    pub geo: Option<GeoLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
}
