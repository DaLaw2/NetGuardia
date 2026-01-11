use serde::Serialize;
use common::model::flow_stats::FlowStats;
use crate::core::infrastructure::geoip::GeoLocation;

#[derive(Debug, Clone, Serialize)]
pub struct FlowStatsWithGeo {
    #[serde(flatten)]
    pub stats: FlowStats,
    pub geo: Option<GeoLocation>,
}
