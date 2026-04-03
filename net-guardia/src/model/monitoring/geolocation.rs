#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GeoLocation {
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
}
