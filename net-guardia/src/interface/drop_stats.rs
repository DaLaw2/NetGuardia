use crate::domain::data_plane::drop_event::DropCounters;

pub trait DropStatsPort: Send + Sync {
    fn get_counters(&self) -> DropCounters;
}
