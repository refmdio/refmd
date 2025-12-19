#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerTick {
    Processed,
    Idle,
}
