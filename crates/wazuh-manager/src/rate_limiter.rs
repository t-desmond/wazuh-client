use std::collections::VecDeque;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

/// Sliding-window client-side rate limiter.
///
/// Defaults to 12 req / 3s (~240 req/min), safely under Wazuh's default server
/// limit of 300 req/min. The lock is released while sleeping so other tasks can
/// proceed.
pub struct RateLimiter {
    max: usize,
    period: Duration,
    slots: Mutex<VecDeque<Instant>>,
}

impl RateLimiter {
    pub fn new(max: usize, period: Duration) -> Self {
        Self {
            max,
            period,
            slots: Mutex::new(VecDeque::new()),
        }
    }

    /// Block until a request slot is available, then record it.
    pub async fn acquire(&self) {
        loop {
            {
                let mut slots = self.slots.lock().await;
                let now = Instant::now();
                while let Some(&t) = slots.front() {
                    if now.duration_since(t) > self.period {
                        slots.pop_front();
                    } else {
                        break;
                    }
                }
                if slots.len() < self.max {
                    slots.push_back(now);
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
