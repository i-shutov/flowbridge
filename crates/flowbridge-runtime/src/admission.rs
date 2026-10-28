//! Shared per-loopback-upstream admission. Applies to explicitly managed routes;
//! external clients of the same SSH listener are outside this budget.
use flowbridge_core::Endpoint;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
    time::Duration,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Instant,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_flows: usize,
    pub max_opening: usize,
    pub max_queued: usize,
    pub wait_timeout_ms: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_flows: 128,
            max_opening: 16,
            max_queued: 64,
            wait_timeout_ms: 10000,
        }
    }
}
impl Limits {
    fn validate(&self) -> Result<(), String> {
        if !(1..=4096).contains(&self.max_flows)
            || !(1..=self.max_flows).contains(&self.max_opening)
            || !(1..=4096).contains(&self.max_queued)
            || !(10..=120000).contains(&self.wait_timeout_ms)
        {
            return Err("invalid managed SSH admission limits".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub limits: Limits,
    pub active_including_opening: usize,
    pub opening: usize,
    pub queued: usize,
    pub rejected: u64,
}
pub(crate) struct Budget {
    limits: Limits,
    active: Arc<Semaphore>,
    opening: Arc<Semaphore>,
    queued: Arc<Semaphore>,
    rejected: AtomicU64,
}
impl Budget {
    fn new(limits: Limits) -> Self {
        Self {
            active: Arc::new(Semaphore::new(limits.max_flows)),
            opening: Arc::new(Semaphore::new(limits.max_opening)),
            queued: Arc::new(Semaphore::new(limits.max_queued)),
            rejected: AtomicU64::new(0),
            limits,
        }
    }
    pub(crate) fn shared(endpoint: &Endpoint, limits: Limits) -> Result<Arc<Self>, String> {
        limits.validate()?;
        let ip: IpAddr = endpoint
            .host
            .parse()
            .map_err(|_| "managed upstream must be an IP literal")?;
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            _ => ip,
        };
        let key = SocketAddr::new(ip, endpoint.port);
        static REGISTRY: OnceLock<Mutex<BTreeMap<SocketAddr, Weak<Budget>>>> = OnceLock::new();
        let mut registry = REGISTRY
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        registry.retain(|_, weak| weak.strong_count() > 0);
        if let Some(existing) = registry.get(&key).and_then(Weak::upgrade) {
            if existing.limits != limits {
                return Err("the shared SSH upstream already has different limits; detach all engines using it before changing limits".into());
            }
            return Ok(existing);
        }
        if registry.len() >= 1024 {
            return Err("managed upstream registry is full".into());
        }
        let budget = Arc::new(Self::new(limits));
        registry.insert(key, Arc::downgrade(&budget));
        Ok(budget)
    }
    pub(crate) fn snapshot(&self) -> Snapshot {
        Snapshot {
            limits: self.limits.clone(),
            active_including_opening: self.limits.max_flows - self.active.available_permits(),
            opening: self.limits.max_opening - self.opening.available_permits(),
            queued: self.limits.max_queued - self.queued.available_permits(),
            rejected: self.rejected.load(Ordering::Relaxed),
        }
    }
    pub(crate) fn enqueue(self: &Arc<Self>) -> Result<Waiter, String> {
        match self.queued.clone().try_acquire_owned() {
            Ok(permit) => Ok(Waiter {
                budget: self.clone(),
                _queued: permit,
                deadline: Instant::now() + Duration::from_millis(self.limits.wait_timeout_ms),
            }),
            Err(_) => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                Err("managed SSH queue is full; no direct fallback".into())
            }
        }
    }
}
pub(crate) struct Waiter {
    budget: Arc<Budget>,
    _queued: OwnedSemaphorePermit,
    pub(crate) deadline: Instant,
}
pub(crate) struct Admission {
    _budget: Arc<Budget>,
    _active: OwnedSemaphorePermit,
    opening: Option<OwnedSemaphorePermit>,
}
impl Admission {
    pub(crate) fn connected(&mut self) {
        self.opening.take();
    }
}
impl Waiter {
    pub(crate) async fn admit(self) -> Result<Admission, String> {
        let result = tokio::time::timeout_at(self.deadline, async {
            let active = self
                .budget
                .active
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| "SSH budget closed")?;
            let opening = self
                .budget
                .opening
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| "SSH opening budget closed")?;
            Ok(Admission {
                _budget: self.budget.clone(),
                _active: active,
                opening: Some(opening),
            })
        })
        .await;
        match result {
            Ok(result) => result,
            Err(_) => {
                self.budget.rejected.fetch_add(1, Ordering::Relaxed);
                Err("managed SSH capacity deadline expired; no direct fallback".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn opening_active_queue_and_timeout_are_independently_bounded() {
        let budget = Arc::new(Budget::new(Limits {
            max_flows: 2,
            max_opening: 1,
            max_queued: 1,
            wait_timeout_ms: 30,
        }));
        let mut first = budget.enqueue().unwrap().admit().await.unwrap();
        assert_eq!(budget.snapshot().opening, 1);
        let waiting = budget.enqueue().unwrap();
        assert!(budget.enqueue().is_err());
        assert!(waiting.admit().await.is_err());
        first.connected();
        let second = budget.enqueue().unwrap().admit().await.unwrap();
        assert_eq!(budget.snapshot().active_including_opening, 2);
        drop(first);
        drop(second);
        let status = budget.snapshot();
        assert_eq!(
            (
                status.active_including_opening,
                status.opening,
                status.queued
            ),
            (0, 0, 0)
        );
        assert_eq!(status.rejected, 2);
    }
    #[tokio::test]
    async fn cancellation_returns_all_permits() {
        let budget = Arc::new(Budget::new(Limits {
            max_flows: 2,
            max_opening: 1,
            max_queued: 2,
            wait_timeout_ms: 10000,
        }));
        let first = budget.enqueue().unwrap().admit().await.unwrap();
        let pending = tokio::spawn(budget.enqueue().unwrap().admit());
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        pending.abort();
        let _ = pending.await;
        drop(first);
        let status = budget.snapshot();
        assert_eq!(
            (
                status.active_including_opening,
                status.opening,
                status.queued
            ),
            (0, 0, 0)
        );
    }
    #[test]
    fn engines_share_canonical_endpoint_and_reject_conflicting_limits() {
        let endpoint = Endpoint {
            host: "127.0.0.1".into(),
            port: 17419,
        };
        let first = Budget::shared(&endpoint, Limits::default()).unwrap();
        let mapped = Endpoint {
            host: "::ffff:127.0.0.1".into(),
            port: 17419,
        };
        assert!(Arc::ptr_eq(
            &first,
            &Budget::shared(&mapped, Limits::default()).unwrap()
        ));
        assert!(Budget::shared(
            &endpoint,
            Limits {
                max_flows: 64,
                ..Limits::default()
            }
        )
        .is_err());
        drop(first);
        assert!(Budget::shared(
            &endpoint,
            Limits {
                max_flows: 64,
                ..Limits::default()
            }
        )
        .is_ok());
    }
    #[test]
    fn malformed_limits_fail_closed() {
        assert!(Limits {
            max_flows: 0,
            ..Limits::default()
        }
        .validate()
        .is_err());
        assert!(Limits {
            max_queued: 100000,
            ..Limits::default()
        }
        .validate()
        .is_err());
        assert!(serde_json::from_str::<Limits>(r#"{"unlimited":true}"#).is_err());
    }
}
