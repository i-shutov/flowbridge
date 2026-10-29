//! Bounded selection of independent managed SSH -D listeners.
//!
//! Worker availability is reported by the owner of each *real* OpenSSH child,
//! not inferred from a successful local SOCKS greeting.  Each worker owns an
//! independent transport and a globally shared per-endpoint admission Budget.
//! No existing TCP stream is re-routed, retried with application data, or
//! migrated between workers.
use crate::admission::{Budget, Limits, Snapshot as AdmissionSnapshot};
use flowbridge_core::Endpoint;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::IpAddr, sync::Arc};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerInput {
    pub endpoint: Endpoint,
    pub ready: bool,
}

#[derive(Clone)]
struct Worker {
    endpoint: Endpoint,
    ready: bool,
    budget: Arc<Budget>,
}

#[derive(Clone)]
pub struct Selected {
    pub endpoint: Endpoint,
    pub budget: Arc<Budget>,
}

#[derive(Serialize)]
pub struct WorkerSnapshot {
    pub endpoint: Endpoint,
    pub ready: bool,
    pub admission: AdmissionSnapshot,
}

#[derive(Serialize)]
pub struct Snapshot {
    pub aggregate_max_flows: usize,
    pub ready_workers: usize,
    pub workers: Vec<WorkerSnapshot>,
}

pub struct Pool {
    primary: Endpoint,
    workers: Vec<Worker>,
    aggregate_max_flows: usize,
}

fn normalized(endpoint: &Endpoint) -> Result<Endpoint, String> {
    endpoint.validate().map_err(|e| e.to_string())?;
    let ip: IpAddr = endpoint
        .host
        .parse()
        .map_err(|_| "managed pool endpoints must be literal loopback IPs")?;
    let canonical = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    };
    if !canonical.is_loopback() {
        return Err("managed pool endpoints must be literal loopback IPs".into());
    }
    Ok(Endpoint {
        host: canonical.to_string(),
        port: endpoint.port,
    })
}

impl Pool {
    pub fn new(
        primary: Endpoint,
        members: Vec<WorkerInput>,
        limits: Limits,
        aggregate_max_flows: usize,
    ) -> Result<Self, String> {
        if !(1..=4).contains(&members.len()) {
            return Err("managed SSH pool must have 1..=4 independent workers".into());
        }
        if !(1..=4096).contains(&aggregate_max_flows)
            || members.len().saturating_mul(limits.max_flows) > aggregate_max_flows
        {
            return Err("managed SSH pool exceeds its explicit aggregate flow ceiling".into());
        }
        let primary = normalized(&primary)?;
        let mut unique = HashSet::new();
        let mut workers = Vec::with_capacity(members.len());
        for (index, item) in members.into_iter().enumerate() {
            let endpoint = normalized(&item.endpoint)?;
            if index == 0 && endpoint != primary {
                return Err("managed SSH pool first worker must match the configured proxy".into());
            }
            if !unique.insert((endpoint.host.clone(), endpoint.port)) {
                return Err(
                    "managed SSH pool contains duplicate loopback listener endpoints".into(),
                );
            }
            let budget = Budget::shared(&endpoint, limits.clone())?;
            workers.push(Worker {
                endpoint,
                ready: item.ready,
                budget,
            });
        }
        Ok(Self {
            primary,
            workers,
            aggregate_max_flows,
        })
    }

    pub fn matches(&self, endpoint: &Endpoint) -> bool {
        normalized(endpoint).is_ok_and(|endpoint| endpoint == self.primary)
    }

    pub fn is_ready(&self, endpoint: &Endpoint) -> bool {
        normalized(endpoint).is_ok_and(|endpoint| {
            self.workers
                .iter()
                .any(|worker| worker.endpoint == endpoint && worker.ready)
        })
    }

    pub fn has_ready(&self) -> bool {
        self.workers.iter().any(|worker| worker.ready)
    }

    /// Prefer a ready worker with free established-flow and handshake permits.
    /// Rotate only across equal-capacity candidates, using a shared per-engine
    /// cursor. When all ready workers are full, choose one bounded queue;
    /// never use an unready worker or fall back to DIRECT.
    pub fn select(&self, cursor: u64) -> Result<Selected, String> {
        let length = self.workers.len();
        let mut best: Option<(usize, bool, usize)> = None;
        for offset in 0..length {
            let index = ((cursor as usize) % length + offset) % length;
            let worker = &self.workers[index];
            if !worker.ready {
                continue;
            }
            let snapshot = worker.budget.snapshot();
            let free = snapshot
                .limits
                .max_flows
                .saturating_sub(snapshot.active_including_opening);
            let opening_free = snapshot.opening < snapshot.limits.max_opening;
            let available = free > 0 && opening_free;
            let replace = match best {
                None => true,
                Some((_, previous_available, previous_free)) => {
                    available > previous_available
                        || (available == previous_available && free > previous_free)
                }
            };
            if replace {
                best = Some((index, available, free));
            }
        }
        let (index, _, _) =
            best.ok_or("all managed SSH pool workers are unavailable; no DIRECT fallback")?;
        let worker = &self.workers[index];
        Ok(Selected {
            endpoint: worker.endpoint.clone(),
            budget: worker.budget.clone(),
        })
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            aggregate_max_flows: self.aggregate_max_flows,
            ready_workers: self.workers.iter().filter(|w| w.ready).count(),
            workers: self
                .workers
                .iter()
                .map(|worker| WorkerSnapshot {
                    endpoint: worker.endpoint.clone(),
                    ready: worker.ready,
                    admission: worker.budget.snapshot(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn endpoint(port: u16) -> Endpoint {
        Endpoint {
            host: "127.0.0.1".into(),
            port,
        }
    }
    fn limits() -> Limits {
        Limits {
            max_flows: 2,
            max_opening: 1,
            max_queued: 2,
            wait_timeout_ms: 100,
        }
    }
    fn pool(ready: [bool; 2]) -> Pool {
        Pool::new(
            endpoint(49101),
            vec![
                WorkerInput {
                    endpoint: endpoint(49101),
                    ready: ready[0],
                },
                WorkerInput {
                    endpoint: endpoint(49102),
                    ready: ready[1],
                },
            ],
            limits(),
            4,
        )
        .unwrap()
    }
    #[tokio::test]
    async fn selects_two_workers_and_respects_existing_flow_ownership() {
        let pool = pool([true, true]);
        let first = pool.select(0).unwrap();
        assert_eq!(first.endpoint.port, 49101);
        let held = first.budget.enqueue().unwrap().admit().await.unwrap();
        let second = pool.select(1).unwrap();
        assert_eq!(second.endpoint.port, 49102);
        let pinned = pool.select(2).unwrap();
        assert_eq!(pinned.endpoint.port, 49102);
        let unavailable = pool([false, true]);
        assert_eq!(unavailable.select(0).unwrap().endpoint.port, 49102);
        assert_eq!(first.budget.snapshot().active_including_opening, 1);
        drop(held);
        assert_eq!(first.budget.snapshot().active_including_opening, 0);
        assert_eq!(pool.snapshot().ready_workers, 2);
    }
    #[test]
    fn rejects_duplicates_mismatched_primary_remote_and_aggregate_overcommit() {
        assert!(Pool::new(endpoint(49101), vec![], limits(), 4).is_err());
        assert!(Pool::new(
            endpoint(49101),
            vec![WorkerInput {
                endpoint: endpoint(49102),
                ready: true
            }],
            limits(),
            4
        )
        .is_err());
        assert!(Pool::new(
            endpoint(49101),
            vec![
                WorkerInput {
                    endpoint: endpoint(49101),
                    ready: true
                },
                WorkerInput {
                    endpoint: endpoint(49101),
                    ready: true
                }
            ],
            limits(),
            4
        )
        .is_err());
        assert!(Pool::new(
            endpoint(49101),
            vec![
                WorkerInput {
                    endpoint: endpoint(49101),
                    ready: true
                },
                WorkerInput {
                    endpoint: endpoint(49102),
                    ready: true
                }
            ],
            limits(),
            3
        )
        .is_err());
        assert!(Pool::new(
            endpoint(49101),
            vec![WorkerInput {
                endpoint: Endpoint {
                    host: "198.51.100.10".into(),
                    port: 49101
                },
                ready: true
            }],
            limits(),
            4
        )
        .is_err());
        assert!(Pool::new(
            endpoint(49101),
            vec![WorkerInput {
                endpoint: endpoint(49101),
                ready: false
            }],
            limits(),
            4
        )
        .unwrap()
        .select(0)
        .is_err());
    }
}
