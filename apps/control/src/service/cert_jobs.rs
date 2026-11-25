//! In-process registry for asynchronous certificate-issuance jobs.
//!
//! Issuing a certificate is not a request-shaped operation: Let's Encrypt needs
//! an account, an order, an HTTP-01 challenge round trip and two polling loops
//! (`wait_authz`, `wait_order`), so a successful issuance routinely takes tens of
//! seconds and a failing one can take minutes. Running that inside the HTTP
//! handler kept `POST /api/v1/certs/issue` — and the reverse proxy in front of it
//! — open for the whole time.
//!
//! The endpoint now answers `202 Accepted` with a job id and the caller polls
//! `GET /api/v1/certs/jobs/:id`. This module is the registry behind that:
//!
//! * **one active job per (domain, provider)** — a double click must not create
//!   two ACME orders, which also burns Let's Encrypt rate limits;
//! * **a global concurrency cap** — each job performs outbound HTTPS calls and an
//!   edge fan-out, so an admin script could otherwise saturate the control plane;
//! * **bounded retention** — finished jobs are pruned by age and by count, so a
//!   long-lived process does not accumulate results nobody polls any more;
//! * **panic-safe** — [`JobGuard`] marks an unfinished job as failed when the
//!   worker is dropped, so a panicking task cannot leave a job `running` forever.
//!
//! State is in-process by design: the control plane is one process behind the
//! console's reverse proxy, and a job lost to a restart is recovered by the
//! renewal worker (a certificate that never landed is still due). Polling a job
//! that vanished with a restart returns `404`, which the console treats as "try
//! again".

use dashmap::DashMap;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// How many jobs may run at the same time.
///
/// Each job performs several outbound HTTPS calls plus a fan-out to every online
/// edge, so this is a resource bound, not a UI preference. Reaching it answers
/// `429` instead of queueing: a queue would hide the load and make the poll
/// status meaningless ("pending" for minutes).
pub const MAX_ACTIVE_JOBS: usize = 8;

/// Finished jobs are kept this long so a slow poller still sees the result.
pub const JOB_RETENTION: Duration = Duration::from_secs(30 * 60);

/// Finished jobs are also capped by count, so a burst of issuances cannot grow
/// the map without bound even inside the retention window.
pub const MAX_FINISHED_JOBS: usize = 64;

/// Lifecycle of one issuance job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
}

impl JobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    /// Terminal states are what retention prunes.
    pub fn is_finished(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed)
    }
}

/// A poll response: a snapshot, never a live handle.
#[derive(Debug, Clone, Serialize)]
pub struct JobSnapshot {
    pub id: Uuid,
    pub domain_name: String,
    pub provider: String,
    pub status: JobStatus,
    /// Human-readable progress or failure text. Never contains the private key.
    pub message: String,
    pub cert_id: Option<Uuid>,
    pub issuer: Option<String>,
    pub edges_pushed: Option<u32>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub elapsed_ms: u64,
}

/// Result of [`CertJobs::start`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Start {
    /// A new job was created; the caller must spawn the worker.
    Started { id: Uuid },
    /// An identical job is already pending/running; poll that id instead.
    AlreadyActive { id: Uuid },
}

/// Start failures the API must surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartError {
    /// [`MAX_ACTIVE_JOBS`] jobs are already pending/running.
    TooManyActive,
}

struct Job {
    id: Uuid,
    domain_name: String,
    provider: String,
    status: JobStatus,
    message: String,
    cert_id: Option<Uuid>,
    issuer: Option<String>,
    edges_pushed: Option<u32>,
    created_at: Instant,
    created_at_ms: u64,
    updated_at_ms: u64,
}

impl Job {
    fn snapshot(&self) -> JobSnapshot {
        JobSnapshot {
            id: self.id,
            domain_name: self.domain_name.clone(),
            provider: self.provider.clone(),
            status: self.status,
            message: self.message.clone(),
            cert_id: self.cert_id,
            issuer: self.issuer.clone(),
            edges_pushed: self.edges_pushed,
            created_at_ms: self.created_at_ms,
            updated_at_ms: self.updated_at_ms,
            elapsed_ms: self.created_at.elapsed().as_millis() as u64,
        }
    }

    fn finished(&self) -> bool {
        self.status.is_finished()
    }
}

#[derive(Default)]
pub struct CertJobs {
    jobs: DashMap<Uuid, Arc<std::sync::Mutex<Job>>>,
    active: AtomicU64,
}

impl CertJobs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a job for `(domain, provider)`.
    ///
    /// Returns [`Start::AlreadyActive`] when an identical job is still
    /// pending/running, so a double click reuses the in-flight order instead of
    /// creating a second one.
    pub fn start(&self, domain_name: &str, provider: &str) -> Result<Start, StartError> {
        self.prune();
        if let Some(existing) = self.find_active(domain_name, provider) {
            return Ok(Start::AlreadyActive { id: existing });
        }
        // Claim the slot before inserting so two concurrent starts cannot both
        // pass the cap check.
        let claimed = self
            .active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_ACTIVE_JOBS as u64).then_some(current + 1)
            })
            .is_ok();
        if !claimed {
            return Err(StartError::TooManyActive);
        }
        let id = Uuid::new_v4();
        let now_ms = epoch_ms();
        let job = Job {
            id,
            domain_name: domain_name.to_string(),
            provider: provider.to_string(),
            status: JobStatus::Pending,
            message: "queued".into(),
            cert_id: None,
            issuer: None,
            edges_pushed: None,
            created_at: Instant::now(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        };
        self.jobs.insert(id, Arc::new(std::sync::Mutex::new(job)));
        Ok(Start::Started { id })
    }

    /// Mark the job as running.
    pub fn mark_running(&self, id: Uuid, message: &str) {
        self.update(id, |job| {
            job.status = JobStatus::Running;
            job.message = message.to_string();
        });
    }

    /// Record a successful issuance.
    pub fn succeed(&self, id: Uuid, cert_id: Uuid, issuer: &str, edges_pushed: u32, message: &str) {
        self.finish(id, |job| {
            job.status = JobStatus::Succeeded;
            job.cert_id = Some(cert_id);
            job.issuer = Some(issuer.to_string());
            job.edges_pushed = Some(edges_pushed);
            job.message = message.to_string();
        });
    }

    /// Record a failure with the operator-facing reason.
    pub fn fail(&self, id: Uuid, message: &str) {
        self.finish(id, |job| {
            job.status = JobStatus::Failed;
            job.message = message.to_string();
        });
    }

    /// Snapshot one job, if it is still retained.
    pub fn snapshot(&self, id: Uuid) -> Option<JobSnapshot> {
        self.jobs
            .get(&id)
            .and_then(|job| job.lock().ok().map(|job| job.snapshot()))
    }

    /// Number of jobs still retained (tests and diagnostics).
    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }

    /// Active (pending/running) jobs, newest first. The console uses this to
    /// restore its progress view after a page reload.
    pub fn active(&self) -> Vec<JobSnapshot> {
        let mut out: Vec<JobSnapshot> = self
            .jobs
            .iter()
            .filter_map(|entry| entry.value().lock().ok().map(|job| job.snapshot()))
            .filter(|job| !job.status.is_finished())
            .collect();
        out.sort_by_key(|job| std::cmp::Reverse(job.created_at_ms));
        out
    }

    fn find_active(&self, domain_name: &str, provider: &str) -> Option<Uuid> {
        self.jobs.iter().find_map(|entry| {
            let job = entry.value().lock().ok()?;
            // DNS names and provider names are case-insensitive; compare folded so
            // "A.test"/"dev" reuses the job started as "a.test"/"DEV".
            (!job.finished()
                && job.domain_name.eq_ignore_ascii_case(domain_name)
                && job.provider.eq_ignore_ascii_case(provider))
            .then_some(job.id)
        })
    }

    fn update(&self, id: Uuid, apply: impl FnOnce(&mut Job)) {
        if let Some(entry) = self.jobs.get(&id) {
            if let Ok(mut job) = entry.value().lock() {
                apply(&mut job);
                job.updated_at_ms = epoch_ms();
            }
        }
    }

    /// Transition to a terminal state and release the concurrency slot once.
    fn finish(&self, id: Uuid, apply: impl FnOnce(&mut Job)) {
        let mut released = false;
        if let Some(entry) = self.jobs.get(&id) {
            if let Ok(mut job) = entry.value().lock() {
                // The guard may have finalised this job already (worker dropped
                // after a panic); finishing twice must not double-release.
                if !job.finished() {
                    apply(&mut job);
                    job.updated_at_ms = epoch_ms();
                    released = true;
                }
            }
        }
        if released {
            self.active.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Drop finished jobs beyond the retention window or the count cap.
    fn prune(&self) {
        let now = Instant::now();
        let mut finished: Vec<(Instant, Uuid)> = Vec::new();
        for entry in self.jobs.iter() {
            if let Ok(job) = entry.value().lock() {
                if job.finished() {
                    finished.push((job.created_at, job.id));
                }
            }
        }
        for (created_at, id) in &finished {
            if now.duration_since(*created_at) > JOB_RETENTION {
                // A finished entry holds no slot; removing it is bookkeeping only.
                self.jobs.remove(id);
            }
        }
        if finished.len() > MAX_FINISHED_JOBS {
            finished.sort_by_key(|(created_at, _)| *created_at);
            let excess = finished.len() - MAX_FINISHED_JOBS;
            for (_, id) in finished.into_iter().take(excess) {
                self.jobs.remove(&id);
            }
        }
    }

    #[cfg(test)]
    fn active_slots(&self) -> u64 {
        self.active.load(Ordering::Acquire)
    }
}

/// Owns one job's completion.
///
/// The worker holds this for the whole issuance. If it is dropped while the job
/// is still unfinished — a panic inside the async block, an aborted task, an
/// early `?` that forgot to record an outcome — the job is marked failed instead
/// of staying `running` forever, and the concurrency slot is released.
pub struct JobGuard {
    jobs: Arc<CertJobs>,
    id: Uuid,
    finished: bool,
}

impl JobGuard {
    pub fn new(jobs: Arc<CertJobs>, id: Uuid) -> Self {
        Self {
            jobs,
            id,
            finished: false,
        }
    }

    pub fn succeed(&mut self, cert_id: Uuid, issuer: &str, edges_pushed: u32, message: &str) {
        self.jobs
            .succeed(self.id, cert_id, issuer, edges_pushed, message);
        self.finished = true;
    }

    pub fn fail(&mut self, message: &str) {
        self.jobs.fail(self.id, message);
        self.finished = true;
    }
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.jobs
                .fail(self.id, "issuance worker stopped before reporting a result");
        }
    }
}

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn started(jobs: &CertJobs, domain: &str, provider: &str) -> Uuid {
        match jobs.start(domain, provider).expect("start") {
            Start::Started { id } => id,
            Start::AlreadyActive { .. } => panic!("expected a new job"),
        }
    }

    #[test]
    fn starting_a_job_records_it_as_pending() {
        let jobs = CertJobs::new();
        let id = started(&jobs, "a.test", "dev");
        let job = jobs.snapshot(id).expect("snapshot");
        assert_eq!(job.status, JobStatus::Pending);
        assert_eq!(job.domain_name, "a.test");
        assert_eq!(job.provider, "dev");
        assert_eq!(job.message, "queued");
        assert_eq!(jobs.active_slots(), 1);
    }

    /// A double click must reuse the in-flight job: two ACME orders for the same
    /// name waste the CA's rate limit and can race each other.
    #[test]
    fn an_active_job_is_reused_for_the_same_domain_and_provider() {
        let jobs = CertJobs::new();
        let first = started(&jobs, "a.test", "letsencrypt");
        assert_eq!(
            jobs.start("a.test", "letsencrypt"),
            Ok(Start::AlreadyActive { id: first })
        );
        // A different provider or domain is a different job.
        assert!(matches!(
            jobs.start("a.test", "dev"),
            Ok(Start::Started { .. })
        ));
        assert!(matches!(
            jobs.start("b.test", "letsencrypt"),
            Ok(Start::Started { .. })
        ));
        assert_eq!(jobs.active_slots(), 3);
    }

    #[test]
    fn a_finished_job_does_not_block_a_new_one() {
        let jobs = CertJobs::new();
        let id = started(&jobs, "a.test", "dev");
        jobs.fail(id, "boom");
        assert_eq!(
            jobs.snapshot(id).expect("snapshot").status,
            JobStatus::Failed
        );
        assert!(matches!(
            jobs.start("a.test", "dev"),
            Ok(Start::Started { .. })
        ));
    }

    #[test]
    fn the_concurrency_cap_is_enforced_and_released() {
        let jobs = CertJobs::new();
        let mut ids = Vec::new();
        for i in 0..MAX_ACTIVE_JOBS {
            ids.push(started(&jobs, &format!("d{i}.test"), "dev"));
        }
        assert_eq!(jobs.active_slots(), MAX_ACTIVE_JOBS as u64);
        assert_eq!(
            jobs.start("overflow.test", "dev"),
            Err(StartError::TooManyActive)
        );

        // Finishing one job frees exactly one slot.
        jobs.fail(ids[0], "done");
        assert_eq!(jobs.active_slots(), MAX_ACTIVE_JOBS as u64 - 1);
        assert!(matches!(
            jobs.start("overflow.test", "dev"),
            Ok(Start::Started { .. })
        ));
    }

    #[test]
    fn finishing_twice_releases_one_slot_only() {
        let jobs = CertJobs::new();
        let id = started(&jobs, "a.test", "dev");
        jobs.succeed(id, Uuid::nil(), "Lagran Dev CA", 0, "ok");
        assert_eq!(jobs.active_slots(), 0);
        // A late failure (the guard firing after an explicit success) must not
        // drive the slot counter negative.
        jobs.fail(id, "late");
        assert_eq!(jobs.active_slots(), 0);
        let job = jobs.snapshot(id).expect("snapshot");
        assert_eq!(job.status, JobStatus::Succeeded, "the first outcome wins");
    }

    /// A worker that disappears without reporting must not leave the job running.
    #[test]
    fn dropping_an_unfinished_guard_marks_the_job_failed() {
        let jobs = Arc::new(CertJobs::new());
        let id = started(&jobs, "a.test", "dev");
        jobs.mark_running(id, "contacting ACME");
        {
            let _guard = JobGuard::new(jobs.clone(), id);
            // ... the worker would panic or be aborted here ...
        }
        let job = jobs.snapshot(id).expect("snapshot");
        assert_eq!(job.status, JobStatus::Failed);
        assert!(job.message.contains("stopped before reporting"));
        assert_eq!(jobs.active_slots(), 0, "the slot must be released");
    }

    #[test]
    fn a_finished_guard_is_not_overwritten_on_drop() {
        let jobs = Arc::new(CertJobs::new());
        let id = started(&jobs, "a.test", "dev");
        {
            let mut guard = JobGuard::new(jobs.clone(), id);
            guard.succeed(Uuid::nil(), "Lagran Dev CA", 2, "issued");
        }
        let job = jobs.snapshot(id).expect("snapshot");
        assert_eq!(job.status, JobStatus::Succeeded);
        assert_eq!(job.edges_pushed, Some(2));
    }

    #[test]
    fn retention_prunes_finished_jobs_by_count() {
        let jobs = CertJobs::new();
        for i in 0..MAX_FINISHED_JOBS + 10 {
            let id = started(&jobs, &format!("d{i}.test"), "dev");
            jobs.fail(id, "done");
        }
        // Pruning runs on the next start.
        let _ = jobs.start("fresh.test", "dev").expect("start");
        assert!(
            jobs.len() <= MAX_FINISHED_JOBS + 1,
            "retained {} jobs",
            jobs.len()
        );
    }

    #[test]
    fn active_jobs_are_listed_and_finished_ones_are_not() {
        let jobs = CertJobs::new();
        let id = started(&jobs, "a.test", "dev");
        let _ = jobs.start("b.test", "dev").expect("start");
        jobs.fail(id, "done");
        let active = jobs.active();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].domain_name, "b.test");
    }

    #[test]
    fn status_strings_are_the_api_contract() {
        assert_eq!(JobStatus::Pending.as_str(), "pending");
        assert_eq!(JobStatus::Running.as_str(), "running");
        assert_eq!(JobStatus::Succeeded.as_str(), "succeeded");
        assert_eq!(JobStatus::Failed.as_str(), "failed");
        assert!(!JobStatus::Running.is_finished());
        assert!(JobStatus::Failed.is_finished());
    }
}
