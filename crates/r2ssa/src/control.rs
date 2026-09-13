//! Cooperative control for bounded SSA preparation work.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Work one controlled run has done, counted rather than timed.
///
/// A wall clock answers a different question on every machine, so the same
/// binary refuses different functions under load and a census cannot be
/// reproduced. Every phase already reports through one `poll`, so counting
/// those polls measures the same thing the clock was standing in for and
/// measures it identically on every run.
#[derive(Debug, Default)]
pub struct SsaWorkMeter {
    polls: AtomicU64,
    limit: Option<u64>,
}

impl SsaWorkMeter {
    /// A meter that also stops the run once `limit` units are spent.
    pub fn with_limit(limit: u64) -> Self {
        Self {
            polls: AtomicU64::new(0),
            limit: Some(limit),
        }
    }

    /// Count one unit of work and return the running total.
    pub fn spend(&self) -> u64 {
        self.polls.fetch_add(1, Ordering::Relaxed).saturating_add(1)
    }

    /// Work counted so far.
    pub fn spent(&self) -> u64 {
        self.polls.load(Ordering::Relaxed)
    }

    /// The units this run may spend, where it is bounded.
    pub fn limit(&self) -> Option<u64> {
        self.limit
    }

    fn exhausted(&self, spent: u64) -> bool {
        self.limit.is_some_and(|limit| spent >= limit)
    }
}

/// Cloneable cancellation token shared by SSA preparation callers.
#[derive(Debug, Clone, Default)]
pub struct SsaCancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl SsaCancellationToken {
    /// Request cooperative cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Why controlled SSA preparation stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SsaExecutionStopReason {
    Cancelled,
    DeadlineExceeded,
    /// The run spent the work its captured input allows. Counted rather than
    /// timed, so the same input stops at the same place on every machine.
    WorkExhausted,
}

impl std::fmt::Display for SsaExecutionStopReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Cancelled => "SSA preparation cancelled",
            Self::DeadlineExceeded => "SSA preparation deadline exceeded",
            Self::WorkExhausted => "SSA preparation exhausted the work its input allows",
        })
    }
}

impl std::error::Error for SsaExecutionStopReason {}

/// Error returned by checked SSA builders.
///
/// Malformed source input remains distinct from cooperative cancellation and
/// deadline expiry. Optimization iteration caps are normal, valid completion
/// bounds and are still reported through [`crate::OptimizationStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsaPrepareError {
    MalformedInput,
    Cancelled,
    DeadlineExceeded,
    WorkExhausted,
}

impl std::fmt::Display for SsaPrepareError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::MalformedInput => "malformed SSA source input",
            Self::Cancelled => "SSA preparation cancelled",
            Self::DeadlineExceeded => "SSA preparation deadline exceeded",
            Self::WorkExhausted => "SSA preparation exhausted the work its input allows",
        })
    }
}

impl std::error::Error for SsaPrepareError {}

impl From<SsaExecutionStopReason> for SsaPrepareError {
    fn from(reason: SsaExecutionStopReason) -> Self {
        match reason {
            SsaExecutionStopReason::Cancelled => Self::Cancelled,
            SsaExecutionStopReason::DeadlineExceeded => Self::DeadlineExceeded,
            SsaExecutionStopReason::WorkExhausted => Self::WorkExhausted,
        }
    }
}

/// Allocation-free polling seam used by checked SSA worklists.
///
/// The trait permits deterministic callers and tests without requiring a
/// thread, timer callback, or allocation at each poll.
pub trait SsaWorkControl {
    fn poll(&self) -> Result<(), SsaExecutionStopReason>;
}

/// Cloneable cancellation/deadline control for SSA preparation.
#[derive(Debug, Clone, Default)]
pub struct SsaExecutionControl {
    cancellation: SsaCancellationToken,
    deadline: Option<Instant>,
    meter: Option<Arc<SsaWorkMeter>>,
}

impl SsaExecutionControl {
    /// Build a control that observes both cancellation and a deadline.
    pub fn new(cancellation: SsaCancellationToken, deadline: Option<Instant>) -> Self {
        Self {
            cancellation,
            deadline,
            meter: None,
        }
    }

    /// Count this run's work into `meter`, so what the deadline is standing in
    /// for can be measured against the body's own size.
    #[must_use]
    pub fn metered(mut self, meter: Arc<SsaWorkMeter>) -> Self {
        self.meter = Some(meter);
        self
    }

    /// The meter this run counts into.
    pub fn meter(&self) -> Option<&Arc<SsaWorkMeter>> {
        self.meter.as_ref()
    }

    pub fn with_cancellation(cancellation: SsaCancellationToken) -> Self {
        Self::new(cancellation, None)
    }

    pub fn with_deadline(deadline: Instant) -> Self {
        Self::new(SsaCancellationToken::default(), Some(deadline))
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self::with_deadline(
            Instant::now()
                .checked_add(timeout)
                .unwrap_or_else(Instant::now),
        )
    }

    pub fn cancellation(&self) -> SsaCancellationToken {
        self.cancellation.clone()
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub fn stop_reason(&self) -> Option<SsaExecutionStopReason> {
        if self.cancellation.is_cancelled() {
            return Some(SsaExecutionStopReason::Cancelled);
        }
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
            .then_some(SsaExecutionStopReason::DeadlineExceeded)
    }
}

impl SsaWorkControl for SsaExecutionControl {
    fn poll(&self) -> Result<(), SsaExecutionStopReason> {
        if let Some(meter) = &self.meter
            && meter.exhausted(meter.spend())
        {
            return Err(SsaExecutionStopReason::WorkExhausted);
        }
        self.stop_reason().map_or(Ok(()), Err)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct UncheckedSsaWorkControl;

impl SsaWorkControl for UncheckedSsaWorkControl {
    #[inline]
    fn poll(&self) -> Result<(), SsaExecutionStopReason> {
        Ok(())
    }
}
