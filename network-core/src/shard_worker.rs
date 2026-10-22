use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex, Semaphore, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::shard::{
    ShardDescriptor,
    ShardId,
    ShardKind,
    ShardState,
    ShardTrustState,
};

/// Maximum permitted size of a shard work payload.
pub const MAX_SHARD_WORK_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Maximum permitted length of a work identifier.
pub const MAX_SHARD_WORK_ID_BYTES: usize = 128;

/// Maximum number of work items buffered by the worker.
pub const DEFAULT_SHARD_WORK_QUEUE_CAPACITY: usize = 256;

/// Default execution deadline.
pub const DEFAULT_SHARD_WORK_TIMEOUT: Duration =
    Duration::from_secs(30);

/// Errors produced by the shard worker.
#[derive(Debug, Error)]
pub enum ShardWorkerError {
    #[error("Invalid work request: {0}")]
    InvalidRequest(String),

    #[error("Worker is not accepting work")]
    WorkerUnavailable,

    #[error("Worker queue is full")]
    QueueFull,

    #[error("Work item was cancelled")]
    Cancelled,

    #[error("Work item exceeded its execution deadline")]
    Timeout,

    #[error("No executor is registered for shard kind {0:?}")]
    ExecutorUnavailable(ShardKind),

    #[error("Shard is not eligible to execute work")]
    ShardNotEligible,

    #[error("Executor failed: {0}")]
    ExecutionFailed(String),

    #[error("Worker shutdown failed: {0}")]
    ShutdownFailed(String),

    #[error("System clock returned an invalid timestamp")]
    ClockError,
}

/// Result type used by the shard worker.
pub type ShardWorkerResult<T> = Result<T, ShardWorkerError>;

/// Boxed asynchronous execution future.
pub type ShardExecutionFuture<'a> =
    Pin<Box<dyn Future<Output = ShardWorkerResult<ShardWorkOutput>>
        + Send
        + 'a>>;

/// Describes the execution environment available to a shard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardExecutionContext {
    pub shard_id: ShardId,
    pub shard_kind: ShardKind,
    pub work_id: String,
    pub deadline_unix_ms: u64,
}

/// Work submitted to a shard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardWorkItem {
    pub work_id: String,
    pub target_shard_id: ShardId,
    pub required_kind: ShardKind,
    pub payload: Vec<u8>,
    pub deadline_unix_ms: u64,
    pub submitted_at_unix_ms: u64,
}

impl ShardWorkItem {
    /// Construct and validate a work item.
    pub fn new(
        work_id: impl Into<String>,
        target_shard_id: ShardId,
        required_kind: ShardKind,
        payload: Vec<u8>,
        deadline_unix_ms: u64,
    ) -> ShardWorkerResult<Self> {
        let item = Self {
            work_id: work_id.into(),
            target_shard_id,
            required_kind,
            payload,
            deadline_unix_ms,
            submitted_at_unix_ms: current_time_ms()?,
        };

        item.validate()?;

        Ok(item)
    }

    /// Validate the work item's basic limits.
    pub fn validate(&self) -> ShardWorkerResult<()> {
        if self.work_id.trim().is_empty() {
            return Err(ShardWorkerError::InvalidRequest(
                "work_id cannot be empty".to_string(),
            ));
        }

        if self.work_id.len() > MAX_SHARD_WORK_ID_BYTES {
            return Err(ShardWorkerError::InvalidRequest(
                "work_id exceeds the permitted length".to_string(),
            ));
        }

        if self.payload.len() > MAX_SHARD_WORK_PAYLOAD_BYTES {
            return Err(ShardWorkerError::InvalidRequest(
                "payload exceeds the permitted size".to_string(),
            ));
        }

        if self.deadline_unix_ms <= self.submitted_at_unix_ms {
            return Err(ShardWorkerError::InvalidRequest(
                "deadline must be later than submission time".to_string(),
            ));
        }

        Ok(())
    }
}

/// Output produced by a real shard executor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardWorkOutput {
    pub work_id: String,
    pub payload: Vec<u8>,
    pub completed_at_unix_ms: u64,
}

/// Current status of a submitted work item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardWorkStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
}

/// Execution result metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardWorkReceipt {
    pub work_id: String,
    pub shard_id: ShardId,
    pub status: ShardWorkStatus,
    pub submitted_at_unix_ms: u64,
    pub started_at_unix_ms: Option<u64>,
    pub completed_at_unix_ms: Option<u64>,
    pub error: Option<String>,
}

/// Defines a concrete executor for a shard kind.
///
/// Implementations must perform the actual operation associated with
/// their shard kind. They must return an error when they cannot complete
/// the requested operation.
///
/// This interface deliberately does not supply fake networking behavior.
pub trait ShardExecutor: Send + Sync + 'static {
    fn kind(&self) -> ShardKind;

    fn execute<'a>(
        &'a self,
        context: ShardExecutionContext,
        work: ShardWorkItem,
    ) -> ShardExecutionFuture<'a>;
}

/// Worker configuration.
#[derive(Debug, Clone)]
pub struct ShardWorkerConfig {
    pub queue_capacity: usize,
    pub max_concurrent_work: usize,
    pub default_timeout: Duration,
}

impl Default for ShardWorkerConfig {
    fn default() -> Self {
        Self {
            queue_capacity: DEFAULT_SHARD_WORK_QUEUE_CAPACITY,
            max_concurrent_work: 4,
            default_timeout: DEFAULT_SHARD_WORK_TIMEOUT,
        }
    }
}

/// Internal queued work item.
struct QueuedWork {
    item: ShardWorkItem,
    response: oneshot::Sender<ShardWorkerResult<ShardWorkOutput>>,
}

/// A shard worker accepts bounded work and delegates it to a concrete
/// executor.
///
/// The worker is intentionally unable to execute anything until an
/// appropriate executor is supplied.
pub struct ShardWorker {
    descriptor: ShardDescriptor,
    config: ShardWorkerConfig,
    sender: mpsc::Sender<QueuedWork>,
    shutdown: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    join_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl ShardWorker {
    /// Start a worker for a shard using a concrete executor.
    ///
    /// The descriptor must identify a trusted, assigned shard. The
    /// executor must match the descriptor's kind.
    pub fn start(
        descriptor: ShardDescriptor,
        config: ShardWorkerConfig,
        executor: Arc<dyn ShardExecutor>,
    ) -> ShardWorkerResult<Self> {
        validate_descriptor(&descriptor)?;

        if executor.kind() != descriptor.kind {
            return Err(ShardWorkerError::InvalidRequest(
                "executor kind does not match shard kind".to_string(),
            ));
        }

        if config.queue_capacity == 0 {
            return Err(ShardWorkerError::InvalidRequest(
                "queue_capacity must be greater than zero".to_string(),
            ));
        }

        if config.max_concurrent_work == 0 {
            return Err(ShardWorkerError::InvalidRequest(
                "max_concurrent_work must be greater than zero".to_string(),
            ));
        }

        let (sender, receiver) =
            mpsc::channel::<QueuedWork>(config.queue_capacity);

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let semaphore =
            Arc::new(Semaphore::new(config.max_concurrent_work));

        let worker_descriptor = descriptor.clone();
        let worker_config = config.clone();

        let join_handle = tokio::spawn(async move {
            run_worker(
                worker_descriptor,
                worker_config,
                executor,
                receiver,
                shutdown_rx,
                semaphore,
            )
            .await;
        });

        Ok(Self {
            descriptor,
            config,
            sender,
            shutdown: Arc::new(Mutex::new(Some(shutdown_tx))),
            join_handle: Arc::new(Mutex::new(Some(join_handle))),
        })
    }

    /// Return the worker's shard identifier.
    pub fn shard_id(&self) -> &ShardId {
        &self.descriptor.id
    }

    /// Return the shard kind.
    pub fn shard_kind(&self) -> ShardKind {
        self.descriptor.kind
    }

    /// Return worker configuration.
    pub fn config(&self) -> &ShardWorkerConfig {
        &self.config
    }

    /// Submit work and wait for its execution result.
    ///
    /// An error is returned if the queue is closed, the work expires,
    /// or the concrete executor fails.
    pub async fn submit(
        &self,
        item: ShardWorkItem,
    ) -> ShardWorkerResult<ShardWorkOutput> {
        item.validate()?;

        if item.target_shard_id != self.descriptor.id {
            return Err(ShardWorkerError::InvalidRequest(
                "work targets a different shard".to_string(),
            ));
        }

        if item.required_kind != self.descriptor.kind {
            return Err(ShardWorkerError::InvalidRequest(
                "work kind does not match worker kind".to_string(),
            ));
        }

        if current_time_ms()? >= item.deadline_unix_ms {
            return Err(ShardWorkerError::Timeout);
        }

        let (response_tx, response_rx) = oneshot::channel();

        self.sender
            .send(QueuedWork {
                item,
                response: response_tx,
            })
            .await
            .map_err(|_| ShardWorkerError::WorkerUnavailable)?;

        response_rx
            .await
            .map_err(|_| ShardWorkerError::WorkerUnavailable)?
    }

    /// Request graceful shutdown and wait for the worker loop to exit.
    pub async fn shutdown(&self) -> ShardWorkerResult<()> {
        if let Some(shutdown_tx) = self.shutdown.lock().await.take() {
            let _ = shutdown_tx.send(());
        }

        if let Some(handle) = self.join_handle.lock().await.take() {
            handle
                .await
                .map_err(|error| {
                    ShardWorkerError::ShutdownFailed(
                        error.to_string(),
                    )
                })?;
        }

        Ok(())
    }
}

fn validate_descriptor(
    descriptor: &ShardDescriptor,
) -> ShardWorkerResult<()> {
    if descriptor.trust_state != ShardTrustState::Verified {
        return Err(ShardWorkerError::ShardNotEligible);
    }

    if descriptor.assignment.is_none() {
        return Err(ShardWorkerError::ShardNotEligible);
    }

    if descriptor.state != ShardState::Running {
        return Err(ShardWorkerError::ShardNotEligible);
    }

    Ok(())
}

async fn run_worker(
    descriptor: ShardDescriptor,
    config: ShardWorkerConfig,
    executor: Arc<dyn ShardExecutor>,
    mut receiver: mpsc::Receiver<QueuedWork>,
    mut shutdown: oneshot::Receiver<()>,
    semaphore: Arc<Semaphore>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                receiver.close();

                while let Some(queued) = receiver.recv().await {
                    let _ = queued.response.send(
                        Err(ShardWorkerError::WorkerUnavailable)
                    );
                }

                break;
            }

            message = receiver.recv() => {
                let Some(queued) = message else {
                    break;
                };

                let descriptor = descriptor.clone();
                let executor = Arc::clone(&executor);
                let semaphore = Arc::clone(&semaphore);
                let timeout_duration = config.default_timeout;

                tokio::spawn(async move {
                    let QueuedWork { item, response } = queued;

                    let remaining_ms = item
                        .deadline_unix_ms
                        .saturating_sub(
                            current_time_ms().unwrap_or(
                                item.deadline_unix_ms
                            )
                        );

                    if remaining_ms == 0 {
                        let _ = response.send(
                            Err(ShardWorkerError::Timeout)
                        );
                        return;
                    }

                    let deadline_duration = Duration::from_millis(
                        remaining_ms
                    ).min(timeout_duration);

                    let permit = match semaphore.acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => {
                            let _ = response.send(
                                Err(ShardWorkerError::WorkerUnavailable)
                            );
                            return;
                        }
                    };

                    let context = ShardExecutionContext {
                        shard_id: descriptor.id.clone(),
                        shard_kind: descriptor.kind,
                        work_id: item.work_id.clone(),
                        deadline_unix_ms: item.deadline_unix_ms,
                    };

                    let result = timeout(
                        deadline_duration,
                        executor.execute(context, item),
                    ).await;

                    drop(permit);

                    let result = match result {
                        Ok(execution_result) => execution_result,
                        Err(_) => Err(ShardWorkerError::Timeout),
                    };

                    let _ = response.send(result);
                });
            }
        }
    }
}

fn current_time_ms() -> ShardWorkerResult<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ShardWorkerError::ClockError)?;

    Ok(elapsed.as_millis().min(u64::MAX as u128) as u64)
}
