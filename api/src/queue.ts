/**
 * Minimal in-process job queue used as a dependency-free stand-in for
 * BullMQ/Redis in local development. It mirrors just enough of BullMQ's
 * shape (add/consume) that swapping in a real BullMQ+ioredis backed queue
 * later would be a drop-in replacement.
 */
export interface QueuedJob<T> {
  id: string;
  data: T;
}

class InProcessQueue<T> {
  private jobs: QueuedJob<T>[] = [];

  add(id: string, data: T): void {
    this.jobs.push({ id, data });
  }

  /** Removes and returns all currently queued jobs. */
  drain(): QueuedJob<T>[] {
    const drained = this.jobs;
    this.jobs = [];
    return drained;
  }

  size(): number {
    return this.jobs.length;
  }
}

export interface ConfigJobMessage {
  jobId: string;
  deviceId: string;
}

export const configJobQueue = new InProcessQueue<ConfigJobMessage>();

/** One message per plan execution request (see workers/planExecutor.ts). */
export interface PlanExecutionMessage {
  planId: string;
}

export const planQueue = new InProcessQueue<PlanExecutionMessage>();
