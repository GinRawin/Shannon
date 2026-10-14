/** A workflow-local queue for analysis activities, independent of exploitation. */
export function createAnalysisScheduler(serial: boolean): <T>(run: () => Promise<T>) => Promise<T> {
  let tail: Promise<void> = Promise.resolve();
  return <T>(run: () => Promise<T>): Promise<T> => {
    if (!serial) return run();
    // Invoke the activity only once its slot is available, so waiting in this
    // workflow queue does not consume the activity's StartToClose timeout.
    const result = tail.then(run);
    tail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  };
}
