// Generic test helpers: bounded poll-until (poll, never blind sleeps).
export const delay = (ms: number): Promise<void> => {
  const { promise, resolve } = Promise.withResolvers<void>();
  setTimeout(resolve, ms);
  return promise;
};

/** Poll `done` every `everyMs` until true; fail after `deadlineMs`. */
export async function pollUntil(done: () => boolean | Promise<boolean>, deadlineMs = 5000, everyMs = 25): Promise<void> {
  const deadline = Date.now() + deadlineMs;
  while (!(await done())) {
    if (Date.now() > deadline) throw new Error(`condition not met within ${deadlineMs}ms`);
    await delay(everyMs);
  }
}
