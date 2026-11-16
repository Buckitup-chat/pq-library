export const withTimeout = (signal: AbortSignal, timeoutMs: number): AbortSignal => {
	const any = (AbortSignal as unknown as { any?: (signals: AbortSignal[]) => AbortSignal }).any;
	return any ? any([signal, AbortSignal.timeout(timeoutMs)]) : signal;
};

export const abortableDelay = (ms: number, signal: AbortSignal): Promise<void> =>
	new Promise((resolve) => {
		if (signal.aborted) return resolve();
		const timer = setTimeout(done, ms);
		function done() {
			clearTimeout(timer);
			signal.removeEventListener('abort', done);
			resolve();
		}
		signal.addEventListener('abort', done, { once: true });
	});
