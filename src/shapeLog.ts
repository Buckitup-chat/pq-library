export type ShapeOperation = 'insert' | 'update' | 'delete';

export interface ShapeMessage<T> {
	key?: string;
	value?: T;
	headers?: { operation?: ShapeOperation; control?: string; [header: string]: unknown };
}

export interface ShapeChange<T> {
	operation: ShapeOperation;
	key: string;
	value: T | null;
}

export const isControl = (message: ShapeMessage<unknown>, control: string): boolean => message?.headers?.control === control;

let unkeyed = 0;

export const applyShapeMessages = <T>(rows: Map<string, T>, messages: ShapeMessage<T>[]): ShapeChange<T>[] => {
	const changes: ShapeChange<T>[] = [];
	for (const message of messages) {
		if (!message || message.headers?.control) continue;
		const key = typeof message.key === 'string' ? message.key : `#${++unkeyed}`;
		const operation = message.headers?.operation ?? 'insert';
		if (operation === 'delete') {
			rows.delete(key);
			changes.push({ operation, key, value: null });
			continue;
		}
		if (message.value === null || message.value === undefined) continue;
		const previous = rows.get(key);
		const value = operation === 'update' && previous ? ({ ...previous, ...message.value } as T) : message.value;
		rows.set(key, value);
		changes.push({ operation, key, value });
	}
	return changes;
};
