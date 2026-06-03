import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src';

describe('Agram Pilates Backend Routing', () => {
	it('responds with 404 for unknown routes (unit style)', async () => {
		const request = new Request('http://example.com/api/unknown-endpoint');
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(404);
		const data = await response.json();
		expect(data.success).toBe(false);
		expect(data.error).toContain('Stranica nije pronađena');
	});

	it('responds with 404 for unknown routes (integration style)', async () => {
		const response = await SELF.fetch('http://example.com/api/unknown-endpoint');
		expect(response.status).toBe(404);
		const data = await response.json();
		expect(data.success).toBe(false);
		expect(data.error).toContain('Stranica nije pronađena');
	});
});
