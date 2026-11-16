import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const TYPESCRIPT = process.env.CONSUMER_TYPESCRIPT ?? '5.7.3';
const here = path.dirname(fileURLToPath(import.meta.url));
const sources = path.join(here, '..', 'consumer');

const args = process.argv.slice(2);
const browser = args.includes('--browser');
const tarball = args.find((a) => !a.startsWith('--'));
if (!tarball) {
	console.error('usage: consumer-check <path to buckitup-pq-client-*.tgz> [--browser]');
	process.exit(2);
}

const dir = mkdtempSync(path.join(tmpdir(), 'pq-client-consumer-'));
const run = (cmd: string, args: string[]) => {
	console.log(`$ ${cmd} ${args.join(' ')}`);
	execFileSync(cmd, args, { cwd: dir, stdio: 'inherit' });
};
const tsconfig = (name: string, compilerOptions: Record<string, unknown>, files: string[]) =>
	writeFileSync(path.join(dir, name), JSON.stringify({ compilerOptions, files }, null, 2));

const strict = { strict: true, skipLibCheck: false, target: 'ES2022', types: ['node'] };

try {
	writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'pq-client-consumer', private: true, type: 'module' }));
	copyFileSync(path.join(sources, 'smoke.ts'), path.join(dir, 'smoke.ts'));
	copyFileSync(path.join(sources, 'node-only.ts'), path.join(dir, 'node-only.ts'));
	run('npm', ['install', path.resolve(tarball), `typescript@${TYPESCRIPT}`, '@types/node@20', '--no-audit', '--no-fund']);

	tsconfig('tsconfig.nodenext.json', { ...strict, lib: ['ES2022', 'DOM'], module: 'NodeNext', moduleResolution: 'NodeNext', outDir: 'out' }, ['smoke.ts']);
	tsconfig('tsconfig.bundler.json', { ...strict, lib: ['ES2022', 'DOM'], module: 'ESNext', moduleResolution: 'Bundler', noEmit: true }, ['smoke.ts']);
	tsconfig('tsconfig.node-only.json', { ...strict, lib: ['ES2022'], module: 'NodeNext', moduleResolution: 'NodeNext', noEmit: true }, ['node-only.ts']);

	run('npx', ['tsc', '-p', 'tsconfig.bundler.json']);
	run('npx', ['tsc', '-p', 'tsconfig.node-only.json']);
	run('npx', ['tsc', '-p', 'tsconfig.nodenext.json']);
	run('node', ['out/smoke.js']);
	if (browser) await browserCheck();
	console.log(`consumer check passed (${dir})`);
	rmSync(dir, { recursive: true, force: true });
} catch (e) {
	console.error(`consumer check failed; the consumer is kept at ${dir}`);
	throw e;
}

async function browserCheck(): Promise<void> {
	copyFileSync(path.join(sources, 'browser.ts'), path.join(dir, 'browser.ts'));
	run('npm', ['install', 'esbuild@0.24.2', '--no-audit', '--no-fund']);
	writeFileSync(path.join(dir, 'build-browser.mjs'), `
import { build } from 'esbuild';
import path from 'node:path';
await build({
	entryPoints: ['browser.ts'], bundle: true, format: 'esm', platform: 'browser', outfile: 'out/browser.js',
	plugins: [{ name: 'libsodium-sibling', setup(b) {
		b.onResolve({ filter: /^\\.\\/libsodium\\.mjs$/ }, (a) => a.importer.includes('libsodium-wrappers')
			? { path: path.resolve('node_modules/libsodium/dist/modules-esm/libsodium.mjs') } : undefined);
	} }],
});
`);
	run('node', ['build-browser.mjs']);

	const { chromium } = createRequire(path.join(here, '..', 'package.json'))('playwright') as typeof import('playwright');
	const bundle = path.join(dir, 'out', 'browser.js');
	const server = http.createServer((req, res) => {
		if (req.url === '/') {
			res.setHeader('content-type', 'text/html');
			return res.end('<!doctype html><script type="module" src="/browser.js"></script>');
		}
		if (req.url !== '/browser.js' || !existsSync(bundle)) {
			res.statusCode = 404;
			return res.end();
		}
		res.setHeader('content-type', 'text/javascript');
		res.end(readFileSync(bundle));
	});
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	const { port } = server.address() as { port: number };
	const instance = await chromium.launch();
	try {
		const page = await instance.newPage();
		const cdp = await page.context().newCDPSession(page);
		await cdp.send('WebAuthn.enable');
		await cdp.send('WebAuthn.addVirtualAuthenticator', {
			options: {
				protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
				isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true,
			},
		});
		await page.goto(`http://localhost:${port}/`);
		const checks = await page.evaluate(() => (window as unknown as { __checks: Promise<Array<[string, unknown]>> }).__checks);
		console.log(`chromium ${instance.version()} (virtual WebAuthn authenticator with PRF):`, JSON.stringify(checks));
		const failed = checks.filter(([, ok]) => ok !== true);
		if (failed.length || checks.length !== 3) throw new Error(`browser check failed: ${JSON.stringify(failed)}`);
	} finally {
		await instance.close();
		server.close();
	}
}
