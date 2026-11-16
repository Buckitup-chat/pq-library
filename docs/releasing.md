# Releasing @buckitup/pq-client

The first public version is `1.0.0`. Package metadata, changelog and `LICENSE`
use GPL-3.0-only, following the original
[Partner Venue Messaging specification](https://github.com/Buckitup-chat/chat/blob/docs/partner-venue-messaging/docs/pq/reqs/pq_partner_venue_messaging.proposed.md#client-library).
The approved repository split changes source ownership, not the wire protocol.

## Toolchain

Development and all SDK workflow jobs use Node 22.23.1 (`.nvmrc`). The package
requires Node >=22.14.0. The publish job installs npm 11, which must be >=11.5.1
for trusted publishing. Consumers of the browser bundle do not run Node.

## Release prerequisites

- Publish access to the npm `@buckitup` organization and this package name.
- Reviewed source on `main`, with SDK CI green and a matching changelog section.
- GitHub environment `npm-release`, reviewers and branch restrictions, if using
  the workflow publish job. These settings are external to the YAML.
- Full partner acceptance remains a separate requirement. Current backend
  concurrency limits are documented in [backend dependencies](backend-dependencies.md);
  a successful package build does not close them.

## Check the exact artifact

```sh
node --version
npm ci --legacy-peer-deps
npm run typecheck
npm run lint
npm test
npm run build
mkdir -p /tmp/pq-pack
npm pack --pack-destination /tmp/pq-pack
npm run check:consumer -- /tmp/pq-pack/buckitup-pq-client-1.0.0.tgz --browser
npm publish /tmp/pq-pack/buckitup-pq-client-1.0.0.tgz --dry-run --access public --tag latest
```

The tarball contains `dist`, `LICENSE`, `README.md`, `CHANGELOG.md` and
`package.json`. The package needs no frontend checkout. Browser verification
requires Playwright Chromium (`npx playwright install chromium`) and uses a
virtual PRF authenticator; it does not replace real-device or live-server acceptance.

## First publication

Trusted publishing is configured against an existing npm package. For a new
package, an authorized maintainer can make the first publication interactively
with 2FA, using the reviewed artifact:

```sh
npm login
npm whoami
npm publish /tmp/pq-pack/buckitup-pq-client-1.0.0.tgz --access public --tag latest
```

Alternatively use npm staged publishing with the supported Node/npm versions
and human approval. Do not execute both first-publication paths. A dry run
does not establish registry permissions or create the package.

## Subsequent workflow releases

Configure the npm trusted publisher for `Buckitup-chat/pq-library`, workflow
`release-pq-client.yml`, environment `npm-release`, with publishing allowed.
The workflow uses OIDC (`id-token: write`); no npm token is needed in this mode.
The existing `NPM_TOKEN` fallback, if used, must have current publish permissions.

1. Prepare the new version and dated changelog entry in a PR.
2. Run the release workflow with matching version/tag and `publish: false`.
   Verification builds and checks a tarball consumer, then uploads the artifact.
3. For a version not already published, run with `publish: true` from `main`.
   The environment approval gates the publish job.
4. Confirm the registry version, install it in consumers, then record the release tag.

Stable versions use `latest`; `X.Y.Z-rc.N` versions use `next`. Protocol or
derivation changes require a major version and partner notification, as in the
specification. Published versions are immutable; release a new version to fix one.

After first publication, the frontend replaces its temporary tarball dependency
with the exact npm version and runs its integration checks.
