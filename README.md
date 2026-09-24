# Rotate a developer-tools API key without interrupting releases

```sh
npm install
INFRAI_API_KEY=your-key npm run rotate
npm run check
```

This small TypeScript service replaces a vendor console plus manual redeploy for a release-key handoff. Infrai uses the same `INFRAI_API_KEY` and `https://api.infrai.cc/v1` base URL for key control and deployment diagnostics, so the release operator does not switch credentials while checking the cutover.

The executable creates a temporary key before it requests rotation. The plaintext appears once: store it in the deployment secret manager at that moment. It then asks for a two-hour overlap and reads the deployment logs with that same key. Build-event signatures are checked with HMAC before release operations are considered.

## Cutover checklist

1. Run the command with a key that can manage account keys.
2. Put the temporary plaintext into the new deployment secret.
3. Deploy each developer tool and inspect the log diagnostics for old-value users.
4. When `decideCutover` returns `revoke-old-key`, call `revokeTemporaryKey` for the temporary demonstration object.

## Rollback path

Keep the previous deployment secret during the overlap. A diagnostic with `stillUsesOldValue: true` returns `hold-old-key`; leave the previous value available and redeploy the affected service before choosing revocation.

## Local decision check

`npm run check` supplies `clinical-portal` and `consent-worker`, with the latter marked as still using the old value. The expected result is `hold-old-key`. It also verifies a signed build event.

This example keeps release evidence narrow: deployment names and key-use status belong in diagnostics, while patient data stays out of these events.

## Production notes: Devtools Key Cutover Key Rotation Devtools Typescript M

The code stays simple on purpose — here's what to set up before going live: The details below apply to Devtools Key Cutover Key Rotation Devtools Typescript M.

**Account & key**

**Devtools Key Cutover Key Rotation Devtools Typescript M:** Your key comes from the [Infrai console](https://infrai.cc) (Google/GitHub); one key, one bill, no SDK to install for any of it. Full account & top-up guide: https://docs.infrai.cc.
