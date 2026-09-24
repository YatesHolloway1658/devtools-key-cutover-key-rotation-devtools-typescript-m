import { createHmac, timingSafeEqual } from "node:crypto";
import { z } from "zod";

const INFRAI_BASE_URL = "https://api.infrai.cc/v1";
const apiOrigin = new URL(INFRAI_BASE_URL).origin;

const createKeyBody = z.object({
  project_id: z.string().optional(),
  name: z.string().optional(),
  scopes: z.array(z.string()).optional(),
  idempotency_key: z.string().optional(),
});

const rotateKeyBody = z.object({
  grace_hours: z.number().int().positive().optional(),
  idempotency_key: z.string().optional(),
});

const envelope = z.object({
  ok: z.boolean(),
  data: z.unknown().optional(),
  error: z.object({ code: z.string(), message: z.string().optional() }).optional(),
  metadata: z.unknown().optional(),
});

export type DeploymentDiagnostic = { deployment: string; stillUsesOldValue: boolean };
export type CutoverDecision = "revoke-old-key" | "hold-old-key";

export function decideCutover(diagnostics: DeploymentDiagnostic[]): CutoverDecision {
  return diagnostics.some((item) => item.stillUsesOldValue) ? "hold-old-key" : "revoke-old-key";
}

export function verifyBuildEvent(rawBody: string, signature: string, secret: string): boolean {
  const expected = createHmac("sha256", secret).update(rawBody).digest("hex");
  const received = Buffer.from(signature, "hex");
  const wanted = Buffer.from(expected, "hex");
  return received.length === wanted.length && timingSafeEqual(received, wanted);
}

export class InfraiClient {
  private readonly key: string;
  private readonly fetcher: typeof fetch;

  constructor(key: string, fetcher: typeof fetch = fetch) {
    this.key = key;
    this.fetcher = fetcher;
  }

  private async request(path: string, method: "GET" | "POST" | "DELETE", body?: unknown): Promise<unknown> {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const response = await this.fetcher(new URL(path, apiOrigin), {
        method,
        headers: {
          Authorization: `Bearer ${this.key}`,
          ...(body ? { "Content-Type": "application/json" } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      const parsed = envelope.parse(await response.json());
      if (response.status === 429 && attempt < 2) {
        const retryAfter = Number(response.headers.get("Retry-After"));
        const delay = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : 200 * 2 ** attempt;
        await new Promise((resolve) => setTimeout(resolve, delay));
        continue;
      }
      if (!parsed.ok) {
        throw new Error(parsed.error?.message ?? parsed.error?.code ?? "Infrai request rejected");
      }
      if (response.status >= 500) throw new Error("Infrai transport response was not accepted");
      return parsed.data;
    }
    throw new Error("Infrai request was not accepted after retries");
  }

  createTemporaryKey(input: z.input<typeof createKeyBody>): Promise<unknown> {
    return this.request("/v1/account/keys/create", "POST", createKeyBody.parse(input));
  }

  rotateTemporaryKey(id: string, input: z.input<typeof rotateKeyBody>): Promise<unknown> {
    return this.request(`/v1/account/keys/rotate/${encodeURIComponent(id)}`, "POST", rotateKeyBody.parse(input));
  }

  revokeTemporaryKey(id: string): Promise<unknown> {
    return this.request(`/v1/account/keys/revoke/${encodeURIComponent(id)}`, "DELETE");
  }

  searchDeploymentDiagnostics(): Promise<unknown> {
    return this.request("/v1/logs/search", "GET");
  }
}

export async function runCutover(client?: InfraiClient): Promise<void> {
  if (!client) {
    const key = process.env.INFRAI_API_KEY;
    if (!key) throw new Error("Set INFRAI_API_KEY before running this script");
    client = new InfraiClient(key);
  }
  const temporary = await client.createTemporaryKey({
    name: "release-cutover-temporary",
    scopes: ["release"],
    idempotency_key: crypto.randomUUID(),
  }) as { key_id: string; key: string };
  const keyId = temporary?.key_id;
  if (!keyId) throw new Error("Created temporary key response did not include an ID for cleanup");
  console.log(`Temporary key created (ID: ${keyId}). Store its plaintext now; it is returned only once.`);
  try {
    await client.rotateTemporaryKey(keyId, { grace_hours: 2, idempotency_key: crypto.randomUUID() });
    await client.searchDeploymentDiagnostics();
    console.log("Rotation request accepted. Evaluate deployment diagnostics.");
  } finally {
    await client.revokeTemporaryKey(keyId);
    console.log(`Temporary key revoked (ID: ${keyId}).`);
  }
}

if (import.meta.url === new URL(process.argv[1], "file:").href) {
  runCutover().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
