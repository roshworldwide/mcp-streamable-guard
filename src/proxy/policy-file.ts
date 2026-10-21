import fs from "node:fs";
import { parse as parseYaml } from "yaml";
import { z } from "zod";

/**
 * The proxy's policy file. It says which upstream tools are physical and how
 * the guard's inputs are read; everything else passes straight through.
 *
 *   physical:
 *     unlock_door: { door_arg: door_id }   # the pass must be for the door the call names
 *     open_garage: { door: garage }        # or a fixed door
 *   approvers: [homeowner, caregiver]
 *   timezone: America/Los_Angeles
 *   night: "22:00-06:00"
 *   presence: ring
 *   rate: { max: 5, minutes: 10 }
 */
const DoorRule = z
  .object({
    door: z.string().min(1).max(40).optional(),
    door_arg: z.string().min(1).max(64).optional(),
  })
  .strict()
  .refine((r) => (r.door ? 1 : 0) + (r.door_arg ? 1 : 0) === 1, { message: "give exactly one of door (a fixed door) or door_arg (the argument that names the door)" });

const Clock = /^([01]\d|2[0-3]):([0-5]\d)$/;

export const PolicySchema = z
  .object({
    /** Tool name -> which door it acts on. Only these tools go through the guard. */
    physical: z.record(z.string().min(1).max(128), DoorRule).refine((p) => Object.keys(p).length > 0, { message: "list at least one physical tool" }),
    /** Roles whose phones are asked to approve (MCP elicitation). */
    approvers: z.array(z.enum(["homeowner", "caregiver"])).min(1).default(["homeowner", "caregiver"]),
    timezone: z
      .string()
      .default("UTC")
      .refine((tz) => {
        try {
          new Intl.DateTimeFormat("en-US", { timeZone: tz });
          return true;
        } catch {
          return false;
        }
      }, { message: "not a known IANA time zone" }),
    /** Night mode window in local time, "HH:MM-HH:MM" (may wrap midnight), or "off". */
    night: z
      .string()
      .default("22:00-06:00")
      .refine((s) => s === "off" || (s.split("-").length === 2 && s.split("-").every((p) => Clock.test(p.trim()))), { message: 'use "HH:MM-HH:MM" or "off"' }),
    /** How the guard knows someone is at the door: a Ring-signed webhook to /ring/webhook, or always (weaker). */
    presence: z.enum(["ring", "always"]).default("ring"),
    presence_seconds: z.number().int().min(10).max(3600).default(120),
    rate: z.object({ max: z.number().int().min(1).max(1000), minutes: z.number().int().min(1).max(1440) }).strict().default({ max: 5, minutes: 10 }),
    /** An approval counts for this many seconds. */
    approval_seconds: z.number().int().min(5).max(600).default(60),
    /** How long a phone has to answer. */
    approval_timeout_seconds: z.number().int().min(5).max(600).default(45),
    /** Wrong codes before a pass is revoked. */
    max_wrong_codes: z.number().int().min(1).max(20).default(5),
    /** Longest window a pass may have. */
    max_pass_hours: z.number().min(0.25).max(72).default(12),
  })
  .strict();

export type GuardPolicy = z.infer<typeof PolicySchema>;

export function parsePolicy(text: string): GuardPolicy {
  const raw = parseYaml(text) as unknown;
  const r = PolicySchema.safeParse(raw ?? {});
  if (!r.success) {
    const msg = r.error.issues.map((i) => `${i.path.join(".") || "(policy)"}: ${i.message}`).join("; ");
    throw new Error(`Invalid guard policy: ${msg}`);
  }
  return r.data;
}

export function loadPolicy(file: string): GuardPolicy {
  return parsePolicy(fs.readFileSync(file, "utf8"));
}

/** The door a call acts on, from the policy and the call's own (structured) arguments. */
export function doorFor(policy: GuardPolicy, tool: string, args: Record<string, unknown>): string | null {
  const rule = policy.physical[tool];
  if (!rule) return null;
  if (rule.door) return rule.door;
  const v = args[rule.door_arg!];
  // A plain name only: the door name is shown on the owner's phone, so it must not carry a message.
  return typeof v === "string" && /^[A-Za-z0-9_-]{1,40}$/.test(v) ? v : "";
}

/** Local minutes since midnight in `tz`. */
function localMinutes(ms: number, tz: string): number {
  const parts = new Intl.DateTimeFormat("en-US", { timeZone: tz, hourCycle: "h23", hour: "2-digit", minute: "2-digit" }).formatToParts(new Date(ms));
  const h = Number(parts.find((p) => p.type === "hour")?.value ?? 0);
  const m = Number(parts.find((p) => p.type === "minute")?.value ?? 0);
  return h * 60 + m;
}

export function isNight(policy: GuardPolicy, ms: number): boolean {
  if (policy.night === "off") return false;
  const [a, b] = policy.night.split("-").map((p) => {
    const [h, m] = p.trim().split(":").map(Number);
    return h * 60 + m;
  });
  const now = localMinutes(ms, policy.timezone);
  return a <= b ? now >= a && now < b : now >= a || now < b;
}
