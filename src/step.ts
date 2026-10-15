import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { Recorder } from './recorder.ts';
import { LEDGER_FILE } from './ledger.ts';

export const STAGES = ['plan', 'create', 'verify', 'package', 'secure', 'release', 'configure', 'monitor', 'govern'] as const;
export type Stage = (typeof STAGES)[number];

export interface Step {
  /** Which agent or flow acted, e.g. "ai-fixer-flow". */
  agent: string;
  stage: Stage;
  /** One plain sentence: what was done. */
  action: string;
  /** Link or id a reader can follow: an MR, a pipeline, a job. */
  ref?: string;
  ok?: boolean;
}

/**
 * Write one agent action into a ledger, opening it on the first step and
 * resuming it on every later one. Each pipeline job is a new process, so
 * resuming (which leaves a visible marker) is the honest thing to do.
 */
export function recordStep(dir: string, step: Step, opts: { session?: string } = {}): void {
  if (!STAGES.includes(step.stage)) throw new Error(`unknown stage "${step.stage}"; use one of ${STAGES.join(', ')}`);
  const rec = existsSync(join(dir, LEDGER_FILE))
    ? Recorder.resume(dir, { actor: step.agent })
    : Recorder.open(dir, { actor: step.agent, session: opts.session });
  const id = rec.call(`gitlab.${step.stage}`, { action: step.action, ref: step.ref }, { actor: step.agent });
  rec.result(id, { done: step.action }, { ok: step.ok ?? true });
}

export function closeSession(dir: string): void {
  Recorder.resume(dir, { actor: 'acta' }).close();
}
