/**
 * Canonical JSON. Two values that are structurally equal must serialise to the
 * same bytes, or two honest recorders would disagree about a hash.
 *
 * Rules: object keys sorted by UTF-16 code unit, no whitespace, `undefined`
 * properties dropped (as JSON.stringify does), `undefined` array elements
 * become null (as JSON.stringify does), objects with `toJSON` are serialised
 * through it, and anything JSON cannot represent is refused rather than
 * silently approximated — a hash over an approximation proves nothing.
 */
import { createHash } from 'node:crypto';

export function canon(value: unknown): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError(`canon: cannot represent ${value}`);
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'object':
      break;
    default:
      throw new TypeError(`canon: cannot represent a ${typeof value}`);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((v) => (v === undefined ? 'null' : canon(v))).join(',') + ']';
  }
  const obj = value as Record<string, unknown> & { toJSON?: () => unknown };
  if (typeof obj.toJSON === 'function') return canon(obj.toJSON());
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canon(obj[k])).join(',') + '}';
}

export function sha256(text: string | Uint8Array): string {
  return createHash('sha256').update(text).digest('hex');
}

/** The digest of a value's canonical form. */
export function digest(value: unknown): string {
  return sha256(canon(value));
}
