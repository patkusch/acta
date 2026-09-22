/**
 * Unit tests for the Rekor anchor sink and its witness check. Both talk to
 * Rekor through an injectable `exec` (the same shape as `github-anchor.ts`'s
 * `ghExec`), so these run offline and are part of `npm test`. They do not
 * touch the network or a real Rekor instance.
 *
 * The Merkle inclusion-proof math (`rootFromInclusionProof`) is instead
 * checked against a real, independently-fetched entry from the public
 * rekor.sigstore.dev log (logIndex 1, a 22-hash proof against a
 * ~4.16M-entry tree, fetched 2026-09-22) — a fixture, not a mock, so this
 * does not just check the code against itself.
 *
 * The one real end-to-end submission — a genuine hashedrekord entry pushed
 * to the real public instance, fetched back and verified for real, plus
 * real tamper cases against the actual API — is a separate, documented
 * manual step (see the "A public transparency-log witness (Rekor)" section
 * of the README). It needs network access to rekor.sigstore.dev, so it is
 * not run here.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';

import {
  writeRekorAnchor,
  verifyRekorWitness,
  rootFromInclusionProof,
  parseCheckpoint,
  verifyCheckpointSignature,
  REKOR_SIGSTORE_DEV_CHECKPOINT_PUBLIC_KEY_PEM,
  type RekorExec,
  type RekorWitness,
} from '../src/rekor-anchor.ts';
import type { Anchor } from '../src/anchor.ts';

const anchorA: Anchor = { session: 'rekor-test', seq: 3, hash: 'a'.repeat(64), at: '2026-09-22T09:00:00.000Z' };
const anchorB: Anchor = { session: 'rekor-test', seq: 9, hash: 'b'.repeat(64), at: '2026-09-22T09:05:00.000Z' };

// --- rootFromInclusionProof, against a real fetched entry ------------------

test('rootFromInclusionProof recomputes the real root for a real rekor.sigstore.dev entry (logIndex 1, fetched 2026-09-22)', () => {
  const entryBodyBase64 =
    'eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJzcGVjIjp7ImRhdGEiOnsiaGFzaCI6eyJhbGdvcml0aG0iOiJzaGEyNTYiLCJ2YWx1ZSI6IjU0NDczODVjZjliOTIwNGE4YTRlNWVmMWI5NzFmNDAzMzQ5Yjk4OWM5ODcwZGE1NjAyNTk3NjhkNTNlYmQzZDAifX0sInNpZ25hdHVyZSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCUVIxQWdVMGxIVGtGVVZWSkZMUzB0TFMwS0NtbFJTRXRDUVVGQ1EwRkJNRVpwUlVWalowTlZXRWMzT0dGa2FqWm9SMVZLU25KbVFtOUtNRFJ3U0c5R1FXd3ZPVEJOUlZkSVIzaHZZVmMxYTJNd1FuY0tZMjA1TUdJeU5YUlpWMnh6VEcxT2RtSlJRVXREVWtGdGREaEhaMjVVYVd0bGF6ZFRSRUZEV0VKNGVXcEROMHA0WTI5M2VWZE5kbmRtTVVkTWIwSXpad3BwVm5STldsQkRZazV6Umt0NGJuVktjemQwWlRSWGFsRnRiVUoxUWxOa1ZtazJabGRLU1hkSmRucEZjMVZpZWk5MVRsaFRVMlpEUkZwa1MwSXhNMEZDQ2tOdFZtTnBTRk5ITTBWd1ZuVjZUSGhXZEhObGIxb3djMlZwTkdjNGFHRkZWSEEzTVcxNUwwRkhTRVpuVkc1emExVnRjMWxwVG1wSlkyWm5LMVZTTHprS09IUnVkVmRXV0U1UVQyNHljbkJSZFZGaldqZE1lVXhqYjFCd1UyVnplbXAzTW1SaWVHdElVVXh5Y1U5eGJFcExNM2wyV1doelpubHNWa2xXTHpsemR3cHNjMlZxTm5SU00zUnZZWEJRWkdsMFJHbDRNV1EwYVhobE5EaGhTa1pxUzFKRlUzUk5SVFZOVWtWUk1XczVWRzFrVVZBMVQzUmtkbVF6UlRSTUwzVnZDbVp1ZG5GaFZ5OXNRVlJ5VWtkalR6bEJVVFZaYzJGS1JUZDZTSGxyYWtaTlFYUmFhMlZKTjA5U2JXeHpaRFpNZDIxR1dYRnRlblUxYzJadVJIbzRja2NLYjJzckwzWkhLMG93WjNCUVoyMDJhR1psUzFGYVlrazNSR1JwWkVONGIwVkRPRFZxU21JMlYzTjVUSEVyVWtkVVEzWTFlbVUwYjA1eFMwNW1kWFZyVHdwUmVqTnNVR0pJWml0RVRISk5aMHRFYkRKSWRYSkRTRVI2Yldad2RESXJTWFU1WkVsTWVGRnhOVWR5WTNWSFprRkxiRGM1Tms0eFpUUnRRemM0V0c1Q0NtaFRUelJ2VEhkVFRrVmFaaXRJWm1GWU5GTnNMMDV4Ukc5NFNrbGlhQ3MyTkRZek9HTjRNRDBLUFRsSlpYSUtMUzB0TFMxRlRrUWdVRWRRSUZOSlIwNUJWRlZTUlMwdExTMHRDZz09IiwiZm9ybWF0IjoicGdwIiwicHVibGljS2V5Ijp7ImNvbnRlbnQiOiJMUzB0TFMxQ1JVZEpUaUJRUjFBZ1VGVkNURWxESUV0RldTQkNURTlEU3kwdExTMHRDZ3A0YzBST1FrWXJZMGxOTUVKRVFVTmhPRWMzVWtReWRqTnRhWGROZEhoV1lWcHBNMHBDVm5WbFZrRnhTRXRETkdWTGIwMVROVWhOUTFKdkswaGFWbEpCQ2pjd1dHMXpWSEJZTVZveFoxcFJkWFZETUVkRVdUSTJhRUpvWldwQmNUTm9lREp5ZGpZdk9IRTVNRUoyVjBkSU9YUldaVWR3VERGellVbHROVEpuUlZJS1dIbFdaMmQ2Tld0QlF6QlROblpOYmpka2NqSmxkRUpyVjFkUUswOXFNRFZUTURKWldrSlVXV2Q0Y0U5aWVXVmpWVk5qY1V0T1ZHcHpiRnBSUWtneVpBcFRTSFZyTTI4eVdqZG9UVFE1VlRCc04zcGlWM2MwYjBsVUsyeEJVbU56WVdwUlZIZFhhbXhwWVZCRUwwaFNhbFF5YmxKUGFFbG9hWFJsWkM5M1ozbDZDbmxrU1hFMVpUWnpNVGhXVEdOVU56VnhWMjV5V2xoT1VGZEdkMll5TlZKWVdUTjFkR3RYSzBkWE5XNVJaVTQ0TUZFeWExSkZaMnQ0Um5NMVFXUTFWMW9LZGtVM2REZ3ZhSGcxZW0xemJGbzBkR1pHTkhOcE0xRmFaVWxSUW1GaldXSjNlRTFRVTBSbU9XOUdSM2hrUjBaVU9EZzVkMHBNUjJkWGJYSXhWR3RRVFFwalRqQTJkM2hCVWtkMGVFNHdlall4UmtwVWFXcE1WMUppYWxjemRXNUpPV2hqVVdOVmJFNHZVU3N4Tm05MFNIQmxTMVpuTkc5WE1EQkRjblpYVDBRMkNuRnJUR05OUkRRNWVWVkVPR1pUUjBJclVrVnVhVUpoT0RsRE9XdFJWVFJUUzJSbmMweE1MMUVyU2tzclUzazVTMjFKUkhKdE1XRTBSR1pRTVhCelptVUtUR3BoY25welZscG1TMVZJWm5kalFVVlJSVUZCWXpCcFZFaFdjbHBUUWtsaFZ6VnJZM2xCT0dKSGFIQmliVko2VVVoQ2VXSXpVblppYlRGb1lWZDNkUXBaTWpsMFVITk1Ra1pCVVZSQlVXZEJVR2haYUVKSVNVRnNSbmgxTDBkdVdTdHZVbXhEVTJFemQyRkRaRTlMVWpaQ1VVcG1ia05FVGtGb2MwUkNVV3RFQ25kdFkwRkNVWE5LUTBGalEwSm9WVXREVVdkTVFXZFJWMEZuVFVKQmFEUkNRV2hsUVVGQmIwcEZRMkV6ZDJGRFpFOUxValphTVd0TUx6RkpTekIyWkdVS1dsZzFjalZUWldKT2VGUkpUbE5CUVhaWmEzSkxVbmxLTldZM2JFOU5PV2RNUjBsMVl6SkdiMDVWYm1wV1VWUXdja2xIT1RBeE9XZzBPSEJEZVRreFpncFlha1JFVWsxWk9XZDZSbGRYUTJkSGJsaG9NV2hYU1ROTk4wSktSalpaUlRaMU5rUllSM04yZFZWd1IzSk9aVnBCUnpacmEyRjZRWFZCYm01V01HdERDakE0ZW05U2NrRmFRM1pzY0dGYWNubGtPR2wwWWl0eVZpdFJTM0EzUVhjeWJFRkpTREZsTm1SM1RUUlNURVpxZG1ack9FeEtXSGhxU2tGdlVHMTNObXdLVEhjeE9HTTNiMWMyVWt4UE9WRllVVGhsVFRaeU1uWklTSEJ0TUZSMVpIWmFlV0ZtVG5WRE16SkhSR3hOV1RSMU1GWXhSR0k0VEhONWJWQnpRV2gxUVFveVNubzBMMHRRY1RaMVMzZEpkRzFXU3pSd2JtUm1SVVIxTmtReFZHOXZSRmxZYVhCMFdXRm1aSFpWTXpOd1ZWRjRkMGh2WmxSVVprVTFlbHAzTWxCbENteElNMjVhWkhOblNGaEhVSGhLVEV4TmNVOXdWelJETDJOTk5scFJWbWRaVTNSV2NqQnVkbFUyTml0UmFsRjJjMnRWV2xJd05tUmtSWHB1UW5CSFNuTUtkSEJ0YWpsQlpTOUhVbGs0UlU1dVRqa3ZNa2RtUlhWeWRIb3paRXRPVlZwdmFrMTVNVFV6YW1OSE1GVXhlbnBvTVRFMVYwbzNkRGgzU0VKMU5GTTBjQW93WjBVclVrRnhlWFJCWTBsYVJHUXlUbE5PY25vNFZuSTVSa1U1ZUN0bVlYUTVSVkpzWW01a1FVSkZOV2xXT0hOTE1DdEdZVzVYZDJkak4wRjZVVkptQ201RFJFNUJVWGRCZEVKdmRHaG1ZMUo2Y2pONGNqTlFPWEEzVVVOTmQwdDFhVzl1ZGsxRGJUaFhaM2RPVXpSRGNHaHhielZPVDNJeWFVMXFhMHhRTUVvS2IyMW5Ta3hXV0RWT0sySnlkamg1TkVnNGNsbFFkMHRDTVRadkwyaEJPRWxpUjJKd1dYbHRNMFpqZVd0VWQyTmlWMkowVUZSTVJYUmtRMVZRVEZsVVJBcE9RelZNUjBwd1p6TmxPRFpaWmxGMFFVNDJMMDF1V25sWlQyMXNSSGd5VjBkMGRFeGtiWE5CVTBkV2RYZzJRVlpLY1VsMkszZ3dObFZMU2tWdFN6TjBDbXBzUlZaTGVXY3hNbEpGZW5sbE5VbFVObkZGVTBkd1QzcHZNbGxzVjFWeFNWUjNMMEZoVUZFeVduaFZZWGgyV1VadlZVOWpkMmRqWkc1SWEyZHphRWtLVDI0NWFDOU9TRlZ0VURNeVYxRjJjV3RSVFhWVllWQkpUbEp6UXpnelMzWlVSRWRzZVdaVFNGWkdlazFoTkdoRVRXaEZZMWg2TkdGamFXNWtOVmRVWlFwNmVVeG5XbWhQWWpkalRtVkRlRFI0WTNKMFVFSTJWVGRDVWk5R1ZreDZURUpzUVhwMWVtcHBSV2haZDBwdk0wRlBUWEZHYjFJMWJVRnhhR3gxZEU1UENuTnplVzltWW5GVVowZGlVMHhrYW1KWVVDOWhSWFJuZWpKTlZqbHVMMjlqTVZOQ09FaGxXazh2TVRkS2VXZHVlbkoxU1V0NUt5OXNUMWRQZW5RcmFsWUtWa1p3Vm5sb01YVmxPR3hHTjNsdFMxSTBkSE5zSzJsSlZtSnhibEIyY0Uxb1RFOUpRbkZZUm00eVowMURhMGR2U2t4NU4wOUliekpYUVVWS1IyeDBNd3BUZDNCaWNtcHFNVUZDUlVKQlFVaERkMUIzUlVkQlJVbEJRMWxYU1ZGU2VVRktVbU5pZG5od01sQnhSVnBSYTIxME9FZG5ibFJwYTJWblZVTllOWGRuQ25wUlNXSkVRVlZLUVRoS2JrRkJRVXREVWtGdGREaEhaMjVVYVd0bGFXNXBSRUZEUlVGbWExcHhMelJTY0RKaFRrRTBaR0p2U2pkVlJsaEVUMkZTYTFZS09VMUxiMFZhUm5GVVRVNXZka1JNTlhob1RXeG5iRkJRZFM5c0syUm9WR2Q0WkdWS09VVldTRzlsZW5SaU9EazJWUzl3VDNWQ1VuTnVPVlowVnpSWkx3cHFaV2xYTjBWNVRsaEJaQzlQY25adVJtSjRLemRwV0V4eGRYQmFTa3BHVkdrdmFqbFNhRlpaVG5OdGJEZHpaV0pVVUdWQ2JrZEVRVGt4Y1dKRE5IaElDbkJSVmtSRGRXcDROamxXZUU4MVJURk1VMjlvUTAwclR5ODFka3hDYlRocE1XOHZibUpHYldKNU4xWkRlVXRsVWtSbWFIUm1PVzVET0RSeGMwVTVSM0VLVlRjdlRGTnBhemxpWm5oTlYySndjVGg1YTI1MGJWTXpZVEJ6ZW1NMFlsWkdjR1Y2UW5CdFRtSXdRVlpqUWl0VWJUbG5WMjFGZW1ocFRITTJSa3RCVGdwSmJuRk9kVmgxUWt3NVVFTmhZemNyYlZVcll6SnRRbWRIVDFKSFpERmtXazh6VWtNNE9YcEdNM2hDUWxsdVEwOWxOV05CVFVac1l6RllSM05zYkhOSkNtUjZaSEprV0haaVRrSjZMMm8zTVhCMVRqaHZSbGx0TDFoaVZtTnBaVTh3VkdaUmFVUmpWSFE0UzJscFVqbFVRVVE1TDFBMU9UTlNUV3hNVDBkVE9IQUthSFpLWW1sR2IxcG1XRWhqYkhOYVJraHRPRVJSVVdFNU5FbGFkMVJDT0cwMFowSldNRTB5V0ZOMlpFaHZNekJzYzNGcWRGcGhXbWxUY2xKb05ISnphQXB1TVRSd1lrRmhWR1JoUzBWUVkzWjBkV1ppVlhWWE1FbHFXV1F5YTNCSlZDOTBaejBLUFdoYVdGVUtMUzB0TFMxRlRrUWdVRWRRSUZCVlFreEpReUJMUlZrZ1FreFBRMHN0TFMwdExRPT0ifX19LCJraW5kIjoicmVrb3JkIn0=';
  const proofHashes = [
    'b08416d417acdb0610d4a030d8f697f9d0a718024681a00fa0b9ba67072a38b5',
    '766ae2c918bbc083a6cce41f6ff3a3cf1a8153b86f594303ce16ded44c99647b',
    'd17f9cb9776767672a026878d31368d6620c12c0b6eb537c7788f975771d5488',
    '3d3952e9ac03dd00d6817cb1ba7e4ca832fdc9472fd066f6eb6550f4a6d3cff1',
    '2b5d2e57470fbaa592f6311b5665ec2870297c39dda407fe8ee45f146df27dbc',
    '8a0cd237f42edf76d50ac9a539108a4f0c73cefd87a27e5ede32ee5153d79a6c',
    '24fe0dc0e19a75cd7bd5f1a58c5aff086bbefcc6c777b70b21a87a5bfd8c8c23',
    'd0b0d0cf8fc7a914cad93607ac5bfd511afd8d9b3729da87cb4d243b53385f17',
    '7e777698d7e8ceb92a03c05cde3632ab12aa4fc3513064a723d68370b287c9d3',
    '0d0f2102d842d56843727e1848872655501af276613f8d04b6ccad806a334d57',
    '34f60d3658ce812525e34e8b6858678be09d9d44b8f9d8c61814be5706c615cf',
    '15ca1b46d6458b9eecd3e1669a8c2848449d158655de9d24f78fd70ad9955e3b',
    '6cde371d35dfc14a44ac42c1ed55025066a261d39333f1c7ff25b7955da48f2f',
    '6d96b436ff041cd3b73f9c291b223b2cc47ec13ab92f97a5d625d15f9aa439fb',
    '70ebf715c1f35f512c68cedbd83d47aba5e5ed309ddbba9472f1786e3b2e40c3',
    '7e6076f58c8241594c9592de95fa4d698b23985025a135049299abc901d5de03',
    '1891d104464a0d35c122f6b4a5ac1b146dc9f43dc86e86f0bc07491b1f50c410',
    '93b48fbede85f163c9a6c96ea5a4af34c212ae946b8870fdbcf9e61987fa5c3c',
    'df963b882a1c8375d0723e4f7e496752a62561f02da4755d2dff311e42ad2d16',
    '34300f7e815c2e7346b6a918b49bb8af51fa32aeada5e86e36d4c19fe0552e72',
    '33e05128e17bff1533f0335a256e681b9b295e5c1530c143d701fca12ea58245',
    'aaf1ac2b361e59fecfd9581a11183902040943a7b39824f1f2e66e18d8a69ba5',
  ];
  const rootHash = '4d006aa46efcb607dd51d900b1213754c50cc9251c3405c6c2561d9d6a2f3239';
  const logIndex = 1;
  const treeSize = 4163431;

  const entryBytes = Buffer.from(entryBodyBase64, 'base64');
  const leafHash = createHash('sha256').update(Buffer.concat([Buffer.from([0x00]), entryBytes])).digest();
  const proof = proofHashes.map((h) => Buffer.from(h, 'hex'));

  const calc = rootFromInclusionProof(logIndex, treeSize, leafHash, proof);
  assert.equal(calc.toString('hex'), rootHash);
});

test('rootFromInclusionProof rejects a proof of the wrong length rather than silently accepting it', () => {
  assert.throws(() => rootFromInclusionProof(1, 4163431, Buffer.alloc(32), [Buffer.alloc(32)]));
});

// --- checkpoint parsing and signature verification, against real fetched checkpoints ---
//
// Both checkpoints below were fetched for real from rekor.sigstore.dev on
// 2026-09-22/23. The first is bundled with the same logIndex-1 entry used
// above; the second is a fresh `GET /api/v1/log` read of the currently
// active shard. Together they prove the ECDSA P-256 signature type for
// real, against real data, before any of this was wired into
// `verifyRekorWitness` — see the module doc for why Ed25519 was the wrong
// assumption to carry over from the plan.

const REAL_CHECKPOINT_LOGINDEX_1 =
  'rekor.sigstore.dev - 3904496407287907110\n' +
  '4163431\n' +
  'TQBqpG78tgfdUdkAsSE3VMUMySUcNAXGwlYdnWovMjk=\n' +
  '\n' +
  '— rekor.sigstore.dev wNI9ajBFAiEAqu0HfRgZ3Us8aRWE1tElE4t5Rukwsd+m7ck/2pyd3qcCIHBgCnYEuZ6GNga6sofQ/sLvETuBh0MI/1pbujUVysCg\n';

const REAL_CHECKPOINT_ACTIVE_SHARD =
  'rekor.sigstore.dev - 1193050959916656506\n' +
  '2787668724\n' +
  'mIBb++gnp2hZUqcKzMQidxwa0eMuAU7uAq324IdmaJI=\n' +
  '\n' +
  '— rekor.sigstore.dev wNI9ajBEAiBqop3cXhaJSYc9vlBbXgZBg3lP77LstFExeb+mY1ig/wIgMgIg2n5XkwB9xQVTJObpyIldyzK6zN1kT4BSIBqvXFo=\n';

test('parseCheckpoint reads a real rekor.sigstore.dev checkpoint (origin, size, root, signature)', () => {
  const c = parseCheckpoint(REAL_CHECKPOINT_LOGINDEX_1);
  assert.equal(c.origin, 'rekor.sigstore.dev - 3904496407287907110');
  assert.equal(c.size, 4163431);
  assert.equal(c.rootHash.toString('hex'), '4d006aa46efcb607dd51d900b1213754c50cc9251c3405c6c2561d9d6a2f3239');
  assert.equal(c.signatures.length, 1);
  assert.equal(c.signatures[0].name, 'rekor.sigstore.dev');
  // The key hint on the signature line is the first 4 bytes of the logID
  // every entry from this instance reports — checked here as an
  // independent cross-check, not just asserted.
  assert.equal(c.signatures[0].keyHint.toString('hex'), 'c0d23d6a');
});

test('verifyCheckpointSignature verifies a real checkpoint against the real rekor.sigstore.dev key, for two different real checkpoints (logIndex 1 and the current active shard)', () => {
  for (const text of [REAL_CHECKPOINT_LOGINDEX_1, REAL_CHECKPOINT_ACTIVE_SHARD]) {
    const check = verifyCheckpointSignature(text, REKOR_SIGSTORE_DEV_CHECKPOINT_PUBLIC_KEY_PEM);
    assert.deepEqual(check.findings, []);
    assert.equal(check.ok, true);
  }
});

test('verifyCheckpointSignature rejects a checkpoint whose signature was tampered with', () => {
  const tampered = REAL_CHECKPOINT_LOGINDEX_1.replace('wNI9aj', 'wNI9ak');
  const check = verifyCheckpointSignature(tampered, REKOR_SIGSTORE_DEV_CHECKPOINT_PUBLIC_KEY_PEM);
  assert.equal(check.ok, false);
  assert.ok(check.findings.some((f) => f.code === 'CHECKPOINT_SIGNATURE_INVALID' || f.code === 'CHECKPOINT_UNPARSEABLE'));
});

test('verifyCheckpointSignature rejects a checkpoint whose root hash was tampered with (signature no longer covers the modified note)', () => {
  const tampered = REAL_CHECKPOINT_LOGINDEX_1.replace('TQBqpG78tgfdUdkAsSE3VMUMySUcNAXGwlYdnWovMjk=', Buffer.alloc(32, 0xaa).toString('base64'));
  const check = verifyCheckpointSignature(tampered, REKOR_SIGSTORE_DEV_CHECKPOINT_PUBLIC_KEY_PEM);
  assert.equal(check.ok, false);
  assert.ok(check.findings.some((f) => f.code === 'CHECKPOINT_SIGNATURE_INVALID'));
});

test('verifyCheckpointSignature rejects a well-formed checkpoint signed by a key that is not the one asked for', () => {
  const check = verifyCheckpointSignature(REAL_CHECKPOINT_LOGINDEX_1, generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ type: 'spki', format: 'pem' }) as string);
  assert.equal(check.ok, false);
  assert.ok(check.findings.some((f) => f.code === 'CHECKPOINT_KEY_MISMATCH'));
});

test('parseCheckpoint throws on a checkpoint with no blank line before the signature block', () => {
  assert.throws(() => parseCheckpoint('not a checkpoint at all'));
});

// --- writeRekorAnchor / verifyRekorWitness, against a fake Rekor -----------

/** Deterministic 32-byte Ed25519 seed for a test key — not used for anything real. */
function testSeed(): Uint8Array {
  const { privateKey } = generateKeyPairSync('ed25519');
  return Buffer.from((privateKey.export({ format: 'jwk' }) as { d: string }).d, 'base64url');
}

/** Signs a fake checkpoint the same way rekor.sigstore.dev's real one is shaped (see the module doc): ECDSA P-256 over SHA-256 of the note text, 4-byte key-hint-prefixed signature line. */
function signFakeCheckpoint(priv: KeyObject, origin: string, size: number, rootHash: Buffer): string {
  const note = `${origin}\n${size}\n${rootHash.toString('base64')}\n`;
  const sig = cryptoSign('sha256', Buffer.from(note, 'utf8'), priv);
  const pubDer = createPublicKey(priv).export({ type: 'spki', format: 'der' }) as Buffer;
  const keyHint = createHash('sha256').update(pubDer).digest().subarray(0, 4);
  const sigLine = Buffer.concat([keyHint, sig]).toString('base64');
  return `${note}\n— fake-log ${sigLine}\n`;
}

function fakeCheckpointKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { privateKey, checkpointPublicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }) as string };
}

/**
 * A tiny in-memory stand-in for the slice of Rekor's v1 API this module
 * uses: POST creates a single-leaf-tree entry (so the inclusion proof is
 * trivial — a real one is checked separately, above, against real data),
 * GET by UUID fetches it back. The checkpoint bundled with each entry is a
 * real, verifiable signature (over the trivial 1-leaf tree), signed with a
 * fresh per-fake ECDSA key — not the real rekor.sigstore.dev key, so callers
 * must pass back `checkpointPublicKeyPem`.
 */
function fakeRekor() {
  const entries = new Map<string, unknown>();
  const { privateKey, checkpointPublicKeyPem } = fakeCheckpointKeyPair();
  let counter = 0;

  const exec: RekorExec = (method, url, body) => {
    if (method === 'POST' && url.endsWith('/api/v1/log/entries')) {
      counter += 1;
      const uuid = `uuid-${counter}`;
      const submitted = JSON.parse(body!) as { spec: unknown };
      const entryBodyB64 = Buffer.from(JSON.stringify({ kind: 'hashedrekord', apiVersion: '0.0.1', spec: submitted.spec })).toString('base64');
      const entryBytes = Buffer.from(entryBodyB64, 'base64');
      const leafHash = createHash('sha256').update(Buffer.concat([Buffer.from([0x00]), entryBytes])).digest();
      const checkpoint = signFakeCheckpoint(privateKey, `fake-log - ${counter}`, 1, leafHash);
      const entry = {
        body: entryBodyB64,
        integratedTime: 1700000000 + counter,
        logID: 'fake-log-id',
        logIndex: 1000 + counter,
        verification: {
          inclusionProof: { logIndex: 0, treeSize: 1, hashes: [], rootHash: leafHash.toString('hex'), checkpoint },
          signedEntryTimestamp: 'fake-set',
        },
      };
      entries.set(uuid, entry);
      return { status: 201, body: JSON.stringify({ [uuid]: entry }) };
    }
    const getMatch = /\/api\/v1\/log\/entries\/(.+)$/.exec(url);
    if (method === 'GET' && getMatch) {
      const uuid = getMatch[1];
      const entry = entries.get(uuid);
      if (!entry) return { status: 404, body: 'Not Found' };
      return { status: 200, body: JSON.stringify({ [uuid]: entry }) };
    }
    throw new Error(`unexpected request: ${method} ${url}`);
  };

  return { exec, entries, checkpointPublicKeyPem };
}

test('writeRekorAnchor produces a witness that verifyRekorWitness confirms', () => {
  const { exec, checkpointPublicKeyPem } = fakeRekor();
  const seed = testSeed();
  const w = writeRekorAnchor(anchorA, { secretKey: seed, exec });

  assert.equal(w.provider, 'rekor');
  assert.equal(w.anchor.hash, anchorA.hash);
  assert.ok(w.uuid);
  assert.equal(w.publicKeyHex.length, 64, 'raw 32-byte ed25519 public key, hex');

  const check = verifyRekorWitness(w, { exec, checkpointPublicKeyPem });
  assert.deepEqual(check.findings, []);
  assert.equal(check.ok, true);
});

test('verifyRekorWitness actually checks the Ed25519ph signature, not just structure: corrupting the signature bytes on the log entry is caught', () => {
  const { exec, entries, checkpointPublicKeyPem } = fakeRekor();
  const w = writeRekorAnchor(anchorA, { secretKey: testSeed(), exec });
  const entry = entries.get(w.uuid) as { body: string };
  const decoded = JSON.parse(Buffer.from(entry.body, 'base64').toString('utf8')) as { spec: { signature: { content: string } } };
  const sig = Buffer.from(decoded.spec.signature.content, 'base64');
  sig[0] ^= 0xff; // flip a bit in the signature itself
  decoded.spec.signature.content = sig.toString('base64');
  entry.body = Buffer.from(JSON.stringify(decoded)).toString('base64');

  const check = verifyRekorWitness(w, { exec, checkpointPublicKeyPem });
  assert.equal(check.ok, false);
  // The body changed, so its own leaf hash no longer matches the inclusion
  // proof the fake computed at write time — exactly the kind of tamper a
  // real proof recomputation is supposed to catch, alongside the signature
  // check itself.
  assert.ok(check.findings.some((f) => f.code === 'REKOR_SIGNATURE_INVALID' || f.code === 'CHECKPOINT_ROOT_MISMATCH' || f.code === 'REKOR_INCLUSION_PROOF_INVALID'));
});

test('verifyRekorWitness rejects a witness whose public key does not match what the log entry actually holds', () => {
  const { exec, checkpointPublicKeyPem } = fakeRekor();
  const w = writeRekorAnchor(anchorA, { secretKey: testSeed(), exec });
  const tampered: RekorWitness = { ...w, publicKeyHex: '00'.repeat(32) };
  const check = verifyRekorWitness(tampered, { exec, checkpointPublicKeyPem });
  assert.equal(check.ok, false);
  assert.ok(check.findings.some((f) => f.code === 'REKOR_PUBLIC_KEY_MISMATCH'));
});

test('verifyRekorWitness rejects a witness claiming an anchor the log entry does not actually hash to', () => {
  const { exec, checkpointPublicKeyPem } = fakeRekor();
  const w = writeRekorAnchor(anchorA, { secretKey: testSeed(), exec });
  const tampered: RekorWitness = { ...w, anchor: anchorB }; // same entry, claims a different anchor
  const check = verifyRekorWitness(tampered, { exec, checkpointPublicKeyPem });
  assert.equal(check.ok, false);
  assert.ok(check.findings.some((f) => f.code === 'REKOR_HASH_MISMATCH'));
  assert.ok(check.findings.some((f) => f.code === 'REKOR_SIGNATURE_INVALID'), 'the signature was over anchorA, not anchorB, so re-verifying against anchorB must fail too');
});

test('verifyRekorWitness rejects a witness whose logID does not match the log entry', () => {
  const { exec, checkpointPublicKeyPem } = fakeRekor();
  const w = writeRekorAnchor(anchorA, { secretKey: testSeed(), exec });
  const tampered: RekorWitness = { ...w, logID: 'not-the-real-log-id' };
  const check = verifyRekorWitness(tampered, { exec, checkpointPublicKeyPem });
  assert.equal(check.ok, false);
  assert.ok(check.findings.some((f) => f.code === 'REKOR_LOG_ID_MISMATCH'));
});

test('verifyRekorWitness rejects a witness whose integratedTime does not match the log entry', () => {
  const { exec, checkpointPublicKeyPem } = fakeRekor();
  const w = writeRekorAnchor(anchorA, { secretKey: testSeed(), exec });
  const tampered: RekorWitness = { ...w, integratedTime: 1 };
  const check = verifyRekorWitness(tampered, { exec, checkpointPublicKeyPem });
  assert.equal(check.ok, false);
  assert.ok(check.findings.some((f) => f.code === 'REKOR_INTEGRATED_TIME_MISMATCH'));
});

test('verifyRekorWitness rejects a witness whose inclusion proof does not recompute to the checkpoint-verified root', () => {
  const { exec, entries, checkpointPublicKeyPem } = fakeRekor();
  const w = writeRekorAnchor(anchorA, { secretKey: testSeed(), exec });
  const entry = entries.get(w.uuid) as { verification: { inclusionProof: { rootHash: string } } };
  entry.verification.inclusionProof.rootHash = 'f'.repeat(64); // corrupt the root after the fact — no longer what the checkpoint attests to
  const check = verifyRekorWitness(w, { exec, checkpointPublicKeyPem });
  assert.equal(check.ok, false);
  assert.ok(check.findings.some((f) => f.code === 'CHECKPOINT_ROOT_MISMATCH'), 'the corrupted rootHash no longer matches what the (untouched) checkpoint signs');
});

test('verifyRekorWitness rejects an entry whose checkpoint is missing', () => {
  const { exec, entries, checkpointPublicKeyPem } = fakeRekor();
  const w = writeRekorAnchor(anchorA, { secretKey: testSeed(), exec });
  const entry = entries.get(w.uuid) as { verification: { inclusionProof: { checkpoint?: string } } };
  delete entry.verification.inclusionProof.checkpoint;
  const check = verifyRekorWitness(w, { exec, checkpointPublicKeyPem });
  assert.equal(check.ok, false);
  assert.ok(check.findings.some((f) => f.code === 'CHECKPOINT_MISSING'));
});

test('verifyRekorWitness rejects an entry whose checkpoint is present but not signed by the key the caller trusts', () => {
  const { checkpointPublicKeyPem: wrongKey } = fakeRekor();
  const { exec: exec2 } = fakeRekor(); // a second fake, unrelated signing key
  const w = writeRekorAnchor(anchorA, { secretKey: testSeed(), exec: exec2 });
  const check = verifyRekorWitness(w, { exec: exec2, checkpointPublicKeyPem: wrongKey });
  assert.equal(check.ok, false);
  assert.ok(check.findings.some((f) => f.code === 'CHECKPOINT_KEY_MISMATCH'));
});

test('verifyRekorWitness reports a missing entry as tamper, not as unreachable', () => {
  const { exec, checkpointPublicKeyPem } = fakeRekor();
  const w = writeRekorAnchor(anchorA, { secretKey: testSeed(), exec });
  const tampered: RekorWitness = { ...w, uuid: 'uuid-does-not-exist' };
  const check = verifyRekorWitness(tampered, { exec, checkpointPublicKeyPem });
  assert.equal(check.ok, false);
  assert.equal(check.unreachable, false);
  assert.ok(check.findings.some((f) => f.code === 'REKOR_ENTRY_NOT_FOUND'));
});

test('verifyRekorWitness reports a network failure as unreachable, never as a pass or as tamper', () => {
  const throwingExec: RekorExec = () => {
    throw new Error('simulated DNS failure');
  };
  const w: RekorWitness = {
    provider: 'rekor',
    rekorUrl: 'https://rekor.sigstore.dev',
    uuid: 'whatever',
    logIndex: 1,
    logID: 'x',
    integratedTime: 1,
    publicKeyHex: '00'.repeat(32),
    anchor: anchorA,
  };
  const check = verifyRekorWitness(w, { exec: throwingExec });
  assert.equal(check.ok, false);
  assert.equal(check.unreachable, true);
  assert.ok(!check.findings.some((f) => f.severity === 'tamper'), 'unreachable must never be reported as tamper');
});

test('writeRekorAnchor throws when the log rejects the submission', () => {
  const rejectingExec: RekorExec = () => ({ status: 400, body: '{"message":"bad request"}' });
  assert.throws(() => writeRekorAnchor(anchorA, { secretKey: testSeed(), exec: rejectingExec }), /rekor rejected the entry/);
});
