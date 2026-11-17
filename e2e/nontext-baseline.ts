/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry
 *     must be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can
 * paint outside its host and the oracle measures it against the host's
 * backdrop, so that ratio is NOT trustworthy — hand-measure before acting on
 * it.
 *
 * A run with `NT_BASELINE_CAPTURE=1` prints every finding through this same
 * path and asserts nothing, which is how this file is regenerated.
 *
 * IT STARTS EMPTY AND IS MEANT TO STAY THAT WAY. The palette in
 * `src/style.css` was chosen against this oracle rather than corrected by it:
 * `--control-border` is `#6b7684` because that measures 3.75:1 against
 * `--surface` (the fleet's usual `#626d7a` measures 3.28:1 and clears 3:1 only
 * just), and `--accent-ink` is the border on every accent-filled control
 * because a border the same colour as its own fill leaves the control with no
 * edge at all — the defect most of this fleet carries on `.btn-primary`.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {};
