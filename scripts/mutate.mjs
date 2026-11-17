#!/usr/bin/env node
// Applies, reverts, or JUDGES the recorded §4.1c mutations in
// e2e/verdict-mutations.json.
//
//   node scripts/mutate.mjs list
//   node scripts/mutate.mjs apply <id>
//   node scripts/mutate.mjs revert <id>
//   node scripts/mutate.mjs run [id...]      <- the judging loop
//
// WHY A JUDGING LOOP AND NOT JUST apply/revert
//
// apply/revert leaves the judgement to a person, and the judgement is the part
// that goes wrong. A mutated run can go red for reasons that are not the
// verdict: a build error, a server that never started, a port answering from
// an unmutated checkout. Each of those looks exactly like a kill in a terminal
// and is not one. Worse, a patch whose anchor no longer matches applies nothing
// at all, the suite stays green, and "the mutation survived" is
// indistinguishable from "the harness does not bite".
//
// THE FOUR RULES A KILL HAS TO CLEAR, all enforced below:
//
//   1. the owning test PASSED unmutated, in this same run;
//   2. the patch actually CHANGED the file (anchor unique, bytes different);
//   3. the run served the MUTATED code -- proved two ways, because one is not
//      enough: the built bundle's hash must move, and the failure must not
//      match a shape that means the code never ran at all;
//   4. the failure is the OWNING test, not the suite going red elsewhere.
//
// A patch that does not compile is DOES NOT BUILD and is never a kill. Fix the
// patch -- `void x` rather than deleting a used parameter -- and re-run.
//
// BOTH SUITES RUN, and that is deliberate. Several of these mutations are
// caught far more precisely by a unit test reading the RFC text than by
// anything the page can show: dropping the "tls13 " label prefix moves every
// key in the lab, so every browser assertion goes red at once and the failure
// names nothing useful, while hkdf.test.ts names the exact HkdfLabel encoding
// that stopped matching Appendix A.1. So a record may own a vitest test, a
// browser test, or both, and every named owner must fail.
//
// The run happens in an isolated `git archive HEAD` tree with node_modules
// symlinked, so nothing is judged against the working copy and a crash cannot
// strand an inverted condition in a file that also holds real work. CI=1 forces
// playwright.config.ts's `reuseExistingServer: !process.env.CI` to false, so
// port 4245 cannot be answered by a server an earlier, unmutated run left up --
// which has really happened in this fleet and reads as "not caught".
//
// This loop does NOT write its results back into the ledger, and that is a
// deliberate split. e2e/global-teardown.ts already fails the run when a
// recorded kill never executed, so an unperformed record cannot sit in that
// file looking performed; an archived `observed` string would be a second copy
// of an answer the suite already enforces.

import { execFileSync, execSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../', import.meta.url)).replace(/\/$/, '')
const registry = JSON.parse(readFileSync(join(root, 'e2e', 'verdict-mutations.json'), 'utf8'))
const [command, ...rest] = process.argv.slice(2)

if (command === 'list' || !command) {
  for (const [key, entry] of Object.entries(registry.mutations)) {
    console.log(`${key}\n  ${entry.file}`)
    for (const [marker, kill] of Object.entries(entry.kills ?? {})) {
      console.log(`  kills marker ${marker} in: ${kill.test}`)
    }
    for (const title of entry.unitTests ?? []) {
      console.log(`  kills unit test: ${title}`)
    }
    console.log(`  ${entry.why}\n`)
  }
  process.exit(0)
}

/* ---- apply / revert: one edit, in the working tree ----------------------- */
if (command === 'apply' || command === 'revert') {
  const id = rest[0]
  const entry = registry.mutations[id]
  if (!entry) {
    console.error(`unknown mutation: ${id}`)
    process.exit(2)
  }
  const path = join(root, entry.file)
  const source = readFileSync(path, 'utf8')
  const [from, to] = command === 'apply' ? [entry.find, entry.replace] : [entry.replace, entry.find]
  const occurrences = source.split(from).length - 1
  if (occurrences !== 1) {
    console.error(`refusing: ${entry.file} matched ${occurrences}x, want exactly 1`)
    process.exit(2)
  }
  writeFileSync(path, source.replace(from, to))
  console.log(`${command} ${id} -> ${entry.file}`)
  process.exit(0)
}

if (command !== 'run') {
  console.error(`unknown command: ${command}. Try list, apply, revert or run.`)
  process.exit(2)
}

/* ---- run: the judging loop ----------------------------------------------- */

const ids = rest.length ? rest : Object.keys(registry.mutations)
const unknown = ids.filter((id) => !registry.mutations[id])
if (unknown.length) {
  console.error(`unknown mutation(s): ${unknown.join(', ')}`)
  process.exit(2)
}

const git = (...a) => execFileSync('git', ['-C', root, ...a], { encoding: 'utf8' }).trim()

// `git archive HEAD` cannot see uncommitted work, so a dirty tree would produce
// results about a tree nobody has.
const dirty = git('status', '--porcelain', '--untracked-files=no')
if (dirty && !process.env.MUTATION_ALLOW_DIRTY) {
  console.error('Refusing to run: uncommitted changes to tracked files.\n')
  console.error(dirty)
  console.error('\nThe isolated tree is archived from HEAD and would not contain them.')
  console.error('Commit first. MUTATION_ALLOW_DIRTY=1 overrides, knowing that.')
  process.exit(2)
}
const sha = git('rev-parse', 'HEAD').slice(0, 7)

/* Rule 2, checked for every selected patch BEFORE any is applied. An
   unreversible patch strands a mutated file and turns every later result into a
   verdict about that file rather than about its own mutation. */
const invalid = []
for (const id of ids) {
  const entry = registry.mutations[id]
  const text = readFileSync(join(root, entry.file), 'utf8')
  const anchors = text.split(entry.find).length - 1
  if (anchors !== 1) {
    invalid.push(`${id}: find occurs ${anchors} times in ${entry.file}, expected 1`)
    continue
  }
  const after = text.replace(entry.find, entry.replace)
  if (after === text) invalid.push(`${id}: the patch is a no-op, it would not change ${entry.file}`)
  else if (after.split(entry.replace).length - 1 !== 1) {
    invalid.push(`${id}: replace occurs more than once after applying, so it cannot be reverted`)
  }
  if (!(entry.kills && Object.keys(entry.kills).length) && !(entry.unitTests ?? []).length) {
    invalid.push(`${id}: names no owning test at all, so nothing could judge it`)
  }
}
if (invalid.length) {
  console.error('Refusing to run: these patches cannot make the round trip.\n')
  for (const line of invalid) console.error(`  ${line}`)
  process.exit(2)
}

const TREE = mkdtempSync(join(tmpdir(), 'quic-packet-mutation-'))
console.log(`isolated tree: ${TREE}`)
console.log(`archived from: ${sha}`)
console.log(`${ids.length} patches make the round trip.\n`)
execSync(`git -C ${root} archive HEAD | tar -x -C ${TREE}`, { stdio: 'pipe' })
symlinkSync(join(root, 'node_modules'), join(TREE, 'node_modules'))

const sh = (cmd) =>
  execSync(cmd, {
    cwd: TREE,
    stdio: 'pipe',
    encoding: 'utf8',
    env: { ...process.env, CI: '1' },
    maxBuffer: 128 * 1024 * 1024,
  })

const DIST = join(TREE, 'dist', 'assets')
function bundleHash() {
  if (!existsSync(DIST)) return null
  const h = createHash('sha256')
  for (const f of readdirSync(DIST).sort()) h.update(f).update(readFileSync(join(DIST, f)))
  return h.digest('hex').slice(0, 12)
}
const md5 = (rel) =>
  createHash('md5').update(readFileSync(join(TREE, rel))).digest('hex').slice(0, 12)

function build() {
  try {
    sh('npm run build')
    return true
  } catch {
    return false
  }
}

const ESC = String.fromCharCode(27)
const ANSI = new RegExp(ESC + '\\[[0-9;]*m', 'g')
const strip = (s) => String(s).replace(ANSI, '')

/** Rule 3's second half. Red for one of these reasons means the code never ran. */
const NOT_A_KILL = [
  { pattern: /error TS\d+|Build failed|Transform failed|Could not resolve/i, label: 'build error' },
  {
    pattern: /webServer.*did not start|was not able to start|exceeded while running "beforeAll"/i,
    label: 'server never started',
  },
  { pattern: /ERR_CONNECTION_REFUSED|ECONNREFUSED/i, label: 'nothing served on the port' },
  { pattern: /Port \d+ is already in use/i, label: 'the port was held by another server' },
]
const notAKill = (output) =>
  NOT_A_KILL.find(({ pattern }) => pattern.test(strip(output)))?.label ?? null

/**
 * The WHOLE of each suite, never a single test by name.
 *
 * e2e/global-teardown.ts fails the run when any recorded kill in
 * verdict-mutations.json did not execute, which is the mechanism that makes an
 * unperformed record impossible to leave lying around. A `-g` run therefore
 * CANNOT exit 0 here: the named test passes and the teardown fails on all the
 * others. So each suite runs whole, once per phase, and the per-test answer is
 * read out of the reporter.
 */
function runUnit() {
  try {
    return { failed: false, output: sh('npx vitest run --reporter=verbose') }
  } catch (err) {
    return { failed: true, output: `${err.stdout ?? ''}${err.stderr ?? ''}` }
  }
}

/**
 * Release port 4245 before every browser phase.
 *
 * CI=1 forces `reuseExistingServer: false`, which is what stops a mutated run
 * being answered by an unmutated server — but it also means every phase starts
 * its own `vite preview`, and a preview that has not finished exiting still
 * holds the port. The first full run of this loop reported four mutations as
 * NOT A KILL (server never started) for exactly that reason: the classifier
 * was right, the harness was not. Four results nobody could act on is worse
 * than a slow loop, so the port is cleared and confirmed free first.
 */
function releasePort() {
  for (let attempt = 0; attempt < 20; attempt++) {
    let holders = ''
    try {
      holders = execSync('lsof -nP -iTCP:4245 -sTCP:LISTEN -t', { encoding: 'utf8' }).trim()
    } catch {
      return true // lsof exits non-zero when nothing matches
    }
    if (!holders) return true
    for (const pid of holders.split('\n').filter(Boolean)) {
      try {
        process.kill(Number(pid), 'SIGKILL')
      } catch {
        /* already gone */
      }
    }
    execSync('sleep 0.5')
  }
  return false
}

function runBrowser() {
  if (!releasePort()) {
    return { failed: true, output: 'Port 4245 is already in use and could not be released' }
  }
  const cmd =
    'npx playwright test --project=claims --project=coverage --reporter=list --retries=0 --workers=2'
  try {
    return { failed: false, output: sh(cmd) }
  } catch (err) {
    return { failed: true, output: `${err.stdout ?? ''}${err.stderr ?? ''}` }
  }
}

const CROSS = String.fromCharCode(0xd7)
const BALLOT = String.fromCharCode(0x2717)

/** Vitest's verbose reporter marks a failure with a cross before the title. */
function unitFailed(output, title) {
  for (const line of strip(output).split('\n')) {
    if ((line.includes(CROSS) || line.includes(BALLOT)) && line.includes(title)) return true
  }
  return false
}

/** Playwright's list reporter prints `  N) path:line > title`. */
function browserFailingTitles(output) {
  const RULE = new RegExp('^\\s*\\d+\\)\\s+(.+?)(?:\\s*[' + String.fromCharCode(0x2500) + '-]{3,})?\\s*$', 'gm')
  return [...strip(output).matchAll(RULE)].map((m) => m[1].trim())
}

function apply(entry, forward) {
  const [from, to] = forward ? [entry.find, entry.replace] : [entry.replace, entry.find]
  const path = join(TREE, entry.file)
  const before = readFileSync(path, 'utf8')
  if (before.split(from).length - 1 !== 1) throw new Error(`${entry.file}: anchor no longer unique`)
  const after = before.replace(from, to)
  if (after === before) throw new Error('the patch produced an identical file: it did not apply')
  writeFileSync(path, after)
}

console.log('building the baseline in the isolated tree...')
if (!build()) {
  console.error('The baseline build fails in the isolated tree. Nothing below would mean anything.')
  rmSync(TREE, { recursive: true, force: true })
  process.exit(2)
}
const baselineHash = bundleHash()
console.log(`baseline bundle ${baselineHash}\n`)

console.log('running the unmutated baseline suites...')
const baseUnit = runUnit()
const baseBrowser = runBrowser()
if (baseUnit.failed || baseBrowser.failed) {
  console.error('The unmutated suites do not pass in the isolated tree. Nothing below would mean')
  console.error('anything: a mutation "caught" by an already-red suite is caught by nothing.\n')
  console.error(
    strip((baseUnit.failed ? baseUnit : baseBrowser).output).split('\n').slice(-30).join('\n'),
  )
  rmSync(TREE, { recursive: true, force: true })
  process.exit(2)
}
const unitCount = (strip(baseUnit.output).match(/Tests\s+(\d+) passed/) || [])[1] ?? '?'
const browserCount = (strip(baseBrowser.output).match(/(\d+) passed/) || [])[1] ?? '?'
console.log(`baseline PASSED: ${unitCount} unit tests, ${browserCount} browser tests\n`)

// Rule 1, as a property of the whole run rather than per mutation: every test a
// record names has to exist and have passed. A record naming a test nobody
// wrote would otherwise look like a kill the moment anything went red.
const missing = []
for (const id of ids) {
  const entry = registry.mutations[id]
  for (const title of entry.unitTests ?? []) {
    if (!strip(baseUnit.output).includes(title)) {
      missing.push(`${id}: no unit test titled "${title}"`)
    }
  }
  for (const kill of Object.values(entry.kills ?? {})) {
    if (!strip(baseBrowser.output).includes(kill.test)) {
      missing.push(`${id}: no browser test titled "${kill.test}"`)
    }
  }
}
if (missing.length) {
  console.error('Refusing to run: these records name tests that did not execute unmutated.\n')
  for (const line of missing) console.error(`  ${line}`)
  rmSync(TREE, { recursive: true, force: true })
  process.exit(2)
}

const results = []
for (const id of ids) {
  const entry = registry.mutations[id]
  const owners = [
    ...(entry.unitTests ?? []).map((title) => ({ kind: 'unit', title })),
    ...Object.entries(entry.kills ?? {}).map(([marker, kill]) => ({
      kind: 'browser',
      title: kill.test,
      marker,
    })),
  ]
  process.stdout.write(`${id.padEnd(44)} `)
  try {
    const beforeMd5 = md5(entry.file)
    apply(entry, true)
    const built = build()
    const mutatedHash = built ? bundleHash() : null

    let unit = { failed: false, output: '' }
    let browser = { failed: false, output: '' }
    if (built) {
      if (owners.some((o) => o.kind === 'unit')) unit = runUnit()
      if (owners.some((o) => o.kind === 'browser')) browser = runBrowser()
    }

    const browserFailures = built ? browserFailingTitles(browser.output) : []
    const survived = owners.filter((owner) =>
      owner.kind === 'unit'
        ? !unitFailed(unit.output, owner.title)
        : !browserFailures.some((t) => t.includes(owner.title)),
    )

    apply(entry, false)
    build()
    const restoredHash = bundleHash()
    if (md5(entry.file) !== beforeMd5) {
      console.log('NOT RESTORED')
      console.error(`\n${id}: ${entry.file} did not return to md5 ${beforeMd5}. Aborting.`)
      rmSync(TREE, { recursive: true, force: true })
      process.exit(2)
    }

    const shape = notAKill(`${unit.output}\n${browser.output}`)
    const verdict = !built
      ? 'DOES NOT BUILD'
      : mutatedHash === baselineHash
        ? 'BUNDLE UNCHANGED'
        : shape
          ? `NOT A KILL (${shape})`
          : survived.length
            ? `SURVIVED (${survived.map((o) => `${o.kind}:${o.marker ?? o.title}`).join(', ')})`
            : restoredHash !== baselineHash
              ? 'NOT RESTORED'
              : 'KILLED'
    results.push({ id, verdict, owners })
    console.log(
      verdict === 'KILLED'
        ? `KILLED  ${baselineHash} -> ${mutatedHash} -> ${restoredHash}  by ${owners.length} owner(s)`
        : verdict,
    )
  } catch (err) {
    console.log(`ERROR  ${err.message}`)
    console.error(
      '\nAborting: a mutated file left in place makes every later verdict a statement about it.',
    )
    rmSync(TREE, { recursive: true, force: true })
    process.exit(2)
  }
}

rmSync(TREE, { recursive: true, force: true })
const bad = results.filter((r) => r.verdict !== 'KILLED')
const covered = results.reduce((n, r) => n + r.owners.length, 0)
console.log(
  `\n${results.length - bad.length}/${results.length} mutations killed, covering ${covered} owning assertions.`,
)
if (bad.length) {
  console.log('\nNot killed:')
  for (const r of bad) console.log(`  ${r.id}: ${r.verdict}`)
  console.log(
    '\nDOES NOT BUILD is a broken PATCH, not a surviving mutation: fix the patch and re-run.',
  )
  console.log('SURVIVED is evidence about the SOURCE or the test, and is the one worth stopping for.')
}
process.exit(bad.length ? 1 : 0)
