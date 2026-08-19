import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import test from 'node:test'

import getPort from 'get-port'
import { temporaryDirectory } from 'tempy'

// Helper: spawn the CLI with given args and collect output.
// Uses a timeout to kill the process when the server starts (valid invocations
// start a long-running server that never exits on its own).
function run(
  args: string[],
  { timeout = 3000 }: { timeout?: number } = {},
): Promise<{ stdout: string; stderr: string; exitCode: number | null; killed: boolean }> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      ['--experimental-strip-types', 'src/bin.ts', ...args],
      { timeout, env: { ...process.env, NODE_ENV: 'production' } },
      (error, stdout, stderr) => {
        if (error && error.killed) {
          // Process was killed by timeout - means server started successfully
          resolve({ stdout, stderr, exitCode: null, killed: true })
        } else if (error) {
          resolve({
            stdout,
            stderr,
            exitCode: typeof error.code === 'number' ? error.code : 1,
            killed: false,
          })
        } else {
          resolve({ stdout, stderr, exitCode: 0, killed: false })
        }
      },
    )
  })
}

// Create a temporary db file for tests that need a valid JSON file
function createTmpDb(data: Record<string, unknown> = {}): string {
  const dir = temporaryDirectory()
  const file = join(dir, 'db.json')
  writeFileSync(file, JSON.stringify(data))
  return file
}

await test('bin CLI argument parsing', async (t) => {
  await t.test('--port with valid numeric value starts server on that port', async () => {
    const port = await getPort()
    const dbFile = createTmpDb()
    const result = await run(['--port', String(port), dbFile])
    // Server started (killed by timeout) and output contains the port
    assert.equal(result.killed, true, 'Server should have started (killed by timeout)')
    assert.match(result.stdout, new RegExp(`PORT :${port}`), `stdout should contain PORT :${port}`)
  })

  await t.test('--port with non-numeric value crashes with ERR_SOCKET_BAD_PORT', async () => {
    const dbFile = createTmpDb()
    const result = await run(['--port', 'abc', dbFile])
    // parseInt('abc') => NaN which fails net.Server.listen validation
    assert.equal(result.killed, false, 'Server should NOT have started')
    assert.equal(result.exitCode, 1, 'Exit code should be 1')
    assert.match(result.stderr, /ERR_SOCKET_BAD_PORT/, 'stderr should contain ERR_SOCKET_BAD_PORT')
  })

  await t.test('--host defaults to localhost when omitted', async () => {
    const port = await getPort()
    const dbFile = createTmpDb()
    const result = await run(['--port', String(port), dbFile])
    assert.equal(result.killed, true, 'Server should have started (killed by timeout)')
    assert.match(result.stdout, /http:\/\/localhost:/, 'stdout should contain http://localhost:')
  })

  await t.test('--static with missing directory crashes with ENOENT', async () => {
    const port = await getPort()
    const dbFile = createTmpDb()
    // sirv (via totalist) throws ENOENT when scanning a nonexistent directory
    const result = await run(['-s', '/nonexistent/path', '--port', String(port), dbFile])
    assert.equal(result.killed, false, 'Server should NOT have started')
    assert.equal(result.exitCode, 1, 'Exit code should be 1')
    assert.match(result.stderr, /ENOENT/, 'stderr should contain ENOENT')
    assert.match(result.stderr, /no such file or directory/, 'stderr should mention missing directory')
  })

  await t.test('repeated --port flags uses last value (last-one-wins)', async () => {
    const port1 = await getPort()
    const port2 = await getPort()
    const dbFile = createTmpDb()
    const result = await run(['--port', String(port1), '--port', String(port2), dbFile])
    // parseArgs uses last-one-wins for non-multiple string options
    assert.equal(result.killed, true, 'Server should have started (killed by timeout)')
    assert.match(result.stdout, new RegExp(`PORT :${port2}`), `stdout should contain PORT :${port2} (last-one-wins)`)
    assert.ok(!result.stdout.includes(`PORT :${port1}`), `stdout should NOT contain PORT :${port1}`)
  })

  await t.test('repeated --host flags uses last value (last-one-wins)', async () => {
    const port = await getPort()
    // Need data in the db so that logRoutes prints endpoint URLs containing the host
    const dbFile = createTmpDb({ posts: [{ id: '1' }] })
    const result = await run(['--host', 'aaa', '--host', 'bbb', '--port', String(port), dbFile])
    assert.equal(result.killed, true, 'Server should have started (killed by timeout)')
    // The host value appears in the Endpoints section (logRoutes uses the host variable)
    assert.match(result.stdout, /http:\/\/bbb:/, 'stdout should contain http://bbb: in Endpoints (last host wins)')
    assert.ok(!result.stdout.includes('http://aaa:'), 'stdout should NOT contain http://aaa:')
  })

  await t.test('repeated --static flags accumulate (multiple: true)', async () => {
    const port = await getPort()
    const dbFile = createTmpDb()
    // Use existing directories so sirv does not crash
    const dir1 = temporaryDirectory()
    const dir2 = temporaryDirectory()
    // Since static has multiple:true, both values should be kept (not last-wins)
    const result = await run(['-s', dir1, '-s', dir2, '--port', String(port), dbFile])
    // Server starts without error because both directories exist
    assert.equal(result.killed, true, 'Server should have started (killed by timeout)')
    assert.match(result.stdout, /JSON Server started/, 'stdout should contain "JSON Server started"')
  })
})
