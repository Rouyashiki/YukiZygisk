import assert from 'node:assert/strict';
import { zygiskOutcome, zygiskRecords } from '../../webui/zygisk_outcomes.js';

const record = { pid: 17, generation: 3, abi: 'arm64-v8a', kind: 'zygote',
  module: 'zygisk_vector', state: 'failed', process_state: 'running',
  load_success_seen: true, load_failure_seen: true };
const status = { zygisk_module_outcomes: true,
  zygote_monitor: [{ pid: 17, generation: 3, abi: 'arm64-v8a' }],
  runtime: [record, { ...record, generation: 2 }, { ...record, abi: 'armeabi-v7a' },
    { ...record, process_state: 'exited' }] };
assert.deepEqual(zygiskRecords(status, 'zygisk_vector'), [record]);
assert.equal(zygiskOutcome(status, 'zygisk_vector'), 'partial');
assert.equal(zygiskOutcome({ ...status, zygisk_module_outcomes: false }, 'zygisk_vector'), 'load_legacy_failure');
assert.equal(zygiskOutcome({ ...status, runtime: [{ ...record, load_failure_seen: false }] }, 'zygisk_vector'), 'load_success');
assert.equal(zygiskOutcome({ ...status, runtime: [{ ...record, load_success_seen: false }] }, 'zygisk_vector'), 'load_failed');
assert.equal(zygiskOutcome({ ...status, runtime: [] }, 'zygisk_vector'), 'unknown');
assert.equal(zygiskOutcome({ ...status, zygote_monitor: [] }, 'zygisk_vector'), 'unknown');
console.log('PASS: Zygisk outcome compatibility, generation, ABI and process lifetime');
