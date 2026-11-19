import assert from 'node:assert/strict';
import { translations } from '../../webui/i18n.js';
import { configSavePhase, policyModeText, statusPresentation } from '../../webui/status.js';

for (const pending of [false, true]) {
  for (const changes of [{ fixed_sepolicy: true }, { fixed_sepolicy: false },
    { fixed_sepolicy: true, denylist_mode: 1 }]) {
    const phase = configSavePhase(changes, pending);
    assert.equal(phase, 'savedPolicy');
    for (const strings of Object.values(translations)) assert.ok(strings[`settings.${phase}`]);
  }
  assert.equal(configSavePhase({ denylist_mode: 1 }, pending), pending ? 'savedPending' : 'saved');
}

let reply;
globalThis.ksu = {
  exec(command, _options, callback) {
    assert.match(command, /status --json$/);
    globalThis[callback](...reply);
  },
};
const { api } = await import('../../webui/api.js');
const error = 'cannot open YukiZygisk kernel control session: No such device';
const policy = { supported: false, reboot_required: true };

reply = [1, JSON.stringify({ kernel_alive: false, policy, error }), 'yzctl: ' + error];
let status = await api.getStatus();
assert.equal(status.available, false);
assert.equal(status.late_load_pending, false);
assert.equal(status.error, error);
assert.deepEqual(status.policy, policy);

reply = [1, JSON.stringify({ late_load: true, late_load_pending: true, error }), error];
assert.equal((await api.getStatus()).late_load_pending, false);

reply = [0, JSON.stringify({ kernel_alive: false, late_load: true, late_load_pending: true, policy }), ''];
status = await api.getStatus();
assert.equal(status.late_load_pending, true);
assert.equal(status.error, '');
assert.deepEqual(status.policy, policy);

const prepareError = 'boot policy preparation failed: Operation not permitted';
reply = [1, JSON.stringify({ late_load: true, late_load_pending: true, late_load_error: prepareError,
  error: prepareError, policy }), prepareError];
const blockedBoot = await api.getStatus();
assert.equal(blockedBoot.late_load_pending, true);
assert.equal(blockedBoot.late_load_error, prepareError);

for (const [stdout, stderr] of [['', 'legacy status error'], ['legacy status error', '']]) {
  reply = [1, stdout, stderr];
  status = await api.getStatus();
  assert.equal(status.available, false);
  assert.equal(status.error, 'legacy status error');
}
reply = [0, 'invalid JSON', ''];
assert.match((await api.getStatus()).error, /invalid status JSON/);
reply = [0, JSON.stringify({ kernel_alive: true, policy: { reboot_required: false } }), ''];
status = await api.getStatus();
assert.equal(status.available, true);
assert.equal(status.policy.reboot_required, false);

for (const [locale, strings] of Object.entries(translations)) {
  const t = (key, fallback, values = {}) =>
    (strings[key] ?? fallback).replace(/\{(\w+)\}/g, (_, name) => values[name]);
  const card = (policy) => statusPresentation({ ...status, policy }, true, t);
  for (const online of [true, false]) {
    const blocked = statusPresentation({ ...blockedBoot, available: online, kernel_alive: online }, true, t);
    assert.equal(blocked.tone, 'danger');
    assert.equal(blocked.description, t('settings.policyRebootRequired', '', { status: prepareError }));
  }
  const fixed = { supported: true, initialized: true, requested: true, active: true, error: 0 };
  for (const fixed_sepolicy of [false, true]) {
    const state = { status: { policy: fixed }, config: { fixed_sepolicy } };
    for (const configReady of [false, true]) {
      const key = fixed_sepolicy ? 'settings.policyFixed' : 'settings.policyTemporary';
      assert.equal(policyModeText({ ...state, configReady }, t), t('settings.policyState', '', {
        active: strings['settings.policyFixed'], preferred: strings[configReady ? key : 'common.unknown'],
      }), locale);
    }
  }
  const denied = policyModeText({
    status: {
      policy: {
        ...fixed,
        missing_source: 'netd',
        missing_target: 'yukizygisk_file',
        missing_class: 'file',
        missing_av: 0x44412,
      },
    },
    configReady: true,
    config: { fixed_sepolicy: true },
  }, t);
  assert.ok(denied.includes('netd') && denied.includes('yukizygisk_file') && denied.includes('0x44412'), locale);
  const deferred = policyModeText({
    status: { policy: { ...fixed, active: false, requested: false } },
    configReady: true, config: { fixed_sepolicy: true },
  }, t);
  assert.ok(deferred.includes(strings['settings.policyTemporary']) && deferred.includes(strings['settings.policyFixed']));
  assert.doesNotMatch(deferred, /Next boot|下次启动/i);
  for (const [error, key] of [[-13, 'settings.policyRejected'], [-101, 'settings.policyMountRejected']]) {
    const blocked = card({ ...fixed, active: false, error, reboot_required: true });
    assert.equal(blocked.tone, 'danger', locale);
    assert.equal(blocked.title, strings['settings.fixedPolicy']);
    const reason = t('settings.policyError', '', { status: strings[key], error });
    assert.equal(blocked.description, t('settings.policyRebootRequired', '', { status: reason }));
    for (const reboot_required of [false, true]) {
      const late = statusPresentation({ ...status, late_load_pending: true,
        policy: { ...fixed, active: false, error, reboot_required } }, true, t);
      const detail = t('status.lateLoadBlocked', '', { error: reason });
      assert.equal(late.tone, 'danger', locale);
      assert.equal(late.title, blocked.title);
      assert.equal(late.description, reboot_required
        ? t('settings.policyRebootRequired', '', { status: detail.replace(/[.。]$/, '') }) : detail);
    }
  }
  assert.equal(statusPresentation({ ...status, policy: fixed, late_load_pending: true }, true, t).title,
    strings['status.lateLoad']);
  const pending = card({ ...fixed, initialized: false, active: false });
  assert.equal(pending.tone, 'warning');
  assert.equal(pending.description, strings['settings.policyPending']);
  for (const healthy of [fixed, { ...fixed, requested: false, active: false }, { supported: false }, undefined])
    assert.equal(card(healthy).title, strings['status.running']);
  const withdrawal = { ...fixed, reboot_required: true };
  assert.equal(card(withdrawal).description, t('settings.policyRebootRequired', '', { status: status.abi }));
  const safe = statusPresentation({ ...status, policy: withdrawal, safe_mode: true }, true, t);
  assert.equal(safe.title, strings['status.safeMode']);
  assert.equal(safe.description, t('settings.policyRebootRequired', '', {
    status: strings['status.safeModeDesc'].replace(/[.。]$/, ''),
  }));
}
console.log('PASS: offline, deferred, blocked and active policy status');
