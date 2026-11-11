export const meta = {
  name: 'stockfw-verify-1.0.8',
  description: 'Comprehensive verification workflow for StockFW 1.0.8 per-app rules and transactional apply',
  phases: [
    { title: 'Build Verify', detail: 'clean CMake configure and Ninja build across core, cli, and ui' },
    { title: 'Core Test Suite', detail: 'run full test-core.sh suite including new program round-trip and netsh tests' },
    { title: 'TxApply Unit Test', detail: 'run fs-txapply-test unit tests for transactional snapshot/restore/rollback' },
    { title: 'Adversarial Review', detail: 'independent adversarial agent review of all 1.0.8 diffs for memory leaks or race conditions' }
  ]
};

phase('Build Verify');
const buildRes = await agent('Run cmake and ninja build in port/build to verify clean compilation without warnings.', {label: 'build-verify'});

phase('Core Test Suite');
const coreRes = await agent('Run bash tests/test-core.sh and verify all checks pass successfully.', {label: 'core-tests'});

phase('TxApply Unit Test');
const txRes = await agent('Run ./build/fs-txapply-test.exe to verify transactional apply and rollback guarantees.', {label: 'tx-tests'});

phase('Adversarial Review');
const reviewRes = await agent('Adversarially review all git diffs on develop/1.0.8 for memory safety (g_free matching g_strdup), buffer overflows, or partial apply holes.', {schema: {type: 'object', properties: {findings: {type: 'array', items: {type: 'string'}}, secure: {type: 'boolean'}}, required: ['secure']}});

return { buildRes, coreRes, txRes, reviewRes };
