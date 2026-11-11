export const meta = {
  name: 'stockfw-ultracode-audit-1.0.8',
  description: 'Ultracode exhaustive audit and verification of all StockFW 1.0.8 features (per-app rules, transactional apply, UI bind app, event log full path retention)',
  phases: [
    { title: 'Codebase Sweep', detail: 'deep static audit of all modified core and platform files for memory safety, locking discipline, and error handling' },
    { title: 'Test Execution', detail: 'run full core test suite and transactional apply unit tests' },
    { title: 'Architectural Review', detail: 'verify alignment with Portmaster competition goals and robust zero-trust principles' }
  ]
};

phase('Codebase Sweep');
const sweep = await agent('Examine git diff on develop/1.0.8 and check for any potential memory leaks, uninitialized pointers, or error-path omissions.', {label: 'codebase-sweep'});

phase('Test Execution');
const tests = await agent('Run tests/test-core.sh and build/fs-txapply-test.exe and verify 100% pass rate.', {label: 'test-exec'});

phase('Architectural Review');
const review = await agent('Review the 1.0.8 implementation against safety and reliability principles (no kernel driver, transactional apply, fail-loud elevation).', {label: 'arch-review'});

return { sweep, tests, review };
