export const meta = {
  name: 'stockfw-ci-followup',
  description: 'Follow up on StockFW PR status, branch health, and test coverage',
  phases: [
    { title: 'Local Verify', detail: 'run full local test suites and check git status' },
    { title: 'Code Hygiene Check', detail: 'scan for compiler warnings, unescaped strings, or memory safety issues' }
  ]
};

phase('Local Verify');
const localCheck = await agent('Run bash tests/test-core.sh and verify zero failures.', {label: 'local-check'});

phase('Code Hygiene Check');
const hygieneCheck = await agent('Review recent diffs on develop/1.0.8 for memory leaks (g_free matching g_strdup), uninitialized variables, or strict C warnings.', {label: 'hygiene-check'});

return { localCheck, hygieneCheck };
