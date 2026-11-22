# Working in acta

A tamper-evident record of what an agent actually did — hash-chained, signed, anchored, and honest about what that does not prove.

## Run the tests

You need Node 22.6 or newer.

```bash
npm ci
npm test
```

Every test should pass before you start and after you finish.

## Where things are

- `src/`: the code
- `bin/`: the command-line entry point
- `test/`: the tests
- `docs/`: written documentation
- `scripts/`: helper scripts, not part of the tool itself

## Before you commit

- Make sure the tests pass.
- Put changes people will notice in `CHANGELOG.md`.
- Do not put real passwords, keys or private data in test files or examples. Use made-up ones.
