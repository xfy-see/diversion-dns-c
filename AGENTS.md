# C development and validation workflow

This is the independent C repository requested by the owner. Keep C changes here.

1. Edit locally, review the diff, commit and push to this repository. Use the connected
   GitHub tools if the local Git transport has no credentials; then fetch the published
   commit into this checkout. Never publish to the old Go/Rust repository for C work.
2. Let `.github/workflows/build.yml` compile on GitHub. Do not invoke local C compilers,
   Make build targets, Zig, or reinstall a local C build environment unless the owner
   explicitly changes this instruction. Pure Python verifier tests are allowed locally.
3. Wait for all four build/test jobs for the exact commit to succeed, plus the delivery
   job on main. Download the matching Actions ZIP or commit/run/attempt CI prerelease
   asset. Verify workflow head SHA, run ID/attempt, artifact digest, Git source
   tree and every payload hash before executing a downloaded program.
4. Run `scripts/validate.py` on the downloaded macOS ARM64 bundle. It executes native
   and ASan/UBSan unit, domain, server, plan and nft CLI tests without compilation.
   Run downloaded ARM64 library tests and isolated application checks on the owner's
   target when relevant. Kernel NFT writes, routing, performance and sustained-rate
   tests need their own recorded device runs; CI mocks do not establish those results.
5. Preserve old and failed raw evidence, binaries, manifests and source snapshots.
   Report functional tests and performance separately. Never replace old samples or
   claim the imported r12 benchmark is a new CI-artifact measurement.
6. Clean only this C project's generated object files, libraries, expanded build
   dependencies and compiler caches after verified artifacts and tests exist. Keep
   downloads, verification receipts and validation logs. Preserve shared compiler
   installations, unrelated Go/Rust caches and every original measurement record.

The source remains in `c/` to preserve established paths and module structure.
