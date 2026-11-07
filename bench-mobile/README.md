# Mobile proving benchmarks

This directory is a separate Cargo workspace for the `leanvm-mobile-bench` package and `leanvm_mobile_bench` library. It depends on the repository's public `leanvm` API and shielded, Falcon and stateproof host fixtures through path dependencies. Its SDK dependencies and lockfile stay outside the production workspace. The native C ABI runner exports real proving benchmarks, not host timing estimates or emulator measurements.

## Workloads

| Registered function | Timed work | Untimed work |
| --- | --- | --- |
| `leanvm_mobile_bench::shielded_prove` | Prove one fixed two-spend shielded execution | Construct deterministic advice and load the existing ELF; verify every output and proof after timing |
| `leanvm_mobile_bench::shielded_aggregate` | Prove one 2-to-1 aggregation of two two-spend leaves, four spends total | Generate and verify both independent leaves and construct the tree once; verify every returned root after timing |
| `leanvm_mobile_bench::falcon_prove` | Prove a [Falcon-512 guest](../programs/falcon/guest/src/main.rs) execution verifying exactly one signature | Construct `falcon_host::batch(1)` advice and load the existing ELF; match native expected output and verify every proof after timing |
| `leanvm_mobile_bench::stateproof_prove` | Prove an [L1 state guest](../programs/stateproof/guest/src/main.rs) execution verifying exactly one account and its one storage slot | Construct `stateproof_host::reads(1)` advice and load the existing ELF; match native expected output and verify every proof after timing |

Each leaf input is exactly `shielded_host::spends(2)`: one private transfer followed by one withdrawal, proved together in one VM execution. Each spend consumes two input notes with depth-20 membership paths, so standalone proving covers four input notes and aggregation covers eight; the withdrawal has one empty output slot. Leaf proofs use `log_inv_rate = 2`; aggregation uses `log_inv_rate = 1`. Aggregation generates its two leaves on the device once per invocation, without prebuilt fixtures, and reuses those verified leaves and one tree for one warmup and three measured root proofs. Standalone proving retains the same workload and sample counts.

Falcon and L1 state proofs also use `log_inv_rate = 2` (rate 1/4), with one warmup and three measured proofs each. The existing L1 fixture's single read includes both an account proof and a storage-slot proof; it is not an account-only workload. Falcon reports `signatures = 1`; L1 reports `accounts = 1` and `storage_slots = 1`; both report `log_inv_rate = 2` and `verified_proofs = 4`, in addition to actual threads and available parallelism. Both are mobile-only benchmark workloads: the desktop timing suite, cycles suite and CI benchmark matrix omit Falcon and L1 state proofs.

The benchmark queries Rust's `available_parallelism` once per device process and configures exactly that many total pool threads, including the dispatcher, without adding an extra worker. The count is reused across warmup, samples, and repeated invocations. Raw metrics record detected parallelism and actual pool count; OS resource limits can make this smaller than the phone's physical core count. An incompatible already-initialized pool is rejected. No guest ELF or proof protocol is changed. Proof buffers use the current API's ordinary global allocator.

The SDK owns timing. Completed proofs are retained until teardown, where they are verified and dropped outside the timed interval. Raw reports include workload and verification counters. Median, p95, and individual samples are useful diagnostics, but three samples do not establish a precise tail distribution. Shared hosted devices can vary with scheduling, CPU frequency, and thermal state. Compare only the same workload, device model, OS, actual thread count, build flags, and toolchain; never pool sessions with different thread counts. There is no performance-regression threshold gate.

The website's peak memory is the maximum of the function's three `samples[].process_peak_memory_kb` values from the pinned SDK, multiplied by 1024 to obtain bytes, then displayed in MiB (1,048,576 bytes). Despite the `_kb` name, these values are binary KiB: the [SDK's platform readers](https://github.com/worldcoin/mobile-bench-rs/blob/217cfd4f78db1284276a1a1da44e3bf473729f5c/crates/mobench-sdk/src/timing.rs#L988-L1037) divide process resident bytes by 1024. Android reads resident pages from `/proc/self/statm` and multiplies by the OS page size; iOS reads `task_info(MACH_TASK_BASIC_INFO).resident_size`, not physical footprint. Neither is device total RAM or heap allocation. The legacy `peak_memory_kb` sample field is baseline-adjusted growth and is deliberately not used.

The [SDK resource sampler](https://github.com/worldcoin/mobile-bench-rs/blob/217cfd4f78db1284276a1a1da44e3bf473729f5c/crates/mobench-sdk/src/timing.rs#L829-L986) polls at 1 ms intervals with samples at both iteration boundaries. It measures absolute process RSS around each measured closure, not an OS lifetime high-water mark, so brief peaks can be missed. Setup, warmup and teardown are outside these windows, but their still-resident allocations, retained proofs, sampler overhead and allocator residency can contribute. In particular, aggregation's untimed leaf preparation is not sampled as a separate peak, but its resident memory can remain during aggregation. A missing, zero, noninteger or unsafe-to-convert sample fails validation rather than publishing a partial peak, substituting growth or inventing a zero. The report normalizer preserves these per-iteration observations for all four functions on both devices.

## Toolchain and packaging

The workflow pins Rust 1.99.0, `cargo-ndk` 4.1.2, Android SDK 34, build-tools 34.0.0, NDK 26.1.10909125, Java 17, and Gradle 8.5. The CLI and SDK both use Worldcoin `mobile-bench-rs` revision `217cfd4f78db1284276a1a1da44e3bf473729f5c` (0.1.49). See the pinned [build guide](https://github.com/worldcoin/mobile-bench-rs/blob/217cfd4f78db1284276a1a1da44e3bf473729f5c/docs/guides/build.md) and [BrowserStack guide](https://github.com/worldcoin/mobile-bench-rs/blob/217cfd4f78db1284276a1a1da44e3bf473729f5c/docs/guides/browserstack-ci.md).

iOS packaging runs on the macOS 15 image with Xcode 16.4 (iPhoneOS SDK 18.5), XcodeGen 2.44.1 by checksum, and Rust targets `aarch64-apple-ios`, `aarch64-apple-ios-sim` and `x86_64-apple-ios`. The physical workload targets iOS 16.0; the build SDK version is not the phone's OS version. `ios.xcconfig` sets Swift language mode 5 through `XCODE_XCCONFIG_FILE`, because the pinned toolkit template uses the compiler version `5.9` where Xcode expects a language mode. No Apple developer credentials or provisioning profile are configured; the toolkit packages for BrowserStack ad-hoc re-signing.

The isolated lockfile retains libc 0.2.189 for the pinned mobench SDK's iOS resource sampler. libc 0.2.190 restricts its `mach_task_self` binding to macOS, while mobench 0.1.49 calls it on iOS too. The iPhoneOS 18.5 SDK still declares and exports the underlying `mach_task_self_` API; this compatibility pin preserves the real `task_info` memory measurement rather than disabling it. Revisit the pin when upgrading mobench.

The library emits a `staticlib` for the iOS XCFramework, a `cdylib` for Android and an `rlib` for the native correctness smoke.

ARM64 mobile packages use `-C target-cpu=generic` with platform-specific extensions: Android uses `-C target-feature=+aes,-sha3` for PMULL field multiplication, while iOS uses `-C target-feature=+aes,+sha3` for PMULL and EOR3 XORs. The Pixel 7 benchmark worker trapped with an illegal instruction when both extensions were enabled, so its build explicitly excludes SHA3. These builds require their enabled extensions on the device; they do not select a fallback at runtime. Flags are scoped to Cargo target triples, including the ARM64 iOS simulator; the x86 iOS simulator stays generic and host tools receive no mobile flags. The repository's native CPU setting excludes iOS and Android. Do not set global `RUSTFLAGS` or `CARGO_ENCODED_RUSTFLAGS` when packaging: they override the target-specific flags. Device result metadata records the target's compiler flags.

Use the standalone `mobench` executable. Source scanning can warn that there are no `#[benchmark]` attributes because these setup/teardown benchmarks register `BenchFunction` entries directly. Runtime registration is checked by the native smoke executable, not by source scanning.

Install host tools with neutral flags, rather than the repository's native CPU flags:

```sh
rustup toolchain install 1.99.0 --profile minimal --target aarch64-linux-android
RUSTFLAGS='' cargo +1.99.0 install cargo-ndk --version 4.1.2 --locked
RUSTFLAGS='' cargo +1.99.0 install mobench --git https://github.com/worldcoin/mobile-bench-rs --rev 217cfd4f78db1284276a1a1da44e3bf473729f5c --locked
```

With the pinned Android tools, Java, and Gradle installed, run from this directory:

```sh
export RUSTUP_TOOLCHAIN=1.99.0
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
export CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS='-C target-cpu=generic -C target-feature=+aes,-sha3'
export CARGO_BUILD_JOBS=2
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/26.1.10909125"
python3 ../scripts/mobile-bench-package.py --platform android shielded_prove
python3 ../scripts/mobile-bench-package.py --platform android shielded_aggregate
python3 ../scripts/mobile-bench-package.py --platform android falcon_prove
python3 ../scripts/mobile-bench-package.py --platform android stateproof_prove
```

`mobench.toml` is discovered as project configuration; do not pass it as `--config`, which accepts a different run-spec schema. `project.output_dir = "."` places generated Android files directly under this isolated workspace, so the pinned Gradle template finds the persisted `target/mobile-spec/android/bench_spec.json` after runner regeneration. The generated `android/` directory is ignored. `mobench run` without devices packages the selected real benchmark specification without contacting BrowserStack; its package-check report is not a performance result. The app/test APKs are under `android/app/build/outputs/apk/`. The benchmark library is built only for `arm64-v8a`; the upstream JNA dependency also bundles its own support libraries for other ABIs.

The Android package path uses the supported `mobench run` command without `--devices`, then `mobench verify`, and checks both APKs' embedded function, warmup and iteration count. It also checks the app contains the ARM64 benchmark library. Checked artifacts are retained separately under `target/mobile-bench-packages/android/<function>/`.

A host-only correctness smoke, not a mobile measurement, is available from this directory with `RUSTFLAGS='-C target-cpu=generic' cargo +1.99.0 run --release --locked --bin mobile-bench-smoke`. It checks that exactly these four functions are registered, rejects a zero-iteration specification for each through the exported C ABI, and invokes the complete four-function suite twice in the same process. Each invocation uses one warmup and three measured proofs, validates workload/rate/thread/verification counters, and verifies all returned proofs outside timing. This checks repeated-run thread-pool reuse without fabricating a phone result.

On a Mac with the pinned Xcode and XcodeGen, install the same mobench revision and the three iOS Rust targets. Unset `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS`, export `CARGO_TARGET_AARCH64_APPLE_IOS_RUSTFLAGS` and `CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUSTFLAGS` as `-C target-cpu=generic -C target-feature=+aes,+sha3`, and export `CARGO_TARGET_X86_64_APPLE_IOS_RUSTFLAGS` as `-C target-cpu=generic`. Then run `RUSTUP_TOOLCHAIN=1.99.0 python3 ../scripts/mobile-bench-package.py --platform ios <function>` for each of `shielded_prove`, `shielded_aggregate`, `falcon_prove` and `stateproof_prove`. The credential-free path builds the native C ABI XCFramework and packages the device IPA and XCUITest bundle using `mobench package-ipa` and `mobench package-xcuitest`. It checks the app's embedded benchmark specification, device platform, deployment target and ARM64 binaries, including the test runner. Upload packages are retained separately under `target/mobile-bench-packages/ios/<function>/`. Generated `ios/` files are ignored.

## BrowserStack execution

BrowserStack **App Automate real-device** access is required. A generic BrowserStack account or browser-automation entitlement alone does not establish access. The two credential names are `BROWSERSTACK_USERNAME` and `BROWSERSTACK_ACCESS_KEY`. They must already be available to the trusted workflow. No source file contains credentials, and this integration does not change repository settings, create secrets, purchase access, or require manually creating an app in the dashboard. `mobench ci run` builds and uploads the app and instrumentation package automatically.

An authorized administrator should add those two **repository Actions secrets** in `leanEthereum/leanVM`, under Settings > Secrets and variables > Actions > New repository secret. Obtain the values from the existing BrowserStack account's access-key page, with App Automate access already enabled. Do not paste values into workflow files, issue comments, or command arguments, and do not change billing or permissions to bypass an entitlement failure.

After the workflows are installed and secrets are available upstream, request a complete website snapshot:

```sh
gh workflow run benchmark-site.yml --repo leanEthereum/leanVM --ref riscv-exploration
```

The fixed candidates are `Google Pixel 7-13.0` for Android and `iPhone 14-16` for iOS. Neither is assumed available: the runner first queries that platform's authenticated catalog, records only the matching model/OS/availability fields, and validates the identifier before submission. Missing credentials, missing device availability, or provider entitlement errors fail the run instead of falling back to a different phone or emulator. Catalog validation is not proof of a completed hardware run; successful device reports are required for that.

Within the trusted workflow, the wrapper runs from this directory as `python3 ../scripts/mobile-bench-run.py --platform android --source-sha "$SOURCE_SHA"`, or `--platform ios` on the configured Mac. It requires the actual checkout to match that SHA and records `GITHUB_REPOSITORY` and `GITHUB_RUN_ID` from the caller. Each invocation requests all four registered functions through one supported `mobench ci run --functions` invocation, release mode, one warmup and three samples per function, and artifact fetching. The toolkit runs one device session per function sequentially on the same requested model and OS. The benchmark/completion watchdog is 1200 seconds and fetching is bounded at 1500 seconds. The platform's `target/mobile-bench-results/<platform>` output directory must not already exist, preventing stale results from being mistaken for a new run. Local credential-free packaging and the native smoke remain available as described above.

## CI trust boundary and artifacts

`.github/workflows/mobile-bench.yml` runs credential-free Android and iOS ARM64 release packaging for all four workloads on pull requests, including fork PRs. Its `workflow_call` entrypoint accepts the exact `source_sha` selected by the website workflow. It never uses `pull_request_target` or downloads a PR package into a credential-bearing job. Build/device jobs have only `contents: read`; there is no PR-comment publication job. Checkout credentials are not persisted, third-party actions are pinned by commit, and PR/trusted runs do not share build caches.

Trusted device execution is restricted to scheduled or manual callers on `main` or `riscv-exploration` in `leanEthereum/leanVM`. Before any credential-bearing execution, the source job validates the input as a full SHA, checks out that commit and verifies its ancestry against upstream `riscv-exploration`. Every build then checks out that same SHA. Both website and reusable mobile workflow definitions must be installed on `main` for scheduled runs. A scheduled caller's `trigger_ref` may be `main`; it is not the benchmark source branch. The website owns the six-hour schedule and manual trigger; the mobile workflow has neither an independent schedule nor a dispatch entrypoint.

BrowserStack secrets are scoped to the credential preflight and device execution steps. Trusted mobile runs share a non-cancelling concurrency group. The iPhone build and device run execute first; Android follows on success using the same source SHA, so the account runs at most one device session at a time. Android's job timeout is 120 minutes and iOS's is 150 minutes; each device step is additionally limited to 65 minutes. Build failures, unavailable credentials/devices, and provider or benchmark failures fail the complete snapshot, but timing differences do not.

Package artifacts `mobile-bench-android-packages` and `mobile-bench-ios-packages` retain release app/test packages for seven days. The iOS artifact contains the IPA and XCUITest ZIP rather than APKs. Successful result artifacts `snapshot-result-mobile-android` and `snapshot-result-mobile-ios` retain only `metadata.json` and `raw-results.json` at their root for 30 days. They belong to the calling website workflow run, not to separately discovered or approved runs.

Metadata records the actual source SHA, repository, caller run ID and trigger, Rust/compiler options, SDK/NDK pins, authenticated candidate match, and completion state. `measured_at` is the UTC collection-completion time, with `timestamp_basis` set to `collection_completed_at`. The `benchmarks` object is keyed by full registered function and records observed threads, workload, rates and verification counts; shared thread fields are present only when all four functions agree. Completion requires all four functions, three samples and four verified output proofs each, plus two verified input leaves for aggregation. The requested model/OS identifier is checked separately from BrowserStack's model-only summary name. Root-embedded and per-function report copies must agree; duplicates, missing functions or conflicting samples fail validation. Unknown SoC and thermal data remain null.

The full snapshot plan pins these four functions and one source commit/run for both iPhone 14 / iOS 16 and Google Pixel 7 / Android 13. It publishes 56 configurations: 48 desktop configurations plus eight mobile configurations. Each phone's client-side results include **Falcon-512 (Verify 1 signature)** and **L1 state proofs (Verify 1 account and 1 storage slot)**, with source links to their existing guests. An old two-function device report, either missing workload, wrong unit count/rate, failed verification or missing peak RSS blocks atomic publication; no historical result fills a missing measurement.

Successful device runs put a validated results table in the Actions job summary: workload, model/OS, actual threads, median, sample range and proof-verification count, followed by raw timing samples. The renderer recomputes statistics and checks workload, threads and provenance against metadata. A failed or incomplete platform prevents website publication, leaving the previous complete site intact. These are absolute device timings, not desktop CI's paired base/PR comparison. PR packaging alone does not produce phone timings.

Provider logs, session metadata, video files, and signed download URLs are not uploaded. The wrapper uses private temporary storage, strips URL-bearing and credential-bearing JSON fields, and redacts URLs and credential values from exported reports. Local diagnostic files remain outside the two-file publication artifacts. Missing credentials produce no benchmark result. Successful cross-compilation alone is not evidence of a hardware run.
