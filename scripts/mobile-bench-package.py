#!/usr/bin/env python3
"""Package a fixed mobile benchmark and validate its device artifacts."""

import argparse
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import zipfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("function", choices=("shielded_prove", "shielded_aggregate", "falcon_prove", "stateproof_prove"))
parser.add_argument("--platform", choices=("android", "ios"), required=True)
args = parser.parse_args()
name = f"leanvm_mobile_bench::{args.function}"
if args.platform == "ios":
    # Keep the pinned template's compiler-version/language-mode fix scoped to iOS.
    os.environ["XCODE_XCCONFIG_FILE"] = str(Path("ios.xcconfig").resolve())
subprocess.run(
    [
        "mobench",
        "run",
        "--target",
        args.platform,
        "--crate-path",
        ".",
        "--function",
        name,
        "--release",
        "--iterations",
        "3",
        "--warmup",
        "1",
        "--output",
        f"target/package-check-{args.platform}-{args.function}.json",
    ],
    check=True,
)
if args.platform == "ios":
    # A credential-free `run` builds the XCFramework, not the upload packages.
    # These supported commands use Release/iphoneos and BrowserStack ad-hoc
    # packaging without requiring an Apple team or provisioning profile.
    subprocess.run(
        ["mobench", "package-ipa", "--project-root", ".", "--crate-path", ".", "--method", "adhoc"],
        check=True,
    )
    subprocess.run(
        ["mobench", "package-xcuitest", "--project-root", ".", "--crate-path", "."],
        check=True,
    )
subprocess.run(
    [
        "mobench",
        "verify",
        "--target",
        args.platform,
        "--project-root",
        ".",
        "--crate-path",
        ".",
        "--check-artifacts",
        "--spec-path",
        f"target/mobile-spec/{args.platform}/bench_spec.json",
    ],
    check=True,
)


def check_spec(archive, member):
    spec = json.loads(archive.read(member))
    if (spec["function"], spec["iterations"], spec["warmup"]) != (name, 3, 1):
        raise ValueError(f"{archive.filename}: benchmark specification differs from the requested workload")


def check_ios_bundle(archive, bundle):
    info = plistlib.loads(archive.read(f"{bundle}/Info.plist"))
    if info.get("CFBundleSupportedPlatforms") != ["iPhoneOS"]:
        raise ValueError(f"{archive.filename}: {bundle} is not a physical iOS device bundle")
    minimum = tuple(int(part) for part in info["MinimumOSVersion"].split("."))
    if minimum[0] > 16 or (minimum[0] == 16 and any(minimum[1:])):
        raise ValueError(f"{archive.filename}: {bundle} requires iOS {info['MinimumOSVersion']}, newer than 16.0")
    executable = info["CFBundleExecutable"]
    with tempfile.TemporaryDirectory(prefix="mobile-bench-ios-check-") as directory:
        binary_path = Path(directory) / "executable"
        with archive.open(f"{bundle}/{executable}") as source, binary_path.open("wb") as destination:
            shutil.copyfileobj(source, destination)
        # Accept both thin and universal device binaries, including Apple's
        # XCUITest runner, but require a real ARM64 Mach-O slice in each bundle.
        subprocess.run(["xcrun", "lipo", str(binary_path), "-verify_arch", "arm64"], check=True)


if args.platform == "android":
    app = Path("android/app/build/outputs/apk/release/app-release-unsigned.apk")
    test = Path("android/app/build/outputs/apk/androidTest/release/app-release-androidTest.apk")
    for apk in (app, test):
        with zipfile.ZipFile(apk) as archive:
            check_spec(archive, "assets/bench_spec.json")
            if apk == app:
                archive.getinfo("lib/arm64-v8a/libleanvm_mobile_bench.so")
    packages = ((app, "app.apk"), (test, "test.apk"))
else:
    app = Path("ios/BenchRunner.ipa")
    test = Path("ios/BenchRunnerUITests.zip")
    with zipfile.ZipFile(app) as archive:
        bundle = "Payload/BenchRunner.app"
        check_ios_bundle(archive, bundle)
        check_spec(archive, f"{bundle}/bench_spec.json")
    with zipfile.ZipFile(test) as archive:
        runner = "BenchRunnerUITests-Runner.app"
        check_ios_bundle(archive, runner)
        check_ios_bundle(archive, f"{runner}/PlugIns/BenchRunnerUITests.xctest")
    packages = ((app, "app.ipa"), (test, "test.zip"))

output = Path("target/mobile-bench-packages") / args.platform / args.function
output.mkdir(parents=True, exist_ok=True)
for source, filename in packages:
    shutil.copyfile(source, output / filename)
print(f"Packaged and checked {name} for {args.platform}: ARM64 device app and test suite, 1 warmup and 3 samples")
