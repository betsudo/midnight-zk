#!/usr/bin/env python3
"""Prove a Git consumer gets one coherent Midnight ZK source graph."""

import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGES = {
    "midnight-zk-stdlib": "2.4.0",
    "midnight-circuits": "7.3.0",
    "midnight-curves": "0.3.1",
    "midnight-proofs": "0.8.2",
    "blake2b_halo2": "0.2.0",
    "sha3-circuit": "0.2.0",
}


def run(*args: str, cwd: pathlib.Path = ROOT) -> str:
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def main() -> None:
    revision = run("git", "rev-parse", "HEAD")
    repository = ROOT.as_uri()

    with tempfile.TemporaryDirectory(prefix="midnight-zk-external-") as directory:
        consumer = pathlib.Path(directory)
        (consumer / "src").mkdir()
        (consumer / "src" / "lib.rs").write_text("// source-graph canary\n")
        manifest = (
            "[package]\n"
            'name = "midnight-zk-external-consumer"\n'
            'version = "0.0.0"\n'
            'edition = "2021"\n\n'
            "[dependencies]\n"
            f'midnight-zk-stdlib = {{ git = "{repository}", rev = "{revision}" }}\n'
        )
        if "[patch" in manifest:
            raise SystemExit("external consumer manifest must not contain a patch table")
        (consumer / "Cargo.toml").write_text(manifest)
        metadata = json.loads(
            run(
                "cargo",
                "metadata",
                "--format-version",
                "1",
                "--manifest-path",
                str(consumer / "Cargo.toml"),
                cwd=consumer,
            )
        )
        run(
            "cargo",
            "check",
            "--locked",
            "--manifest-path",
            str(consumer / "Cargo.toml"),
            cwd=consumer,
        )

    selected_packages = [
        package for package in metadata["packages"] if package["name"] in PACKAGES
    ]
    selected = {package["name"]: package for package in selected_packages}
    if set(selected) != set(PACKAGES):
        missing = sorted(set(PACKAGES) - set(selected))
        raise SystemExit(f"missing Midnight ZK packages: {missing}")
    if len(selected_packages) != len(PACKAGES):
        duplicates = sorted(package["id"] for package in selected_packages)
        raise SystemExit(f"duplicate Midnight ZK packages: {duplicates}")

    sources = set()
    for name, expected_version in PACKAGES.items():
        package = selected[name]
        if package["version"] != expected_version:
            raise SystemExit(
                f"{name} resolved as {package['version']}, expected {expected_version}"
            )
        source = package["source"] or ""
        if not source.startswith(f"git+{repository}") or f"#{revision}" not in source:
            raise SystemExit(f"{name} resolved from unexpected source: {source or 'path'}")
        sources.add(source)

    if len(sources) != 1:
        raise SystemExit(f"Midnight ZK packages split across sources: {sorted(sources)}")

    print(
        f"patch-free external Git consumer compiled {len(PACKAGES)} "
        f"Midnight ZK packages at {revision}"
    )


if __name__ == "__main__":
    main()
