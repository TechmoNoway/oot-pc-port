"""Build a local ZBIC helper from a pinned, separately downloaded dependency."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = "https://github.com/hexkyz/zstd.git"
REVISION = "491bb11b008cf57019a08fcd57beee5d3d24904d"
COMMON = ("debug.c", "entropy_common.c", "error_private.c", "fse_decompress.c", "xxhash.c", "zstd_common.c")
DECOMPRESS = ("huf_decompress.c", "zstd_ddict.c", "zstd_decompress.c", "zstd_decompress_block.c")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true", help="download the pinned dependency if it is missing")
    parser.add_argument("--fetch-only", action="store_true", help="prepare the dependency for a CMake build")
    parser.add_argument("--compiler", default=shutil.which("gcc") or "C:/msys64/ucrt64/bin/gcc.exe")
    args = parser.parse_args()
    source = ROOT / "toolchain" / "zbic-src"
    try:
        if not source.exists():
            if not args.fetch:
                parser.error("Dependency missing; pass --fetch to download it under toolchain/")
            source.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", str(source)], check=True)
            subprocess.run(["git", "-C", str(source), "remote", "add", "origin", REPOSITORY], check=True)
            subprocess.run(["git", "-C", str(source), "fetch", "--depth", "1", "origin", REVISION], check=True)
            subprocess.run(["git", "-C", str(source), "checkout", "--detach", "FETCH_HEAD"], check=True)
        actual = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        dirty = subprocess.check_output(["git", "-C", str(source), "status", "--porcelain", "--untracked-files=no"], text=True)
        if actual != REVISION or dirty:
            parser.error("Dependency must be an unmodified checkout of the pinned revision; existing files were left untouched")
        if args.fetch_only:
            print(f"ZBIC dependency ready at {REVISION}")
            return 0
        output = ROOT / "build" / "tools" / ("zbic-decode.exe" if os.name == "nt" else "zbic-decode")
        output.parent.mkdir(parents=True, exist_ok=True)
        sources = [source / "lib" / "common" / name for name in COMMON]
        sources += [source / "lib" / "decompress" / name for name in DECOMPRESS]
        command = [args.compiler, "-std=c11", "-O2", "-DZSTD_ZBIC_SUPPORT=1", "-DZSTD_LEGACY_SUPPORT=0",
                   "-DZSTD_DISABLE_ASM=1", "-I", str(source / "lib"), "-I", str(source / "lib/common"),
                   str(ROOT / "tools/zbic_decode.c"), *map(str, sources), "-o", str(output)]
        subprocess.run(command, check=True)
        shutil.copy2(source / "LICENSE", output.parent / "zbic-LICENSE.txt")
        (output.parent / "zbic-backend.json").write_text(json.dumps({
            "repository": REPOSITORY, "revision": REVISION, "compiler": args.compiler,
            "license": "zbic-LICENSE.txt", "executable": output.name,
        }, indent=2) + "\n", encoding="utf-8")
        print(f"Built {output}")
        return 0
    except (OSError, subprocess.SubprocessError) as error:
        print(f"ZBIC build failed: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
