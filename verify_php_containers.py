"""Build and remove isolated real-PHP fixtures; PHP is never installed on the host."""
import argparse
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

# Docker Official Images manifests checked on 2026-10-23.
IMAGES = {
    "8.3.35-fpm": "php:8.3.35-fpm-bookworm@sha256:ca090064188589bba7d1a2106356b15975bcab3d9e40c5b7df45c6e732ee0962",
    "8.3.35-apache": "php:8.3.35-apache-bookworm@sha256:cf2be6b00bfbf09563001476d80f8629ba196dd94a1bb4b2a057acc689645583",
    "8.3.36-fpm": "php:8.3.36-fpm-bookworm@sha256:6b4641a875dd3e0f7551b2751e1f5909084856d18166af7fbb522ac230feb702",
    "8.3.36-apache": "php:8.3.36-apache-bookworm@sha256:cbd3b3d9011668443d54ab40ec31db56c73d91b4c8198935d639aa80d2d815c1",
}


def main():
    """Run pinned PHP-FPM/Apache cases with no host mounts or published ports.

    Raises:
        subprocess.SubprocessError: Docker setup, a build or a fixture fails.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=tuple(IMAGES), help="Run one case instead of all four")
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    for case in (args.case,) if args.case else IMAGES:
        image = IMAGES[case]
        version, sapi = case.split("-", 1)
        name = "php2shell-fixture-" + uuid.uuid4().hex[:12]
        with tempfile.TemporaryDirectory(prefix="php2shell-fixture-") as directory:
            root = Path(directory)
            # Only these files enter the build context; no checkout, credentials or host mounts.
            for filename in ("php2shell-audit.py", "verify_php.py"):
                shutil.copy2(source / filename, root / filename)
            (root / "Dockerfile").write_text(
                "FROM " + IMAGES["8.3.36-fpm"] + " AS fixed\nFROM " + image + "\n"
                "RUN apt-get update && apt-get install -y --no-install-recommends python3 "
                "&& rm -rf /var/lib/apt/lists/*\n"
                "COPY --from=fixed /usr/local/bin/php /fixture-replacement/php\n"
                "COPY php2shell-audit.py verify_php.py /audit/\n"
                'ENTRYPOINT ["python3", "/audit/verify_php.py"]\n')
            iid = root / "image-id"
            try:
                subprocess.run(["docker", "build", "--quiet", "--iidfile", str(iid), str(root)],
                               check=True, timeout=600)
                subprocess.run(["docker", "run", "--rm", "--name", name, "--network", "none",
                                "--cap-add", "SYS_PTRACE", "--pids-limit", "128", "--memory", "512m",
                                iid.read_text().strip(), "--version", version, "--sapi", sapi,
                                "--source", image + "; replacement: " + IMAGES["8.3.36-fpm"],
                                "--replacement", "/fixture-replacement/php"],
                               check=True, timeout=120)
            finally:
                subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30)
                if iid.exists():
                    subprocess.run(["docker", "image", "rm", iid.read_text().strip()], capture_output=True, timeout=30)


if __name__ == "__main__":
    main()
