import os
import sys

from ext4lib.debuglog import setup_logging
from ext4lib.host import project_root, relaunch_as_host


def run() -> None:
    if "--raw-helper-request" in sys.argv:
        try:
            idx = sys.argv.index("--raw-helper-request")
            request_path = sys.argv[idx + 1]
        except (ValueError, IndexError):
            raise SystemExit(2)
        from ext4lib.windows.system_raw import run_helper_request

        raise SystemExit(run_helper_request(request_path))

    try:
        os.chdir(project_root())
    except OSError:
        pass
    relaunch_as_host()
    setup_logging()
    from ext4lib.mount.fuse import cleanup_stale_mounts

    cleanup_stale_mounts()
    if "--install-winfsp" in sys.argv:
        from ext4lib.windows.winfsp_setup import ensure_winfsp_installed

        def _progress(msg: str) -> None:
            try:
                print(msg, flush=True)
            except Exception:
                pass

        ensure_winfsp_installed(
            progress=_progress,
            force="--reinstall-winfsp" in sys.argv,
        )
    from ext4lib.ui.gui import main

    main()


if __name__ == "__main__":
    run()
