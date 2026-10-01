import os
import sys

from ext4reader.debuglog import setup_logging
from ext4reader.host import project_root, relaunch_as_host


def run() -> None:
    try:
        os.chdir(project_root())
    except OSError:
        pass
    relaunch_as_host()
    setup_logging()
    from ext4reader.fuse_mount import cleanup_stale_mounts

    cleanup_stale_mounts()
    if "--install-winfsp" in sys.argv:
        from ext4reader.winfsp_setup import ensure_winfsp_installed

        def _progress(msg: str) -> None:
            try:
                print(msg, flush=True)
            except Exception:
                pass

        ensure_winfsp_installed(
            progress=_progress,
            force="--reinstall-winfsp" in sys.argv,
        )
    from ext4reader.gui import main

    main()


if __name__ == "__main__":
    run()
