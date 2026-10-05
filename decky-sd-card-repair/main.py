import asyncio
import json
import os
import re
import shutil
import subprocess
import decky

EXT_TYPES = {"ext2", "ext3", "ext4"}
SYSTEM_MOUNTS = {"/", "/boot", "/efi", "/home", "/var", "/usr"}
DEV_RE = re.compile(r"^/dev/(mmcblk\d+p\d+|sd[a-z]\d+)$")

def run(*args, timeout=120):
    p = subprocess.run(list(args), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=False)
    return p.returncode, p.stdout.strip()

def lsblk():
    rc, out = run("lsblk", "-J", "-b", "-o", "NAME,PATH,TYPE,FSTYPE,LABEL,UUID,SIZE,RM,RO,MOUNTPOINTS,MODEL,TRAN")
    if rc:
        raise RuntimeError(out or "lsblk failed")
    return json.loads(out)

def flatten(nodes, parent=None):
    out = []
    for n in nodes:
        n["_parent"] = parent
        out.append(n)
        out += flatten(n.get("children") or [], n)
    return out

def mounts(n):
    return [x for x in (n.get("mountpoints") or []) if x]

def candidate(n):
    if n.get("type") != "part" or (n.get("fstype") or "").lower() not in EXT_TYPES:
        return False
    path = n.get("path") or ""
    if not DEV_RE.match(path) or set(mounts(n)) & SYSTEM_MOUNTS:
        return False
    parent = n.get("_parent") or {}
    removable = bool(n.get("rm")) or bool(parent.get("rm"))
    transport = (n.get("tran") or parent.get("tran") or "").lower()
    return path.startswith("/dev/mmcblk") or removable or transport in {"usb", "mmc", "sd"}

def info(n):
    return {"path": n.get("path"), "fstype": n.get("fstype"), "label": n.get("label") or "", "uuid": n.get("uuid") or "", "size": int(n.get("size") or 0), "mountpoints": mounts(n), "readonly": bool(n.get("ro")), "model": ((n.get("_parent") or {}).get("model") or n.get("model") or "").strip()}

class Plugin:
    async def get_status(self):
        return {"root": os.geteuid() == 0, "euid": os.geteuid(), "e2fsck": shutil.which("e2fsck") or ""}

    async def list_cards(self):
        data = await asyncio.to_thread(lsblk)
        return [info(n) for n in flatten(data.get("blockdevices") or []) if candidate(n)]

    async def repair(self, path: str):
        if os.geteuid() != 0:
            return {"ok": False, "stage": "root", "message": f"ROOT 권한이 없습니다 (EUID={os.geteuid()}). plugin.json의 _root 권한으로 플러그인을 다시 설치하세요."}
        if not shutil.which("e2fsck"):
            return {"ok": False, "stage": "tool", "message": "e2fsck를 찾을 수 없습니다."}
        if not DEV_RE.match(path or ""):
            return {"ok": False, "stage": "validate", "message": "허용되지 않은 장치 경로입니다."}
        data = await asyncio.to_thread(lsblk)
        found = [n for n in flatten(data.get("blockdevices") or []) if n.get("path") == path and candidate(n)]
        if len(found) != 1:
            return {"ok": False, "stage": "validate", "message": "장치가 사라졌거나 안전한 SD/이동식 EXT 파티션이 아닙니다."}
        n = found[0]
        if n.get("ro"):
            return {"ok": False, "stage": "validate", "message": "읽기 전용 장치입니다."}

        was_mounted = bool(mounts(n))
        log = [f"backend EUID={os.geteuid()} (root={os.geteuid() == 0})"]
        if was_mounted:
            rc, out = await asyncio.to_thread(run, "udisksctl", "unmount", "-b", path)
            log.append(f"$ udisksctl unmount -b {path}\n{out}")
            if rc:
                rc, out = await asyncio.to_thread(run, "umount", path)
                log.append(f"$ umount {path}\n{out}")
                if rc:
                    return {"ok": False, "stage": "unmount", "message": "언마운트 실패: 실행 중인 게임/파일 작업을 닫으세요.", "log": "\n".join(log)}

        current = [x for x in flatten((await asyncio.to_thread(lsblk)).get("blockdevices") or []) if x.get("path") == path]
        if not current or mounts(current[0]):
            return {"ok": False, "stage": "unmount", "message": "아직 마운트되어 있어 e2fsck를 실행하지 않았습니다.", "log": "\n".join(log)}

        rc, out = await asyncio.to_thread(run, "e2fsck", "-f", "-y", path, timeout=7200)
        log.append(f"$ e2fsck -f -y {path}\n{out}")
        repair_ok = rc in (0, 1)

        verify_rc = None
        if repair_ok:
            verify_rc, verify_out = await asyncio.to_thread(run, "e2fsck", "-f", "-n", path, timeout=7200)
            log.append(f"$ e2fsck -f -n {path}\n{verify_out}")
            repair_ok = verify_rc == 0

        if was_mounted and repair_ok:
            mrc, mout = await asyncio.to_thread(run, "udisksctl", "mount", "-b", path)
            log.append(f"$ udisksctl mount -b {path}\n{mout}")
            if mrc:
                return {"ok": False, "stage": "remount", "message": "복구 및 검증은 완료됐지만 다시 마운트하지 못했습니다.", "fsck_code": rc, "verify_code": verify_rc, "log": "\n".join(log)}

        if repair_ok:
            return {"ok": True, "stage": "done", "repaired": rc == 1, "fsck_code": rc, "verify_code": verify_rc, "message": "자동복구 후 재검증까지 정상 완료했습니다.", "log": "\n".join(log)}

        # Severe/unresolved filesystem errors: intentionally leave unmounted.
        return {"ok": False, "stage": "verify" if rc in (0, 1) else "fsck", "fsck_code": rc, "verify_code": verify_rc, "message": "자동복구/재검증을 완료하지 못했습니다. 안전을 위해 SD카드를 언마운트 상태로 유지합니다.", "log": "\n".join(log)}

    async def _main(self):
        decky.logger.info("SD Card Repair loaded: euid=%s", os.geteuid())

    async def _unload(self):
        decky.logger.info("SD Card Repair unloaded")
