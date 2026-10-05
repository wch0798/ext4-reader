import asyncio
import json
import re
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
    async def list_cards(self):
        data = await asyncio.to_thread(lsblk)
        return [info(n) for n in flatten(data.get("blockdevices") or []) if candidate(n)]

    async def repair(self, path: str):
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
        log = []
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
        rc, out = await asyncio.to_thread(run, "e2fsck", "-f", "-p", path, timeout=7200)
        log.append(f"$ e2fsck -f -p {path}\n{out}")
        ok = rc in (0, 1)
        if was_mounted:
            mrc, mout = await asyncio.to_thread(run, "udisksctl", "mount", "-b", path)
            log.append(f"$ udisksctl mount -b {path}\n{mout}")
            if mrc and ok:
                return {"ok": False, "stage": "remount", "message": "검사는 정상 완료됐지만 다시 마운트하지 못했습니다.", "fsck_code": rc, "log": "\n".join(log)}
        if ok:
            return {"ok": True, "stage": "done", "repaired": rc == 1, "fsck_code": rc, "message": "오류를 자동 복구했습니다." if rc == 1 else "파일시스템이 정상입니다.", "log": "\n".join(log)}
        return {"ok": False, "stage": "fsck", "fsck_code": rc, "message": f"e2fsck 자동 복구를 완료하지 못했습니다 (종료 코드 {rc}).", "log": "\n".join(log)}

    async def _main(self):
        decky.logger.info("SD Card Repair loaded")

    async def _unload(self):
        decky.logger.info("SD Card Repair unloaded")
