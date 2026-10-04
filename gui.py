"""Connect EXT4 volumes to Windows Explorer as drive letters."""

from __future__ import annotations

import os
import queue
import shutil
import sys
import threading
import time
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk

from app_info import __app_name__, __version__
from debuglog import LOG, setup_logging
from dnd import DropTarget
from fuse_mount import (
    MountSession,
    _ensure_fuse,
    cleanup_stale_mounts,
    explain_fuse_error,
    free_drive_letters,
    mount_volume,
    open_explorer,
    unmount,
    unmount_all,
    winfsp_available,
)
from io_backend import ImageDevice
from volume import Ext4Volume, VolumeInfo, discover_volumes, format_bytes
from windows_disk import (
    DiskInfo,
    WindowsPhysicalDevice,
    is_admin,
    list_physical_disks,
    restart_as_admin,
)
from winfsp_setup import WinFspSetupError, ensure_winfsp_installed, find_winfsp_dll, winfsp_ready
from usbdk_setup import (
    USBDK_RELEASE_URL,
    UsbDkRequiredError,
    UsbDkSetupError,
    install_usbdk,
    usbdk_ready,
)

BG = "#1e1e2e"
BG2 = "#313244"
BG3 = "#181825"
FG = "#cdd6f4"
FG_DIM = "#a6adc8"
ACCENT = "#89b4fa"


def _kind_icon(kind: str) -> str:
    if "SD" in kind:
        return "SD"
    if kind == "USB":
        return "USB"
    if "SSD" in kind:
        return "SSD"
    if "HDD" in kind:
        return "HDD"
    return "DISK"


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{__app_name__} {__version__}")
        self.geometry("860x720")
        self.minsize(760, 600)
        self.configure(bg=BG)
        self._scan_q: queue.Queue = queue.Queue()
        self._log_q: queue.Queue = queue.Queue()
        self._busy = False
        self._nodes: dict[str, tuple[str, object]] = {}
        self._mounts: dict[str, MountSession] = {}
        self._drop: DropTarget | None = None
        self._style()
        setup_logging(self._log_q)
        try:
            cleanup_stale_mounts()
        except Exception:
            LOG.exception("남은 드라이브 정리 실패")
        self._build()
        self.after(80, self._poll_log)
        self.after(200, self._startup)
        self.after(400, self._hook_dnd)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def _style(self) -> None:
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure(".", background=BG, foreground=FG, fieldbackground=BG2)
        st.configure("TFrame", background=BG)
        st.configure("TLabel", background=BG, foreground=FG, font=("Segoe UI", 10))
        st.configure("Dim.TLabel", background=BG, foreground=FG_DIM, font=("Segoe UI", 9))
        st.configure("Head.TLabel", background=BG, foreground=ACCENT, font=("Segoe UI", 16, "bold"))
        st.configure("TButton", background=BG2, foreground=FG, padding=7, font=("Segoe UI", 10))
        st.map("TButton", background=[("active", ACCENT)])
        st.configure("Accent.TButton", background="#3d5a80", foreground="white", padding=8)
        st.configure("TCheckbutton", background=BG, foreground=FG)
        st.configure("TCombobox", fieldbackground=BG2, background=BG2, foreground=FG)
        st.configure(
            "Treeview",
            background=BG3,
            foreground=FG,
            fieldbackground=BG3,
            rowheight=26,
            font=("Segoe UI", 10),
        )
        st.configure("Treeview.Heading", background=BG2, foreground=FG, font=("Segoe UI", 9, "bold"))
        st.map("Treeview", background=[("selected", "#45475a")], foreground=[("selected", "white")])

    def _build(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill="x", padx=16, pady=(14, 4))
        ttk.Label(top, text=f"{__app_name__} {__version__}", style="Head.TLabel").pack(side="left")
        ttk.Label(top, text="  탐색기 드라이브로 연결", style="Dim.TLabel").pack(side="left")
        self.write_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="쓰기 허용", variable=self.write_var, command=self._on_write_toggle).pack(
            side="right", padx=8
        )
        self.admin_btn = ttk.Button(top, text="관리자 권한으로 다시 시작", command=self._elevate)
        self.admin_badge = tk.Label(
            top,
            text="관리자 실행 중",
            bg="#40a02b",
            fg="white",
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=3,
        )
        if is_admin():
            self.admin_badge.pack(side="right", padx=6)
            self.title(f"{__app_name__} {__version__} — 관리자 실행 중")
            LOG.info("GUI: 관리자 실행 중")
        else:
            self.admin_btn.pack(side="right", padx=4)
            self.title(f"{__app_name__} {__version__} — 관리자 권한 필요")
            LOG.info("GUI: 일반 권한으로 실행 중")

        ttk.Label(
            self,
            text="연결한 뒤 탐색기에서 파일을 끌어다 놓으면 복사됩니다. "
            "이 창으로 끌어다 놓아도 선택한 드라이브로 들어갑니다. 창은 닫지 마세요.",
            style="Dim.TLabel",
            wraplength=780,
        ).pack(fill="x", padx=16, pady=(0, 8))

        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=16, pady=4)
        ttk.Button(bar, text="디스크 다시 검색", command=self.scan_disks).pack(side="left", padx=2)
        ttk.Button(bar, text="이미지 파일 열기…", command=self.open_image).pack(side="left", padx=2)
        ttk.Label(bar, text="  드라이브").pack(side="left", padx=(12, 4))
        self.drive_var = tk.StringVar()
        self.drive_combo = ttk.Combobox(bar, textvariable=self.drive_var, width=6, state="readonly")
        self.drive_combo.pack(side="left")
        self.drive_combo.bind("<Button-1>", lambda _e: self.refresh_drive_letters())
        self.drive_combo.bind("<FocusIn>", lambda _e: self.refresh_drive_letters())
        ttk.Button(bar, text="탐색기에서 열기", style="Accent.TButton", command=self.mount_selected).pack(
            side="left", padx=10
        )
        ttk.Button(bar, text="연결 해제", command=self.unmount_selected).pack(side="left", padx=2)
        ttk.Button(bar, text="로그 복사", command=self.copy_logs).pack(side="right", padx=2)
        ttk.Button(bar, text="WinFsp 설치", command=self.check_winfsp).pack(side="right", padx=2)
        ttk.Button(bar, text="UsbDk 설치(선택)", command=self.check_usbdk).pack(side="right", padx=2)

        self.status = tk.StringVar(
            value="관리자 실행 중 — 디스크를 검색합니다" if is_admin() else "관리자 권한이 필요합니다. 오른쪽 위 버튼으로 다시 시작하세요."
        )
        tk.Label(
            self,
            textvariable=self.status,
            anchor="w",
            bg=BG3,
            fg="#a6e3a1" if is_admin() else FG_DIM,
            font=("Segoe UI", 9),
            padx=16,
            pady=8,
        ).pack(fill="x", side="bottom")

        log_wrap = ttk.Frame(self)
        log_wrap.pack(fill="x", side="bottom", padx=16, pady=(0, 4))
        ttk.Label(log_wrap, text="로그 (복사해서 붙여넣을 수 있습니다)", style="Dim.TLabel").pack(anchor="w")
        log_box = ttk.Frame(log_wrap)
        log_box.pack(fill="x")
        self.log_text = tk.Text(
            log_box,
            height=8,
            wrap="word",
            bg="#11111b",
            fg="#cdd6f4",
            insertbackground="#cdd6f4",
            font=("Consolas", 9),
            relief="flat",
            padx=8,
            pady=6,
        )
        log_scroll = ttk.Scrollbar(log_box, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")

        tk.Label(
            self,
            text="파일을 이 창으로 끌어다 놓으면 연결된 EXT4 드라이브로 복사됩니다.",
            bg="#45475a",
            fg="white",
            font=("Segoe UI", 10),
            pady=8,
        ).pack(fill="x", side="bottom", padx=16, pady=(0, 4))

        cols = ("kind", "size", "state", "drive")
        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True, padx=16, pady=8)
        self.tree = ttk.Treeview(mid, columns=cols, show="tree headings", selectmode="browse")
        self.tree.heading("#0", text="장치 / 볼륨")
        self.tree.heading("kind", text="종류")
        self.tree.heading("size", text="용량")
        self.tree.heading("state", text="상태")
        self.tree.heading("drive", text="드라이브")
        self.tree.column("#0", width=340)
        self.tree.column("kind", width=90)
        self.tree.column("size", width=90, anchor="e")
        self.tree.column("state", width=140)
        self.tree.column("drive", width=80, anchor="center")
        ysb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ysb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda e: self.mount_selected())
        self.refresh_drive_letters()

    def _elevate(self) -> None:
        try:
            hwnd = int(self.winfo_id())
        except Exception:
            hwnd = None
        LOG.info("관리자 권한으로 다시 시작 요청 hwnd=%s", hwnd)
        try:
            ok, err = restart_as_admin(hwnd)
        except Exception as exc:
            LOG.exception("관리자 재시작 실패")
            messagebox.showerror("관리자 권한", str(exc))
            return
        LOG.info("관리자 재시작 결과 ok=%s err=%s", ok, err)
        if ok:
            self.on_close()
            return
        if err:
            messagebox.showerror("관리자 권한", err)

    def _on_write_toggle(self) -> None:
        if self.write_var.get():
            ok = messagebox.askokcancel(
                "쓰기 허용",
                "탐색기에서 파일을 넣거나 지우면 실제 EXT4 디스크에 기록됩니다.\n\n"
                "리눅스에서 해당 파티션을 언마운트한 뒤에만 쓰세요.\n"
                "이미 연결된 드라이브는 해제 후 다시 연결해야 쓰기가 적용됩니다.",
            )
            if not ok:
                self.write_var.set(False)

    def refresh_drive_letters(self) -> None:
        try:
            letters = free_drive_letters()
        except RuntimeError:
            letters = []
        cur = (self.drive_var.get() or "").upper()
        self.drive_combo["values"] = letters
        if cur in letters:
            self.drive_var.set(cur)
        elif letters:
            self.drive_var.set(letters[0])
        else:
            self.drive_var.set("")
        LOG.info("사용 가능한 드라이브 %s (선택 %s)", ",".join(letters) or "(없음)", self.drive_var.get() or "-")

    def _chosen_letter(self) -> str:
        self.refresh_drive_letters()
        letter = (self.drive_var.get() or "").strip()
        if not letter:
            raise RuntimeError("남는 드라이브 문자가 없습니다. 쓰지 않는 문자를 선택하세요.")
        return letter

    def set_status(self, text: str) -> None:
        prefix = "[관리자 실행 중] " if is_admin() else ""
        self.status.set(prefix + text)

    def _append_log(self, line: str) -> None:
        self.log_text.insert("end", line.rstrip() + "\n")
        self.log_text.see("end")

    def _poll_log(self) -> None:
        try:
            while True:
                self._append_log(self._log_q.get_nowait())
        except queue.Empty:
            pass
        self.after(80, self._poll_log)

    def copy_logs(self) -> None:
        text = self.log_text.get("1.0", "end").strip()
        if not text:
            messagebox.showinfo("로그", "아직 복사할 로그가 없습니다.")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.set_status("로그를 클립보드에 복사했습니다.")
        LOG.info("로그 복사됨 (%s자)", len(text))

    def _startup(self) -> None:
        self.ensure_winfsp(show_success=False)
        self.scan_disks()

    def ensure_winfsp(self, force: bool = False, show_success: bool = False) -> bool:
        if not force and winfsp_ready():
            return True
        dlg = tk.Toplevel(self)
        dlg.title("WinFsp 설치")
        dlg.configure(bg=BG)
        dlg.resizable(False, False)
        dlg.transient(self)
        dlg.protocol("WM_DELETE_WINDOW", lambda: None)
        ttk.Label(
            dlg,
            text="탐색기 드라이브에 필요한 WinFsp를 내려받아 설치합니다.",
            wraplength=420,
        ).pack(padx=20, pady=(16, 6))
        status = ttk.Label(dlg, text="준비 중…", wraplength=420)
        status.pack(padx=20, pady=(0, 16))
        dlg.update_idletasks()
        dlg.geometry(f"+{self.winfo_rootx() + 80}+{self.winfo_rooty() + 80}")
        dlg.grab_set()
        q: queue.Queue = queue.Queue()

        def work():
            try:
                path = ensure_winfsp_installed(progress=lambda m: q.put(("p", m)), force=force)
                q.put(("ok", path))
            except Exception as exc:
                q.put(("err", exc))

        threading.Thread(target=work, daemon=True).start()
        result: dict = {"ok": False, "err": None, "path": None}

        def poll():
            try:
                kind, payload = q.get_nowait()
            except queue.Empty:
                dlg.after(80, poll)
                return
            if kind == "p":
                status.config(text=str(payload))
                dlg.after(80, poll)
                return
            if kind == "ok":
                result["ok"] = True
                result["path"] = payload
            else:
                result["err"] = payload
            dlg.grab_release()
            dlg.destroy()

        poll()
        self.wait_window(dlg)
        if result["ok"]:
            if show_success:
                messagebox.showinfo("WinFsp", f"설치되어 있습니다.\n\n{result['path']}")
            else:
                self.set_status("WinFsp 설치가 완료되었습니다.")
            return True
        err = result["err"]
        if isinstance(err, WinFspSetupError) and err.reboot_required:
            if messagebox.askyesno("재시작 필요", f"{err}\n\n지금 PC를 재시작할까요?"):
                os.system("shutdown /r /t 5")
            return False
        if err is not None:
            messagebox.showerror("WinFsp 설치 실패", str(err))
        return winfsp_ready()

    def check_winfsp(self) -> None:
        dll = find_winfsp_dll()
        if dll:
            if not messagebox.askyesno(
                "WinFsp",
                f"이미 설치되어 있습니다.\n\n{dll}\n\n다시 설치할까요?",
            ):
                return
            self.ensure_winfsp(force=True, show_success=True)
            return
        self.ensure_winfsp(force=False, show_success=True)

    def ensure_usbdk(self, show_success: bool = True) -> bool:
        if usbdk_ready():
            if show_success:
                messagebox.showinfo(
                    "UsbDk",
                    "UsbDk가 이미 설치되어 실행 중입니다.\n\n"
                    "일반 리더기는 기존 Windows 경로를 그대로 사용하고, "
                    "모든 raw-write 경로가 거부되는 USB 리더기에서만 UsbDk를 사용합니다.",
                )
            return True

        dlg = tk.Toplevel(self)
        dlg.title("UsbDk 선택 설치")
        dlg.configure(bg=BG)
        dlg.resizable(False, False)
        dlg.transient(self)
        dlg.protocol("WM_DELETE_WINDOW", lambda: None)
        ttk.Label(
            dlg,
            text=(
                "공식 UsbDk 1.0.22 x64 MSI를 GitHub에서 내려받아 SHA-256을 확인한 뒤 설치합니다.\n"
                "UsbDk는 시스템 USB 필터 드라이버이므로 선택 설치이며, 일반 리더기에는 사용하지 않습니다."
            ),
            wraplength=500,
        ).pack(padx=20, pady=(16, 6))
        status = ttk.Label(dlg, text="준비 중…", wraplength=500)
        status.pack(padx=20, pady=(0, 16))
        dlg.update_idletasks()
        dlg.geometry(f"+{self.winfo_rootx() + 80}+{self.winfo_rooty() + 80}")
        dlg.grab_set()
        q: queue.Queue = queue.Queue()

        def work():
            try:
                result = install_usbdk(progress=lambda m: q.put(("p", m)))
                q.put(("ok", result))
            except Exception as exc:
                q.put(("err", exc))

        threading.Thread(target=work, daemon=True).start()
        result_box: dict = {"result": None, "err": None}

        def poll():
            try:
                kind, payload = q.get_nowait()
            except queue.Empty:
                dlg.after(80, poll)
                return
            if kind == "p":
                status.config(text=str(payload))
                dlg.after(80, poll)
                return
            if kind == "ok":
                result_box["result"] = payload
            else:
                result_box["err"] = payload
            dlg.grab_release()
            dlg.destroy()

        poll()
        self.wait_window(dlg)

        result = result_box["result"]
        if result is not None:
            if result.reboot_required:
                if messagebox.askyesno(
                    "UsbDk 설치 완료 — 재시작 필요",
                    "UsbDk 설치가 완료됐지만 적용을 위해 Windows 재시작이 필요합니다.\n\n"
                    "지금 PC를 재시작할까요?",
                ):
                    os.system("shutdown /r /t 5")
                return False
            if show_success:
                messagebox.showinfo(
                    "UsbDk 설치 완료",
                    "UsbDk가 준비되었습니다.\n\n"
                    "카드리더를 다시 꽂거나 디스크 다시 검색 후 쓰기 연결을 다시 시도하세요. "
                    "UsbDk는 Windows raw-write가 모두 실패하는 USB 리더기에만 자동 사용됩니다.",
                )
            return True

        err = result_box["err"]
        if err is not None:
            LOG.error("UsbDk 설치 실패: %s", err)
            message = str(err)
            if isinstance(err, UsbDkSetupError) and err.manual_install:
                message += "\n\n자동 설치가 안 되면 공식 릴리스에서 직접 설치할 수 있습니다."
                if messagebox.askyesno(
                    "UsbDk 설치 실패",
                    message + "\n\n공식 UsbDk 릴리스 페이지를 열까요?",
                ):
                    webbrowser.open(USBDK_RELEASE_URL)
            else:
                messagebox.showerror("UsbDk 설치 실패", message)
        return usbdk_ready()

    def check_usbdk(self) -> None:
        if usbdk_ready():
            self.ensure_usbdk(show_success=True)
            return
        ok = messagebox.askyesno(
            "UsbDk 선택 설치",
            "UsbDk는 Windows의 일반 raw-write 경로가 전부 차단되는 일부 USB 카드리더를 위한 "
            "마지막 fallback입니다.\n\n"
            "설치하면 시스템 USB 필터 드라이버가 추가되므로 재부팅이 필요할 수 있고, "
            "문제가 생기면 Windows의 '설치된 앱' 또는 UsbDkController -u로 제거할 수 있습니다.\n\n"
            "공식 UsbDk 1.0.22를 다운로드하고 설치할까요?",
        )
        if ok:
            self.ensure_usbdk(show_success=True)

    def scan_disks(self) -> None:
        if self._busy:
            return
        self._busy = True
        self.set_status("디스크를 검색하는 중… (HDD, SSD, USB, SD 카드)")
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._nodes.clear()

        def work():
            try:
                disks = list_physical_disks()
                result = []
                for d in disks:
                    vols, err = [], d.error
                    try:
                        if not d.size:
                            result.append((d, [], d.error))
                            continue
                        dev = WindowsPhysicalDevice(d.path, d.sector_size, writable=False)
                        try:
                            vols = discover_volumes(dev)
                        finally:
                            dev.close()
                    except Exception as exc:
                        err = str(exc)
                    result.append((d, vols, err))
                self._scan_q.put(("ok", result))
            except Exception as exc:
                self._scan_q.put(("err", str(exc)))

        threading.Thread(target=work, daemon=True).start()
        self.after(80, self._poll_scan)

    def _poll_scan(self) -> None:
        try:
            kind, payload = self._scan_q.get_nowait()
        except queue.Empty:
            self.after(80, self._poll_scan)
            return
        self._busy = False
        if kind == "err":
            self.set_status(f"검색 실패: {payload}")
            return
        ext_count = 0
        for disk, vols, err in payload:
            did = self.tree.insert(
                "",
                "end",
                text=f"{_kind_icon(disk.kind)}  {disk.title}",
                values=(disk.bus_name, format_bytes(disk.size), err or "연결됨", ""),
                open=True,
            )
            self._nodes[did] = ("disk", disk)
            if not vols:
                self.tree.insert(did, "end", text="EXT 파티션 없음", values=("", "", "", ""))
                continue
            for v in vols:
                key = self._vol_key("disk", disk.path, v)
                mounted = key in self._mounts
                letter = self._mounts[key].letter if mounted else ""
                state = f"연결됨 {letter}" if mounted else ("쓰기 가능" if not v.write_blockers else "읽기 전용")
                vid = self.tree.insert(
                    did,
                    "end",
                    text=f"{v.sb.fs_type}  {v.label}",
                    values=(
                        v.scheme or "파티션",
                        format_bytes(v.sb.blocks_count * v.sb.block_size),
                        state,
                        letter,
                    ),
                )
                self._nodes[vid] = ("vol", (disk, v))
                ext_count += 1
        extra = "  · 관리자 실행 중" if is_admin() else "  · 물리 디스크는 관리자 권한으로 실행하세요"
        winfsp = "  · WinFsp 준비됨" if winfsp_ready() else "  · WinFsp 설치가 필요합니다"
        self.set_status(f"디스크 {len(payload)}개, EXT 볼륨 {ext_count}개{extra}{winfsp}")
        LOG.info("검색 완료 disks=%s ext=%s admin=%s", len(payload), ext_count, is_admin())
        self.refresh_drive_letters()

    def open_image(self) -> None:
        path = filedialog.askopenfilename(
            title="디스크 이미지 열기",
            filetypes=[
                ("디스크 이미지", "*.img *.raw *.iso *.bin *.dd"),
                ("모든 파일", "*.*"),
            ],
        )
        if not path:
            return
        try:
            with ImageDevice(path, writable=False) as dev:
                size = dev.size()
                vols = discover_volumes(dev)
            if not vols:
                messagebox.showerror("EXT4 없음", "이 파일에서 EXT 슈퍼블록을 찾지 못했습니다.")
                return
            nid = self.tree.insert(
                "",
                "end",
                text=f"IMG  {os.path.basename(path)}",
                values=("이미지", format_bytes(size), "파일", ""),
                open=True,
            )
            self._nodes[nid] = ("image", path)
            for x in vols:
                vid = self.tree.insert(
                    nid,
                    "end",
                    text=f"{x.sb.fs_type}  {x.label}",
                    values=(
                        x.scheme or "파티션",
                        format_bytes(x.sb.blocks_count * x.sb.block_size),
                        "읽기 전용" if x.write_blockers else "쓰기 가능",
                        "",
                    ),
                )
                self._nodes[vid] = ("imgvol", (path, x))
            self.tree.selection_set(vid)
            self.set_status(f"이미지에서 EXT 볼륨 {len(vols)}개를 찾았습니다. 더블클릭하면 탐색기가 열립니다.")
        except Exception as exc:
            messagebox.showerror("열기 실패", str(exc))

    def _selected_volume(self):
        sel = self.tree.selection()
        if not sel:
            return None
        return self._nodes.get(sel[0])

    def _vol_key(self, kind: str, path: str, vinfo: VolumeInfo) -> str:
        return f"{kind}:{path}:{vinfo.offset}"

    def _run_with_progress(self, title: str, message: str, func):
        """Run blocking storage work off the Tk thread while keeping the UI responsive."""
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.transient(self)
        dialog.resizable(False, False)
        dialog.configure(bg=BG)
        dialog.protocol("WM_DELETE_WINDOW", lambda: None)

        frame = ttk.Frame(dialog, padding=16)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text=message, wraplength=420, justify="left").pack(
            fill="x", pady=(0, 10)
        )
        detail = tk.StringVar(value="장치 응답을 기다리는 중…")
        ttk.Label(frame, textvariable=detail, style="Dim.TLabel").pack(
            fill="x", pady=(0, 8)
        )
        progress = ttk.Progressbar(frame, mode="indeterminate", length=420)
        progress.pack(fill="x")
        progress.start(12)

        state: dict[str, object] = {}
        finished = threading.Event()
        done_var = tk.BooleanVar(self, value=False)
        started = time.monotonic()

        def worker() -> None:
            try:
                state["result"] = func()
            except BaseException as exc:
                state["error"] = exc
            finally:
                finished.set()

        def poll() -> None:
            if finished.is_set():
                done_var.set(True)
                return
            elapsed = max(0, int(time.monotonic() - started))
            detail.set(
                f"작업 중… {elapsed}초  ·  Windows raw I/O / UsbDk 응답 확인 중"
            )
            self.after(100, poll)

        thread = threading.Thread(
            target=worker,
            daemon=True,
            name="ext4-storage-operation",
        )
        thread.start()
        self.after(100, poll)

        try:
            dialog.grab_set()
            self.wait_variable(done_var)
        finally:
            try:
                progress.stop()
                dialog.grab_release()
            except tk.TclError:
                pass
            try:
                dialog.destroy()
            except tk.TclError:
                pass

        if "error" in state:
            raise state["error"]
        return state.get("result")

    def mount_selected(self) -> None:
        node = self._selected_volume()
        if not node:
            messagebox.showinfo("선택", "왼쪽에서 EXT4 볼륨을 선택하세요.")
            return
        kind, payload = node
        if kind == "vol":
            disk, vinfo = payload
            key = self._vol_key("disk", disk.path, vinfo)
            opener = lambda writable: WindowsPhysicalDevice(
                disk.path,
                disk.sector_size,
                writable=writable,
                partition_number=vinfo.partition_index,
                partition_offset=vinfo.offset,
                partition_size=vinfo.size,
            )
            src = disk.path
        elif kind == "imgvol":
            path, vinfo = payload
            key = self._vol_key("image", path, vinfo)
            opener = lambda writable: ImageDevice(path, writable=writable)
            src = path
        else:
            messagebox.showinfo("선택", "EXT4 볼륨 줄을 선택한 뒤 다시 시도하세요.")
            return

        if key in self._mounts:
            session = self._mounts[key]
            want_write = bool(self.write_var.get())
            if want_write and session.read_only:
                letter_keep = session.letter
                if not messagebox.askyesno(
                    "쓰기로 다시 연결",
                    f"{letter_keep} 는 지금 읽기 전용입니다.\n"
                    "연결을 해제하고 같은 문자로 쓰기를 열어 다시 연결할까요?",
                ):
                    open_explorer(letter_keep)
                    return
                LOG.info("읽기 전용 %s 를 해제하고 쓰기로 다시 연결합니다", letter_keep)
                self._drop_mount(key)
                deadline = time.time() + 6
                while time.time() < deadline:
                    self.refresh_drive_letters()
                    if letter_keep in (self.drive_combo["values"] or ()):
                        self.drive_var.set(letter_keep)
                        break
                    time.sleep(0.2)
                else:
                    self.drive_var.set(letter_keep)
            else:
                open_explorer(session.letter)
                self.set_status(f"이미 {session.letter} 로 연결되어 있습니다.")
                return

        if not winfsp_available():
            if not self.ensure_winfsp():
                return

        writable = bool(self.write_var.get())
        if writable and kind == "vol" and not is_admin():
            messagebox.showwarning("권한", "물리 디스크에 쓰려면 관리자 권한으로 다시 시작하세요. 읽기 전용으로 엽니다.")
            writable = False

        try:
            letter = self._chosen_letter()
            self.set_status(f"{letter} 드라이브로 연결하는 중…")
            self.update_idletasks()
            LOG.info(
                "마운트 요청 src=%s offset=%s writable=%s admin=%s letter=%s",
                src,
                vinfo.offset,
                writable,
                is_admin(),
                letter,
            )
            # PyInstaller one-file builds load Python modules from the EXE
            # archive. Load the FUSE runtime before spawning any LocalSystem
            # helper so read-only fallback never needs a late archive import.
            _ensure_fuse()
            LOG.info("FUSE 런타임 사전 로드 완료")
            dev = opener(writable)
            vol = Ext4Volume(dev, vinfo.offset, vinfo.size, owns_device=True)
            LOG.info(
                "볼륨 label=%s type=%s blocks=%s block_size=%s inode_size=%s",
                vol.sb.volume_name,
                vol.sb.fs_type,
                vol.sb.blocks_count,
                vol.sb.block_size,
                vol.sb.inode_size,
            )
            read_only = not writable
            if writable:
                recovery_stats = None
                if vol.journal_needs_recovery() or vol.sb.needs_recovery:
                    try:
                        self.set_status("EXT4 저널을 Windows에서 복구하는 중…")
                        self.update_idletasks()
                        recovery_stats = self._run_with_progress(
                            "EXT4 저널 복구 중",
                            "저널을 안전하게 재생하고 있습니다.\n"
                            "Windows raw-write가 차단되면 LocalSystem/UsbDk 경로를 순서대로 확인합니다.\n"
                            "이 작업 동안 창은 계속 응답합니다.",
                            vol.recover_pending_journal,
                        )
                        LOG.info(
                            "Windows JBD2 복구 성공 transactions=%s replayed=%s revoked=%s",
                            recovery_stats.transactions,
                            recovery_stats.replayed_blocks,
                            recovery_stats.revoked_blocks,
                        )
                    except UsbDkRequiredError as exc:
                        LOG.exception("Windows JBD2 복구 중 UsbDk 필요")
                        try:
                            vol.dev.close()
                        except Exception:
                            LOG.exception("UsbDk 설치 전 장치 닫기 실패")
                        install_now = messagebox.askyesno(
                            "이 USB 카드리더에는 UsbDk가 필요합니다",
                            str(exc)
                            + "\n\n일반 Windows/관리자/LocalSystem raw-write 경로는 이미 모두 실패했습니다. "
                            "다른 리더기에는 기존 경로를 계속 사용하고, 이 경우에만 UsbDk direct-USB fallback을 사용합니다.\n\n"
                            "공식 UsbDk를 다운로드하고 설치할까요?",
                        )
                        if install_now:
                            ready = self.ensure_usbdk(show_success=True)
                            if ready:
                                self.set_status("UsbDk 준비 완료 — 카드리더를 다시 검색한 뒤 연결을 다시 시도하세요.")
                        else:
                            self.set_status("UsbDk 설치를 취소했습니다.")
                        return
                    except Exception as exc:
                        LOG.exception("Windows JBD2 복구 실패")
                        messagebox.showwarning(
                            "저널 자동 복구 실패 — 읽기 전용으로 연결",
                            "EXT4 저널을 Windows에서 안전하게 복구하지 못했습니다.\n"
                            "원본 보호를 위해 읽기 전용으로 연결합니다.\n\n"
                            + str(exc),
                        )
                hard = vol.hard_write_blockers()
                soft = vol.soft_write_warnings()
                LOG.info("쓰기 검사 hard=%s soft=%s", hard, soft)
                if hard:
                    messagebox.showwarning(
                        "쓰기 불가 — 읽기 전용으로 연결",
                        "쓸 수 없는 이유:\n- " + "\n- ".join(hard),
                    )
                    read_only = True
                elif soft:
                    ok = messagebox.askyesno(
                        "쓰기 주의",
                        "이 디스크는 리눅스에서 완전히 끄지 않고 뺀 상태일 수 있습니다.\n- "
                        + "\n- ".join(soft)
                        + "\n\n그래도 Windows에서 파일을 복사·저장할까요?\n"
                        "리눅스가 아직 이 USB를 쓰는 중이면 데이터가 깨질 수 있습니다.",
                    )
                    if ok:
                        LOG.warning("사용자가 쓰기 위험을 감수함: %s", soft)
                    else:
                        read_only = True
                        LOG.info("사용자가 쓰기를 취소하고 읽기 전용으로 연결")
            LOG.info("실제 마운트 모드 read_only=%s letter=%s", read_only, letter)
            label = vol.sb.volume_name or vinfo.label or "EXT4"
            session = mount_volume(vol, read_only=read_only, label=label, letter=letter)
            self._mounts[key] = session
            mode = "읽기 전용" if read_only else "읽기/쓰기"
            self.tree.set(self.tree.selection()[0], "state", f"연결됨 ({mode})")
            self.tree.set(self.tree.selection()[0], "drive", session.letter)
            self.refresh_drive_letters()
            open_explorer(session.letter)
            self.set_status(
                f"{session.letter} 드라이브로 연결했습니다 ({mode}). "
                f"내 PC에서 {session.letter} 를 쓰세요."
            )
        except Exception as exc:
            LOG.exception("연결 실패 src=%s", src)
            messagebox.showerror(
                "연결 실패",
                explain_fuse_error(exc) + "\n\n아래 로그를 복사해 주세요. 콘솔 창에도 같은 내용이 있습니다.",
            )
            self.set_status(f"연결 실패: {exc}")

    def unmount_selected(self) -> None:
        node = self._selected_volume()
        if not node:
            return
        kind, payload = node
        if kind == "vol":
            disk, vinfo = payload
            key = self._vol_key("disk", disk.path, vinfo)
        elif kind == "imgvol":
            path, vinfo = payload
            key = self._vol_key("image", path, vinfo)
        else:
            return
        self._drop_mount(key)
        sel = self.tree.selection()
        if sel:
            self.tree.set(sel[0], "state", "해제됨")
            self.tree.set(sel[0], "drive", "")
        self.refresh_drive_letters()
        self.set_status("연결을 해제했습니다.")

    def _drop_mount(self, key: str) -> None:
        session = self._mounts.pop(key, None)
        if not session:
            return
        try:
            unmount(session.letter)
        except Exception:
            LOG.exception("연결 해제 실패 %s", session.letter)

    def _hook_dnd(self) -> None:
        try:
            self.update_idletasks()
            self._drop = DropTarget(self, self.on_drop)
        except Exception:
            self.set_status("창으로 끌어다 놓기는 사용할 수 없습니다. 탐색기에서 드라이브로 드래그하세요.")

    def _mount_key_for_node(self, node) -> str | None:
        if not node:
            return None
        kind, payload = node
        if kind == "vol":
            disk, vinfo = payload
            return self._vol_key("disk", disk.path, vinfo)
        if kind == "imgvol":
            path, vinfo = payload
            return self._vol_key("image", path, vinfo)
        return None

    def _target_letter(self) -> str | None:
        key = self._mount_key_for_node(self._selected_volume())
        if key and key in self._mounts:
            return self._mounts[key].letter
        if len(self._mounts) == 1:
            return next(iter(self._mounts.values())).letter
        return None

    def on_drop(self, files: list[str]) -> None:
        files = [f for f in files if f]
        if not files:
            return
        letter = self._target_letter()
        if not letter:
            if not self.write_var.get():
                messagebox.showinfo(
                    "끌어다 넣기",
                    "탐색기에서 넣으려면 «쓰기 허용»을 켠 뒤 EXT4 볼륨을 연결하세요.\n"
                    "그다음 내 PC의 드라이브로 파일을 끌어다 놓으면 됩니다.",
                )
                return
            self.mount_selected()
            letter = self._target_letter()
        if not letter:
            messagebox.showinfo("대상", "먼저 EXT4 볼륨을 선택하고 «탐색기에서 열기»로 연결하세요.")
            return
        dest_root = letter + "\\"
        ok = 0
        errors = []
        for src in files:
            name = os.path.basename(src.rstrip("\\/"))
            dest = os.path.join(dest_root, name)
            try:
                if os.path.isdir(src):
                    shutil.copytree(src, dest, dirs_exist_ok=True)
                else:
                    shutil.copy2(src, dest)
                ok += 1
            except Exception as exc:
                errors.append(f"{name}: {exc}")
        if errors:
            messagebox.showerror("복사 실패", "\n".join(errors[:8]))
        self.set_status(f"{ok}개 항목을 {letter} 로 복사했습니다. 탐색기에서 확인하세요.")
        try:
            open_explorer(letter)
        except Exception:
            pass

    def on_close(self) -> None:
        self.set_status("드라이브를 해제하는 중…")
        try:
            self.update_idletasks()
        except Exception:
            pass
        if self._drop:
            try:
                self._drop.close()
            except Exception:
                pass
        for key in list(self._mounts):
            self._drop_mount(key)
        try:
            unmount_all()
        except Exception:
            LOG.exception("종료 시 드라이브 해제 실패")
        self.destroy()


def main() -> None:
    if sys.platform != "win32":
        print("이 프로그램은 Windows용입니다.")
    app = App()
    app.mainloop()
