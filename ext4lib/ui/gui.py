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

from ext4lib import __app_name__, __version__
from ext4lib.i18n import (
    LANGUAGES,
    OWNER_MODES,
    language_from_label,
    language_label,
    load_language,
    load_owner_mode,
    save_language,
    save_owner_mode,
    tr,
)
from ext4lib.debuglog import LOG, setup_logging
from ext4lib.ui.dnd import DropTarget
from ext4lib.mount.fuse import (
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
from ext4lib.io.backend import ImageDevice
from ext4lib.fs import constants as C
from ext4lib.fs.volume import Ext4Volume, VolumeInfo, discover_volumes, format_bytes, probe_superblock
from ext4lib.windows.disk import (
    DiskInfo,
    WindowsPhysicalDevice,
    is_admin,
    list_physical_disks,
    restart_as_admin,
)
from ext4lib.windows.winfsp_setup import WinFspSetupError, ensure_winfsp_installed, find_winfsp_dll, winfsp_ready
from ext4lib.windows.usbdk_setup import (
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
        self._operation_active = False
        self.language = load_language()
        self.owner_mode = load_owner_mode()
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

    def _t(self, key: str, **kwargs) -> str:
        return tr(self.language, key, **kwargs)

    def _on_language_change(self, _event=None) -> None:
        language = language_from_label(self.language_var.get())
        if language == self.language:
            return
        self.language = language
        save_language(language)
        messagebox.showinfo(
            self._t("language_changed_title"),
            self._t("language_changed_message"),
            parent=self,
        )

    def _owner_labels(self) -> dict[str, str]:
        return {
            "deck": self._t("owner_deck"),
            "root": self._t("owner_root"),
        }

    def _on_owner_change(self, _event=None) -> None:
        label = self.owner_var.get()
        labels = self._owner_labels()
        mode = next(
            (key for key, value in labels.items() if value == label),
            "deck",
        )
        self.owner_mode = mode
        save_owner_mode(mode)
        uid, gid = OWNER_MODES[mode]
        LOG.info(
            "Linux 신규 inode 소유자 선택 mode=%s uid=%s gid=%s",
            mode,
            uid,
            gid,
        )

    def _apply_owner_mode(self, vol: Ext4Volume) -> None:
        mode = self.owner_mode if self.owner_mode in OWNER_MODES else "deck"
        uid, gid = OWNER_MODES[mode]
        vol.default_uid = uid
        vol.default_gid = gid
        vol.default_file_mode = C.DEFAULT_LINUX_FILE_MODE
        vol.default_dir_mode = C.DEFAULT_LINUX_DIR_MODE
        LOG.info(
            "Linux 신규 inode 적용 mode=%s uid=%s gid=%s file_mode=%04o dir_mode=%04o",
            mode,
            uid,
            gid,
            vol.default_file_mode,
            vol.default_dir_mode,
        )

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
            "Visible.TCombobox",
            fieldbackground=BG2,
            background=BG2,
            foreground=FG,
            arrowcolor=FG,
        )
        st.map(
            "Visible.TCombobox",
            fieldbackground=[("readonly", BG2), ("disabled", BG2)],
            background=[("readonly", BG2), ("disabled", BG2)],
            foreground=[("readonly", FG), ("disabled", FG_DIM)],
            selectbackground=[("readonly", BG2)],
            selectforeground=[("readonly", FG)],
            arrowcolor=[("readonly", FG), ("disabled", FG_DIM)],
        )
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
        ttk.Label(top, text=self._t("subtitle"), style="Dim.TLabel").pack(side="left")
        self.language_var = tk.StringVar(value=language_label(self.language))
        self.language_combo = ttk.Combobox(
            top,
            textvariable=self.language_var,
            values=list(LANGUAGES.values()),
            width=9,
            state="readonly",
            style="Visible.TCombobox",
        )
        self.language_combo.pack(side="right", padx=(4, 0))
        language_codes = list(LANGUAGES)
        if self.language in language_codes:
            self.language_combo.current(language_codes.index(self.language))
        else:
            self.language_combo.current(0)
        self.language_combo.bind("<<ComboboxSelected>>", self._on_language_change)
        ttk.Label(top, text=self._t("language")).pack(side="right", padx=(12, 2))

        self.write_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text=self._t("write_enable"), variable=self.write_var, command=self._on_write_toggle).pack(
            side="right", padx=8
        )
        self.admin_btn = ttk.Button(top, text=self._t("admin_restart"), command=self._elevate)
        self.admin_badge = tk.Label(
            top,
            text=self._t("admin_running"),
            bg="#40a02b",
            fg="white",
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=3,
        )
        if is_admin():
            self.admin_badge.pack(side="right", padx=6)
            self.title(f"{__app_name__} {__version__} — {self._t('admin_running')}")
            LOG.info("GUI: EXT4 Reader v%s 관리자 실행 중", __version__)
        else:
            self.admin_btn.pack(side="right", padx=4)
            self.title(f"{__app_name__} {__version__} — {self._t('admin_required')}")
            LOG.info("GUI: EXT4 Reader v%s 일반 권한으로 실행 중", __version__)

        ttk.Label(
            self,
            text=self._t("main_hint"),
            style="Dim.TLabel",
            wraplength=780,
        ).pack(fill="x", padx=16, pady=(0, 8))

        owner_bar = ttk.Frame(self)
        owner_bar.pack(fill="x", padx=16, pady=(0, 2))
        ttk.Label(owner_bar, text=self._t("linux_owner")).pack(
            side="left", padx=(2, 6)
        )
        owner_labels = self._owner_labels()
        owner_values = [owner_labels["deck"], owner_labels["root"]]
        self.owner_var = tk.StringVar()
        self.owner_combo = ttk.Combobox(
            owner_bar,
            textvariable=self.owner_var,
            values=owner_values,
            width=31,
            state="readonly",
            style="Visible.TCombobox",
        )
        self.owner_combo.pack(side="left")
        owner_index = 1 if self.owner_mode == "root" else 0
        self.owner_combo.current(owner_index)
        self.owner_var.set(owner_values[owner_index])
        self.owner_combo.bind(
            "<<ComboboxSelected>>",
            self._on_owner_change,
        )

        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=16, pady=4)
        ttk.Button(bar, text=self._t("scan"), command=self.scan_disks).pack(side="left", padx=2)
        ttk.Button(bar, text=self._t("open_image"), command=self.open_image).pack(side="left", padx=2)
        ttk.Label(bar, text="  " + self._t("drive")).pack(side="left", padx=(12, 4))
        self.drive_var = tk.StringVar()
        self.drive_combo = ttk.Combobox(
            bar,
            textvariable=self.drive_var,
            width=6,
            state="readonly",
            style="Visible.TCombobox",
        )
        self.drive_combo.pack(side="left")
        self.drive_combo.bind("<Button-1>", lambda _e: self.refresh_drive_letters())
        self.drive_combo.bind("<FocusIn>", lambda _e: self.refresh_drive_letters())
        ttk.Button(bar, text=self._t("open_explorer"), style="Accent.TButton", command=self.mount_selected).pack(
            side="left", padx=10
        )
        ttk.Button(bar, text=self._t("disconnect"), command=self.unmount_selected).pack(side="left", padx=2)
        ttk.Button(bar, text=self._t("copy_log"), command=self.copy_logs).pack(side="right", padx=2)
        ttk.Button(bar, text=self._t("install_winfsp"), command=self.check_winfsp).pack(side="right", padx=2)
        ttk.Button(bar, text=self._t("install_usbdk"), command=self.check_usbdk).pack(side="right", padx=2)

        self.status = tk.StringVar(
            value=self._t("status_admin_scanning") if is_admin() else self._t("status_admin_required")
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
        ttk.Label(log_wrap, text=self._t("log_caption"), style="Dim.TLabel").pack(anchor="w")
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
            text=self._t("drop_hint"),
            bg="#45475a",
            fg="white",
            font=("Segoe UI", 10),
            pady=8,
        ).pack(fill="x", side="bottom", padx=16, pady=(0, 4))

        cols = ("kind", "size", "state", "drive")
        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True, padx=16, pady=8)
        self.tree = ttk.Treeview(mid, columns=cols, show="tree headings", selectmode="browse")
        self.tree.heading("#0", text=self._t("tree_device"))
        self.tree.heading("kind", text=self._t("tree_kind"))
        self.tree.heading("size", text=self._t("tree_size"))
        self.tree.heading("state", text=self._t("tree_state"))
        self.tree.heading("drive", text=self._t("tree_drive"))
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
            messagebox.showerror(self._t("admin_required"), str(exc), parent=self)
            return
        LOG.info("관리자 재시작 결과 ok=%s err=%s", ok, err)
        if ok:
            self.on_close()
            return
        if err:
            messagebox.showerror(self._t("admin_required"), err, parent=self)

    def _on_write_toggle(self) -> None:
        if self.write_var.get():
            ok = messagebox.askokcancel(
                self._t("write_enable_title"),
                self._t("write_enable_message"),
                parent=self,
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
            index = letters.index(cur)
            self.drive_combo.current(index)
            self.drive_var.set(cur)
        elif letters:
            self.drive_combo.current(0)
            self.drive_var.set(letters[0])
        else:
            self.drive_combo.set("")
            self.drive_var.set("")
        LOG.info("사용 가능한 드라이브 %s (선택 %s)", ",".join(letters) or "(없음)", self.drive_var.get() or "-")

    def _chosen_letter(self) -> str:
        self.refresh_drive_letters()
        letter = (self.drive_var.get() or "").strip()
        if not letter:
            raise RuntimeError(self._t("no_drive_letter"))
        return letter

    def set_status(self, text: str) -> None:
        prefix = self._t("admin_prefix") if is_admin() else ""
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
            messagebox.showinfo(self._t("log_title"), self._t("log_empty"), parent=self)
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.set_status(self._t("log_copied"))
        LOG.info("로그 복사됨 (%s자)", len(text))

    def _startup(self) -> None:
        self.ensure_winfsp(show_success=False)
        self.scan_disks()

    def ensure_winfsp(self, force: bool = False, show_success: bool = False) -> bool:
        if not force and winfsp_ready():
            return True
        try:
            path = self._run_with_progress(
                self._t("winfsp_installing"),
                self._t("winfsp_install_desc"),
                lambda report: ensure_winfsp_installed(progress=report, force=force),
                progress_aware=True,
            )
        except WinFspSetupError as err:
            if err.reboot_required:
                if messagebox.askyesno(self._t("reboot_required"), self._t("reboot_now", error=err), parent=self):
                    os.system("shutdown /r /t 5")
                return False
            messagebox.showerror(self._t("winfsp_install_failed"), str(err), parent=self)
            return winfsp_ready()
        except Exception as err:
            messagebox.showerror(self._t("winfsp_install_failed"), str(err), parent=self)
            return winfsp_ready()

        if show_success:
            messagebox.showinfo("WinFsp", self._t("winfsp_installed", path=path), parent=self)
        else:
            self.set_status(self._t("winfsp_done"))
        return True

    def check_winfsp(self) -> None:
        dll = find_winfsp_dll()
        if dll:
            if not messagebox.askyesno(
                "WinFsp",
                self._t("winfsp_reinstall", path=dll),
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
                    self._t("usbdk_already"),
                )
            return True

        try:
            result = self._run_with_progress(
                self._t("usbdk_installing"),
                self._t("usbdk_install_desc"),
                lambda report: install_usbdk(progress=report),
                progress_aware=True,
            )
        except Exception as err:
            LOG.error("UsbDk 설치 실패: %s", err)
            message = str(err)
            if isinstance(err, UsbDkSetupError) and err.manual_install:
                message += self._t("usbdk_manual")
                if messagebox.askyesno(
                    self._t("usbdk_install_failed"),
                    message + self._t("usbdk_open_release"),
                ):
                    webbrowser.open(USBDK_RELEASE_URL)
            else:
                messagebox.showerror(self._t("usbdk_install_failed"), message, parent=self)
            return usbdk_ready()

        if result.reboot_required:
            if messagebox.askyesno(
                self._t("usbdk_reboot_title"),
                self._t("usbdk_reboot_message"),
            ):
                os.system("shutdown /r /t 5")
            return False
        if show_success:
            messagebox.showinfo(
                self._t("usbdk_done_title"),
                self._t("usbdk_done_message"),
            )
        return True

    def check_usbdk(self) -> None:
        if usbdk_ready():
            self.ensure_usbdk(show_success=True)
            return
        ok = messagebox.askyesno(
            self._t("usbdk_select_title"),
            self._t("usbdk_select_message"),
        )
        if ok:
            self.ensure_usbdk(show_success=True)

    def scan_disks(self) -> None:
        if self._busy:
            return
        self._busy = True
        self.set_status(self._t("scanning"))
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
            self.set_status(self._t("scan_failed", error=payload))
            return
        ext_count = 0
        first_volume_id = None
        for disk, vols, err in payload:
            did = self.tree.insert(
                "",
                "end",
                text=f"{_kind_icon(disk.kind)}  {disk.title}",
                values=(disk.bus_name, format_bytes(disk.size), err or self._t("connected"), ""),
                open=True,
            )
            self._nodes[did] = ("disk", disk)
            if not vols:
                self.tree.insert(did, "end", text=self._t("no_ext"), values=("", "", "", ""))
                continue
            for v in vols:
                key = self._vol_key("disk", disk.path, v)
                mounted = key in self._mounts
                letter = self._mounts[key].letter if mounted else ""
                state = f"{self._t('connected')} {letter}" if mounted else (self._t("writable") if not v.write_blockers else self._t("readonly"))
                vid = self.tree.insert(
                    did,
                    "end",
                    text=f"{v.sb.fs_type}  {v.label}",
                    values=(
                        self._volume_kind_label(v),
                        format_bytes(v.sb.blocks_count * v.sb.block_size),
                        state,
                        letter,
                    ),
                )
                self._nodes[vid] = ("vol", (disk, v))
                if first_volume_id is None:
                    first_volume_id = vid
                ext_count += 1
        extra = self._t("admin_extra") if is_admin() else self._t("admin_needed_extra")
        winfsp = self._t("winfsp_ready") if winfsp_ready() else self._t("winfsp_needed")
        self.set_status(self._t("scan_summary", disks=len(payload), volumes=ext_count, admin=extra, winfsp=winfsp))
        LOG.info("검색 완료 disks=%s ext=%s admin=%s", len(payload), ext_count, is_admin())
        if first_volume_id is not None and not self.tree.selection():
            self.tree.selection_set(first_volume_id)
            self.tree.focus(first_volume_id)
            self.tree.see(first_volume_id)
        self.refresh_drive_letters()
        self.after_idle(self.refresh_drive_letters)

    def open_image(self) -> None:
        path = filedialog.askopenfilename(
            title=self._t("image_open_title"),
            filetypes=[
                (self._t("image_filter"), "*.img *.raw *.iso *.bin *.dd"),
                (self._t("all_files"), "*.*"),
            ],
        )
        if not path:
            return
        try:
            with ImageDevice(path, writable=False) as dev:
                size = dev.size()
                vols = discover_volumes(dev)
            if not vols:
                messagebox.showerror(self._t("no_ext_title"), self._t("no_ext_message"), parent=self)
                return
            nid = self.tree.insert(
                "",
                "end",
                text=f"IMG  {os.path.basename(path)}",
                values=(self._t("image_kind"), format_bytes(size), self._t("file_state"), ""),
                open=True,
            )
            self._nodes[nid] = ("image", path)
            for x in vols:
                vid = self.tree.insert(
                    nid,
                    "end",
                    text=f"{x.sb.fs_type}  {x.label}",
                    values=(
                        self._volume_kind_label(x),
                        format_bytes(x.sb.blocks_count * x.sb.block_size),
                        self._t("readonly") if x.write_blockers else self._t("writable"),
                        "",
                    ),
                )
                self._nodes[vid] = ("imgvol", (path, x))
            self.tree.selection_set(vid)
            self.set_status(self._t("image_summary", count=len(vols)))
        except Exception as exc:
            messagebox.showerror(self._t("open_failed"), str(exc), parent=self)

    def _selected_volume(self):
        sel = self.tree.selection()
        if not sel:
            return None
        return self._nodes.get(sel[0])

    def _vol_key(self, kind: str, path: str, vinfo: VolumeInfo) -> str:
        return f"{kind}:{path}:{vinfo.offset}"

    def _volume_kind_label(self, vinfo: VolumeInfo) -> str:
        # The selectable child row represents the filesystem, not the disk's
        # partition-table format. Keep GPT/MBR in vinfo.scheme for internal
        # targeting/diagnostics, but present the user-facing item as EXT4.
        return self._t("ext_partition", fs=vinfo.sb.fs_type)

    def _verify_physical_selection(self, disk: DiskInfo, vinfo: VolumeInfo) -> None:
        """Revalidate the selected medium before any lock/dismount/write action."""
        check = WindowsPhysicalDevice(disk.path, disk.sector_size, writable=False)
        try:
            current_size = int(check.size() or 0)
            if disk.size and current_size and int(disk.size) != current_size:
                raise RuntimeError(
                    self._t(
                        "device_identity_changed",
                        detail=f"disk size {disk.size} -> {current_size}",
                    )
                )

            scanned_serial = (disk.serial or "").strip().lower()
            current_serial = (check.serial or "").strip().lower()
            if scanned_serial and current_serial and scanned_serial != current_serial:
                raise RuntimeError(
                    self._t(
                        "device_identity_changed",
                        detail="storage serial changed",
                    )
                )

            current_sb = probe_superblock(check, vinfo.offset)
            if current_sb is None:
                raise RuntimeError(
                    self._t(
                        "device_identity_changed",
                        detail=f"EXT superblock missing at offset {vinfo.offset}",
                    )
                )
            if current_sb.uuid != vinfo.sb.uuid:
                raise RuntimeError(
                    self._t(
                        "device_identity_changed",
                        detail=(
                            f"EXT UUID {vinfo.sb.uuid.hex()} -> "
                            f"{current_sb.uuid.hex()}"
                        ),
                    )
                )
            if (
                current_sb.block_size != vinfo.sb.block_size
                or current_sb.blocks_count != vinfo.sb.blocks_count
            ):
                raise RuntimeError(
                    self._t(
                        "device_identity_changed",
                        detail="EXT geometry changed after scan",
                    )
                )

            current_vols = discover_volumes(check)
            match = next(
                (
                    item
                    for item in current_vols
                    if item.offset == vinfo.offset and item.sb.uuid == vinfo.sb.uuid
                ),
                None,
            )
            if match is None:
                raise RuntimeError(
                    self._t(
                        "device_identity_changed",
                        detail="selected partition no longer exists at the scanned offset",
                    )
                )
            if vinfo.size and match.size and int(vinfo.size) != int(match.size):
                raise RuntimeError(
                    self._t(
                        "device_identity_changed",
                        detail=f"partition size {vinfo.size} -> {match.size}",
                    )
                )
        finally:
            check.close()


    def _run_with_progress(
        self,
        title: str,
        message: str,
        func,
        *,
        progress_aware: bool = False,
    ):
        """Run blocking storage work off the Tk thread with an in-window overlay."""
        if self._operation_active:
            raise RuntimeError(self._t("operation_busy"))

        self._operation_active = True
        overlay = tk.Frame(
            self,
            bg=BG3,
            cursor="watch",
            highlightthickness=0,
            bd=0,
        )
        overlay.place(x=0, y=0, relwidth=1, relheight=1)
        overlay.lift()

        # This is intentionally a child of the main window rather than a
        # Toplevel.  It therefore cannot appear on another monitor or behind
        # the parent window while journal/UsbDk work is running.
        card = tk.Frame(
            overlay,
            bg=BG2,
            highlightbackground="#45475a",
            highlightthickness=1,
            padx=24,
            pady=20,
        )
        card.place(relx=0.5, rely=0.43, anchor="center", relwidth=0.74)

        tk.Label(
            card,
            text=title,
            bg=BG2,
            fg=ACCENT,
            font=("Segoe UI", 13, "bold"),
            anchor="w",
        ).pack(fill="x", pady=(0, 10))
        tk.Label(
            card,
            text=message,
            bg=BG2,
            fg=FG,
            font=("Segoe UI", 10),
            justify="left",
            anchor="w",
            wraplength=560,
        ).pack(fill="x", pady=(0, 12))

        detail = tk.StringVar(value=self._t("device_wait"))
        tk.Label(
            card,
            textvariable=detail,
            bg=BG2,
            fg=FG_DIM,
            font=("Segoe UI", 9),
            anchor="w",
        ).pack(fill="x", pady=(0, 8))

        progress = ttk.Progressbar(card, mode="indeterminate")
        progress.pack(fill="x")
        progress.start(12)

        tk.Label(
            card,
            text=self._t("do_not_disconnect"),
            bg=BG2,
            fg=FG_DIM,
            font=("Segoe UI", 9),
            anchor="w",
        ).pack(fill="x", pady=(10, 0))

        state: dict[str, object] = {}
        status_updates: queue.Queue = queue.Queue()
        finished = threading.Event()
        done_var = tk.BooleanVar(self, value=False)
        started = time.monotonic()
        last_detail = self._t("device_wait")

        def report(message: str) -> None:
            status_updates.put(str(message))

        def worker() -> None:
            try:
                state["result"] = func(report) if progress_aware else func()
            except BaseException as exc:
                state["error"] = exc
            finally:
                finished.set()

        def poll() -> None:
            nonlocal last_detail
            while True:
                try:
                    last_detail = status_updates.get_nowait()
                except queue.Empty:
                    break
            if finished.is_set():
                done_var.set(True)
                return
            elapsed = max(0, int(time.monotonic() - started))
            if progress_aware:
                detail.set(self._t("progress_seconds", message=last_detail, seconds=elapsed))
            else:
                detail.set(self._t("progress_storage", seconds=elapsed))
            self.after(100, poll)

        thread = threading.Thread(
            target=worker,
            daemon=True,
            name="ext4-storage-operation",
        )
        thread.start()
        self.after(100, poll)

        try:
            overlay.grab_set()
            overlay.focus_set()
            self.wait_variable(done_var)
        finally:
            try:
                progress.stop()
            except tk.TclError:
                pass
            try:
                overlay.grab_release()
            except tk.TclError:
                pass
            try:
                overlay.destroy()
            except tk.TclError:
                pass
            self._operation_active = False

        if "error" in state:
            raise state["error"]
        return state.get("result")

    def mount_selected(self) -> None:
        node = self._selected_volume()
        if not node:
            messagebox.showinfo(self._t("select_title"), self._t("select_volume"), parent=self)
            return
        kind, payload = node
        if kind == "vol":
            disk, vinfo = payload
            key = self._vol_key("disk", disk.path, vinfo)
            partition_number = (
                int(vinfo.partition_index)
                if int(vinfo.partition_index or 0) > 0
                else None
            )
            opener = lambda writable: WindowsPhysicalDevice(
                disk.path,
                disk.sector_size,
                writable=writable,
                partition_number=partition_number,
                partition_offset=vinfo.offset,
                partition_size=vinfo.size,
                expected_size=disk.size,
                expected_serial=disk.serial,
                expected_ext_uuid=vinfo.sb.uuid,
            )
            src = disk.path
        elif kind == "imgvol":
            path, vinfo = payload
            key = self._vol_key("image", path, vinfo)
            opener = lambda writable: ImageDevice(path, writable=writable)
            src = path
        else:
            messagebox.showinfo(self._t("select_title"), self._t("select_volume_row"), parent=self)
            return

        if key in self._mounts:
            session = self._mounts[key]
            want_write = bool(self.write_var.get())
            if want_write and session.read_only:
                letter_keep = session.letter
                if not messagebox.askyesno(
                    self._t("reconnect_write_title"),
                    self._t("reconnect_write_message", letter=letter_keep),
                    parent=self,
                ):
                    open_explorer(letter_keep)
                    return
                LOG.info("읽기 전용 %s 를 해제하고 쓰기로 다시 연결합니다", letter_keep)
                if not self._drop_mount(key, show_error=True):
                    return
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
                self.set_status(self._t("already_connected", letter=session.letter))
                return

        if not winfsp_available():
            if not self.ensure_winfsp():
                return

        writable = bool(self.write_var.get())
        if writable and kind == "vol" and not is_admin():
            messagebox.showwarning(self._t("permission_title"), self._t("permission_write"), parent=self)
            writable = False

        try:
            if kind == "vol":
                self.set_status(self._t("verifying_device"))
                self.update_idletasks()
                self._verify_physical_selection(disk, vinfo)
                LOG.info(
                    "선택 장치 재검증 성공 path=%s offset=%s uuid=%s serial=%s scheme=%s part=%s",
                    disk.path,
                    vinfo.offset,
                    vinfo.sb.uuid.hex(),
                    disk.serial or "-",
                    vinfo.scheme,
                    vinfo.partition_index or "-",
                )
            letter = self._chosen_letter()
            self.set_status(self._t("mounting", letter=letter))
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
            self._apply_owner_mode(vol)
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
                        self.set_status(self._t("journal_recover_status"))
                        self.update_idletasks()
                        recovery_stats = self._run_with_progress(
                            self._t("journal_recover_title"),
                            self._t("journal_recover_message"),
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
                            self._t("usbdk_required_title"),
                            self._t("usbdk_required_message", error=exc),
                        )
                        if install_now:
                            ready = self.ensure_usbdk(show_success=True)
                            if ready:
                                self.set_status(self._t("usbdk_ready_status"))
                        else:
                            self.set_status(self._t("usbdk_cancelled"))
                        return
                    except Exception as exc:
                        LOG.exception("Windows JBD2 복구 실패")
                        messagebox.showwarning(
                            self._t("journal_fail_title"),
                            self._t("journal_fail_message", error=exc),
                        )

                if (
                    vol.sb.feature_ro_compat & C.EXT4_FEATURE_RO_COMPAT_ORPHAN_PRESENT
                    or vol.sb.last_orphan
                ):
                    try:
                        self.set_status(self._t("orphan_repair_status"))
                        self.update_idletasks()
                        orphan_stats = self._run_with_progress(
                            self._t("orphan_repair_title"),
                            self._t("orphan_repair_message"),
                            vol.recover_pending_orphans,
                            progress_aware=True,
                        )
                        LOG.warning(
                            "Windows EXT4 orphan 자동 복구 성공 entries=%s deleted=%s truncated=%s",
                            orphan_stats.entries_found,
                            orphan_stats.deleted,
                            orphan_stats.truncated,
                        )
                        self.set_status(self._t("orphan_repair_done"))
                    except Exception as exc:
                        LOG.error("Windows EXT4 orphan 자동 복구 중단: %s", exc)
                        self.set_status(self._t("orphan_repair_failed", error=exc))

                if vol.sb.state & C.EXT4_ERROR_FS:
                    try:
                        self.set_status(self._t("error_repair_status"))
                        self.update_idletasks()
                        repair_stats = self._run_with_progress(
                            self._t("error_repair_title"),
                            self._t("error_repair_message"),
                            vol.repair_error_state_if_safe,
                            progress_aware=True,
                        )
                        if repair_stats.repaired:
                            LOG.warning(
                                "Windows EXT4 ERROR_FS 자동 복구 성공 groups=%s bitmaps=%s "
                                "root_entries=%s historical_errors=%s bitmap_checksum_repairs=%s",
                                repair_stats.groups_checked,
                                repair_stats.bitmaps_checked,
                                repair_stats.root_entries_checked,
                                repair_stats.error_count,
                                repair_stats.bitmap_checksums_repaired,
                            )
                            self.set_status(self._t("error_repair_done"))
                    except Exception as exc:
                        LOG.error("Windows EXT4 ERROR_FS 자동 복구 중단: %s", exc)
                        self.set_status(self._t("error_repair_failed", error=exc))

                hard = vol.hard_write_blockers()
                soft = vol.soft_write_warnings()
                LOG.info("쓰기 검사 hard=%s soft=%s", hard, soft)
                if hard:
                    messagebox.showwarning(
                        self._t("write_block_title"),
                        self._t("write_block_reasons", reasons="\n- ".join(hard)),
                    )
                    read_only = True
                elif soft:
                    ok = messagebox.askyesno(
                        self._t("write_warning_title"),
                        self._t("write_warning_message", warnings="\n- ".join(soft)),
                    )
                    if ok:
                        LOG.warning("사용자가 쓰기 위험을 감수함: %s", soft)
                    else:
                        read_only = True
                        LOG.info("사용자가 쓰기를 취소하고 읽기 전용으로 연결")
            if read_only and writable:
                # A writable WindowsPhysicalDevice keeps the real volume
                # locked/dismounted/offline for raw writes.  If filesystem
                # safety checks downgrade this request to read-only, release
                # that raw-write state before asking WinFsp to publish a
                # virtual drive.  Keeping the writable handle here can prevent
                # mount-manager registration on some USB/SD readers.
                LOG.warning(
                    "쓰기 연결이 읽기 전용으로 강등됨 — writable raw 장치를 닫고 "
                    "read-only 장치로 다시 엽니다."
                )
                try:
                    vol.close(abort=True)
                except Exception:
                    LOG.exception("RW→RO 강등 중 writable 장치 닫기 실패")
                    raise
                dev = opener(False)
                vol = Ext4Volume(
                    dev,
                    vinfo.offset,
                    vinfo.size,
                    owns_device=True,
                )
                self._apply_owner_mode(vol)
                LOG.info(
                    "RW→RO 재오픈 완료 path=%s state=0x%X incompat=0x%X ro_compat=0x%X",
                    src,
                    vol.sb.state,
                    vol.sb.feature_incompat,
                    vol.sb.feature_ro_compat,
                )

            LOG.info("실제 마운트 모드 read_only=%s letter=%s", read_only, letter)
            label = vol.sb.volume_name or vinfo.label or "EXT4"
            session = mount_volume(vol, read_only=read_only, label=label, letter=letter)
            self._mounts[key] = session
            mode = self._t("mode_ro") if read_only else self._t("mode_rw")
            self.tree.set(self.tree.selection()[0], "state", self._t("connected_state", mode=mode))
            self.tree.set(self.tree.selection()[0], "drive", session.letter)
            self.refresh_drive_letters()
            open_explorer(session.letter)
            self.set_status(self._t("mount_success", letter=session.letter, mode=mode))
        except Exception as exc:
            LOG.exception("연결 실패 src=%s", src)
            messagebox.showerror(
                self._t("mount_fail_title"),
                self._t("mount_fail_message", error=explain_fuse_error(exc)),
                parent=self,
            )
            self.set_status(self._t("mount_fail_status", error=exc))

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
        ok = self._drop_mount(key, show_error=True)
        sel = self.tree.selection()
        if sel:
            self.tree.set(
                sel[0],
                "state",
                self._t("disconnected") if ok else self._t("unmount_failed_state"),
            )
            self.tree.set(sel[0], "drive", "")
        self.refresh_drive_letters()
        if ok:
            self.set_status(self._t("disconnect_done"))

    def _drop_mount(self, key: str, *, show_error: bool = False) -> bool:
        session = self._mounts.pop(key, None)
        if not session:
            return True
        try:
            unmount(session.letter)
            return True
        except Exception as exc:
            LOG.exception("연결 해제 실패 %s", session.letter)
            self.set_status(self._t("unmount_failed_status", error=exc))
            if show_error:
                messagebox.showerror(
                    self._t("unmount_failed_title"),
                    self._t("unmount_failed_message", error=exc),
                    parent=self,
                )
            return False

    def _hook_dnd(self) -> None:
        try:
            self.update_idletasks()
            self._drop = DropTarget(self, self.on_drop)
        except Exception:
            self.set_status(self._t("dnd_unavailable"))

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
                    self._t("drop_title"),
                    self._t("drop_message"),
                    parent=self,
                )
                return
            self.mount_selected()
            letter = self._target_letter()
        if not letter:
            messagebox.showinfo(self._t("target_title"), self._t("target_message"), parent=self)
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
            messagebox.showerror(self._t("copy_failed"), "\n".join(errors[:8]), parent=self)
        self.set_status(self._t("copy_done", count=ok, letter=letter))
        try:
            open_explorer(letter)
        except Exception:
            pass

    def on_close(self) -> None:
        if self._operation_active:
            self.bell()
            self.set_status(self._t("busy_close"))
            return
        self.set_status(self._t("unmounting"))
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
            self._drop_mount(key, show_error=True)
        try:
            unmount_all()
        except Exception:
            LOG.exception("종료 시 드라이브 해제 실패")
        self.destroy()


def main() -> None:
    if sys.platform != "win32":
        print(tr(load_language(), "windows_only"))
    app = App()
    app.mainloop()
