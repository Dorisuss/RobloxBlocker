from __future__ import annotations

import argparse
import ctypes
import sys
import threading

import pystray
from PIL import Image, ImageDraw

from core import (
    APP_NAME,
    AppConfig,
    BlockError,
    RobloxBlocker,
    RobloxProxy,
    UpdateResult,
    is_admin,
    relaunch_as_admin,
    remove_system_proxy,
    set_startup_enabled,
    set_system_proxy,
    startup_enabled,
    update_blocklists,
)

MUTEX_NAME = "Global\\RobloxBlockerSingleInstance_v1"


def acquire_single_instance() -> bool:
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateMutexW(None, False, MUTEX_NAME)
    return kernel32.GetLastError() != 183


def create_icon(blocked: bool) -> Image.Image:
    size = 64
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    fill = (220, 53, 69, 255) if blocked else (40, 167, 69, 255)
    draw.ellipse((4, 4, size - 4, size - 4), fill=fill, outline=(255, 255, 255, 220), width=3)
    if blocked:
        draw.line((18, 18, size - 18, size - 18), fill=(255, 255, 255, 255), width=6)
        draw.line((size - 18, 18, 18, size - 18), fill=(255, 255, 255, 255), width=6)
    else:
        draw.line((14, 32, 28, 46), fill=(255, 255, 255, 255), width=6)
        draw.line((28, 46, 50, 20), fill=(255, 255, 255, 255), width=6)
    return image


class TrayApp:
    def __init__(self) -> None:
        self.blocker = RobloxBlocker()
        self.config = AppConfig.load()
        self.icon: pystray.Icon | None = None
        self._lock = threading.Lock()
        self._updating = False
        self._proxy = RobloxProxy()

    def _start_proxy(self) -> None:
        self._proxy.start()
        set_system_proxy()

    def _stop_proxy(self) -> None:
        self._proxy.stop()
        remove_system_proxy()

    def _set_blocked(self, blocked: bool) -> None:
        with self._lock:
            try:
                self.blocker.sync_block(blocked)
            except BlockError as exc:
                if str(exc) == "admin_required":
                    relaunch_as_admin(["--apply-block" if blocked else "--remove-block"])
                    if self.icon:
                        self.icon.stop()
                return
            self.config.blocked = blocked
            self.config.save()
            if blocked:
                self._start_proxy()
            else:
                self._stop_proxy()
            self._refresh_ui()

    def _toggle_block(self, _icon: pystray.Icon, _item: pystray.MenuItem) -> None:
        self._set_blocked(not self.config.blocked)

    def _toggle_startup(self, _icon: pystray.Icon, item: pystray.MenuItem) -> None:
        enabled = not bool(item.checked)
        set_startup_enabled(enabled)
        self.config.turn_with_windows = enabled
        self.config.save()
        self._refresh_ui()

    def _turn_off(self, icon: pystray.Icon, _item: pystray.MenuItem) -> None:
        if self.config.blocked:
            try:
                if is_admin():
                    self.blocker.disable_block()
                    self._stop_proxy()
                else:
                    relaunch_as_admin(["--remove-block", "--exit-after"])
                    return
            except BlockError:
                pass
            self.config.blocked = False
        self.config.turned_off = True
        self.config.save()
        icon.stop()

    def _show_message(self, text: str, title: str = APP_NAME) -> None:
        ctypes.windll.user32.MessageBoxW(0, text, title, 0x40)

    def _on_update_done(self, result: UpdateResult) -> None:
        self._updating = False
        if result.ok and self.config.blocked and is_admin():
            try:
                self.blocker.sync_block(True)
            except BlockError:
                pass
        self._refresh_ui()
        if result.ok:
            self._show_message(
                "Lists updated successfully.\n\n" + result.message,
                f"{APP_NAME} - Update IPs",
            )
        else:
            self._show_message(result.message, f"{APP_NAME} - Update IPs")

    def _update_lists(self, _icon: pystray.Icon, _item: pystray.MenuItem) -> None:
        if self._updating:
            self._show_message("Update already in progress.", f"{APP_NAME} - Update IPs")
            return
        self._updating = True
        self._refresh_ui()

        def worker() -> None:
            try:
                result = update_blocklists()
            except Exception as exc:
                result = UpdateResult(False, f"Update failed:\n{exc}")
            threading.Timer(0, lambda: self._on_update_done(result)).start()

        threading.Thread(target=worker, daemon=True).start()

    def _refresh_ui(self) -> None:
        if not self.icon:
            return
        blocked = self.config.blocked
        self.icon.icon = create_icon(blocked)
        self.icon.title = f"{APP_NAME} - {'Blocked' if blocked else 'Unblocked'}"
        if hasattr(self.icon, "update_menu"):
            self.icon.update_menu()

    def _build_menu(self) -> pystray.Menu:
        return pystray.Menu(
            pystray.MenuItem(
                lambda item: "Unblock" if self.config.blocked else "Block",
                self._toggle_block,
                default=True,
            ),
            pystray.MenuItem(
                "Turn with Windows",
                self._toggle_startup,
                checked=lambda item: self.config.turn_with_windows or startup_enabled(),
            ),
            pystray.MenuItem(
                lambda item: "Updating..." if self._updating else "Update IPs",
                self._update_lists,
                enabled=lambda item: not self._updating,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Turn Off", self._turn_off),
        )

    def run(self) -> None:
        if self.config.blocked and is_admin():
            try:
                self.blocker.sync_block(True)
            except BlockError:
                pass
            self._start_proxy()
        self.config.turned_off = False
        self.config.turn_with_windows = startup_enabled()
        self.config.save()
        self.icon = pystray.Icon(
            APP_NAME,
            create_icon(self.config.blocked),
            f"{APP_NAME} - {'Blocked' if self.config.blocked else 'Unblocked'}",
            self._build_menu(),
        )
        self.icon.run()


def handle_cli() -> bool:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--startup", action="store_true")
    parser.add_argument("--apply-block", action="store_true")
    parser.add_argument("--remove-block", action="store_true")
    parser.add_argument("--exit-after", action="store_true")
    args = parser.parse_args()
    config = AppConfig.load()

    if args.startup:
        if not config.turn_with_windows and not startup_enabled():
            return True
        config.turned_off = False
        config.turn_with_windows = startup_enabled()
        config.save()
        return False

    if args.apply_block:
        RobloxBlocker().enable_block()
        config.blocked = True
        config.save()
        return args.exit_after

    if args.remove_block:
        RobloxBlocker().disable_block()
        config.blocked = False
        config.save()
        return args.exit_after

    if config.turned_off:
        config.turned_off = False
        config.save()
    return False


def _hide_console() -> None:
    hwnd = ctypes.windll.kernel32.GetConsoleWindow()
    if hwnd:
        ctypes.windll.user32.ShowWindow(hwnd, 0)


def main() -> int:
    _hide_console()
    if not acquire_single_instance():
        ctypes.windll.user32.MessageBoxW(
            0,
            "RobloxBlocker already running.\nCheck the notification area.",
            APP_NAME,
            0x40,
        )
        return 0
    if handle_cli():
        return 0
    if not is_admin():
        relaunch_as_admin()
    TrayApp().run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
