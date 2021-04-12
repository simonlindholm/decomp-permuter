from argparse import ArgumentParser, Namespace
from dataclasses import dataclass
from functools import partial
import os
import queue
import random
import time
import threading
import traceback
from typing import Any, Callable, Dict, List, Optional, Tuple

from PIL import Image
import pystray

from ...helpers import static_assert_unreachable
from ..core import CancelToken, ServerError
from ..server import (
    Client,
    IoActivity,
    IoConnect,
    IoDisconnect,
    IoGlobalMessage,
    IoImmediateDisconnect,
    IoReconnect,
    IoServerFailed,
    IoShutdown,
    IoUserRemovePermuter,
    IoWillSleep,
    IoWorkDone,
    PermuterHandle,
    Server,
    ServerOptions,
)
from .base import Command


SYSTRAY_UPDATE_INTERVAL = 20.0


class RunServerCommand(Command):
    command = "run-server"
    help = """Run a permuter server, allowing anyone with access to the central
        server to run sandboxed permuter jobs on your machine. Requires docker."""

    @staticmethod
    def add_arguments(parser: ArgumentParser) -> None:
        parser.add_argument(
            "--cores",
            dest="num_cores",
            metavar="CORES",
            type=float,
            required=True,
            help="Number of cores to use (float).",
        )
        parser.add_argument(
            "--memory",
            dest="max_memory_gb",
            metavar="MEMORY_GB",
            type=float,
            required=True,
            help="""Restrict the sandboxed process to the given amount of memory in
            gigabytes (float). If this limit is hit, the permuter will crash
            horribly, but at least your system won't lock up.""",
        )
        parser.add_argument(
            "--systray",
            dest="systray",
            action="store_true",
            help="Make the server controllable through the system tray.",
        )
        parser.add_argument(
            "--min-priority",
            dest="min_priority",
            metavar="PRIORITY",
            type=float,
            default=0.1,
            help="""Only accept jobs from clients who pass --priority with a number
            higher or equal to this value. (default: %(default)s)""",
        )

    @staticmethod
    def run(args: Namespace) -> None:
        options = ServerOptions(
            num_cores=args.num_cores,
            max_memory_gb=args.max_memory_gb,
            min_priority=args.min_priority,
        )

        server_main(options, args.systray)


class SystrayState:
    def connect(self, handle: PermuterHandle, nickname: str, fn_name: str) -> None:
        pass

    def disconnect(self, handle: PermuterHandle) -> None:
        pass

    def work_done(self, handle: PermuterHandle, is_improvement: bool) -> None:
        pass

    def will_sleep(self) -> None:
        pass


@dataclass
class Permuter:
    nickname: str
    fn_name: str
    iterations: int = 0
    improvements: int = 0
    last_systray_update: float = 0.0


class RealSystrayState(SystrayState):
    _permuters: Dict[PermuterHandle, Permuter]

    def __init__(
        self,
        io_queue: "queue.Queue[IoActivity]",
        update_menu: Callable[[List[pystray.MenuItem], bool], None],
    ) -> None:
        self._io_queue = io_queue
        self._update_menu = update_menu
        self._permuters = {}

    def _remove_permuter(self, handle: PermuterHandle, *_: Any) -> None:
        self._io_queue.put((None, (handle, IoUserRemovePermuter())))

    def _quit(self) -> None:
        self._io_queue.put((None, IoShutdown()))

    def _update(self, flush: bool = True) -> None:
        title = "Currently permuting:" if self._permuters else "<not running>"
        items: List[pystray.MenuItem] = [
            pystray.MenuItem(title, None, enabled=False),
        ]

        for handle, perm in self._permuters.items():
            items.append(
                pystray.MenuItem(
                    f"{perm.fn_name} ({perm.nickname})",
                    pystray.Menu(
                        pystray.MenuItem(
                            f"Iterations: {perm.iterations}", None, enabled=False
                        ),
                        pystray.MenuItem(
                            f"Improvements found: {perm.improvements}",
                            None,
                            enabled=False,
                        ),
                        pystray.MenuItem(
                            "Stop", partial(self._remove_permuter, handle)
                        ),
                    ),
                ),
            )

        items.append(pystray.MenuItem("Quit", self._quit))

        self._update_menu(items, flush)

    def initial_update(self) -> None:
        self._update()

    def connect(self, handle: PermuterHandle, nickname: str, fn_name: str) -> None:
        self._permuters[handle] = Permuter(nickname, fn_name)
        self._update()

    def disconnect(self, handle: PermuterHandle) -> None:
        del self._permuters[handle]
        self._update()

    def work_done(self, handle: PermuterHandle, is_improvement: bool) -> None:
        perm = self._permuters[handle]
        perm.iterations += 1
        if is_improvement:
            perm.improvements += 1
        flush = time.time() > perm.last_systray_update + SYSTRAY_UPDATE_INTERVAL
        if flush:
            perm.last_systray_update = time.time()
        self._update(flush)

    def will_sleep(self) -> None:
        self._update()


def run_with_systray(
    io_queue: "queue.Queue[IoActivity]",
    loop: Callable[[SystrayState], None],
) -> None:
    menu_items: List[pystray.MenuItem] = []

    icon = pystray.Icon(
        name="permuter@home",
        title="permuter@home",
        icon=Image.open(os.path.join(os.path.dirname(__file__), "icon.png")),
        menu=pystray.Menu(lambda: menu_items),
    )

    def update_menu(items: List[pystray.MenuItem], flush: bool) -> None:
        nonlocal menu_items
        menu_items = items
        if flush:
            icon.update_menu()

    systray = RealSystrayState(io_queue, update_menu)
    systray.initial_update()

    def inner(icon: pystray.Icon) -> None:
        icon.visible = True
        loop(systray)
        icon.stop()

    icon.run(inner)


class Reconnector:
    _RESET_BACKOFF_AFTER_UPTIME: float = 60.0
    _RANDOM_ADDEND_MAX: float = 60.0
    _BACKOFF_MULTIPLIER: float = 2.0
    _INITIAL_DELAY: float = 5.0

    _io_queue: "queue.Queue[IoActivity]"
    _reconnect_token: CancelToken
    _reconnect_delay: float
    _reconnect_timer: Optional[threading.Timer]
    _start_time: float
    _stop_time: float

    def __init__(self, io_queue: "queue.Queue[IoActivity]") -> None:
        self._io_queue = io_queue
        self._reconnect_token = CancelToken()
        self._reconnect_delay = self._INITIAL_DELAY
        self._reconnect_timer = None
        self._start_time = self._stop_time = time.time()

    def mark_start(self) -> None:
        self._start_time = time.time()

    def mark_stop(self) -> None:
        self._stop_time = time.time()

    def stop(self) -> None:
        self._reconnect_token.cancelled = True
        if self._reconnect_timer is not None:
            self._reconnect_timer.cancel()
            self._reconnect_timer.join()
            self._reconnect_timer = None

    def reconnect_eventually(self) -> int:
        if self._stop_time - self._start_time > self._RESET_BACKOFF_AFTER_UPTIME:
            delay = self._reconnect_delay = self._INITIAL_DELAY
        else:
            delay = self._reconnect_delay
            self._reconnect_delay = (
                self._reconnect_delay * self._BACKOFF_MULTIPLIER
                + random.uniform(1.0, self._RANDOM_ADDEND_MAX)
            )
        token = CancelToken()
        self._reconnect_token = token
        self._reconnect_timer = threading.Timer(
            delay, lambda: self._io_queue.put((token, IoReconnect()))
        )
        self._reconnect_timer.daemon = True
        self._reconnect_timer.start()
        return int(delay)


def main_loop(
    io_queue: "queue.Queue[IoActivity]",
    server: Server,
    systray: SystrayState,
) -> None:
    reconnector = Reconnector(io_queue)
    handle_clients: Dict[PermuterHandle, Client] = {}
    while True:
        token, activity = io_queue.get()
        if token and token.cancelled:
            continue

        if not isinstance(activity, tuple):
            if isinstance(activity, IoWillSleep):
                systray.will_sleep()

            elif isinstance(activity, IoShutdown):
                break

            elif isinstance(activity, IoReconnect):
                print("reconnecting...")
                try:
                    server.start()
                    reconnector.mark_start()
                except EOFError:
                    delay = reconnector.reconnect_eventually()
                    print(f"failed again, reconnecting in {delay} seconds...")
                except ServerError as e:
                    print("failed!", e.message)
                except Exception:
                    print("failed!")
                    traceback.print_exc()

            elif isinstance(activity, IoServerFailed):
                print("disconnected from permuter@home")
                server.stop()
                reconnector.mark_stop()

                if activity.graceful:
                    delay = reconnector.reconnect_eventually()
                    print(f"will reconnect in {delay} seconds...")

            else:
                static_assert_unreachable(activity)

        else:
            handle, msg = activity

            if isinstance(msg, IoConnect):
                client = msg.client
                handle_clients[handle] = client
                systray.connect(handle, client.nickname, msg.fn_name)
                print(f"{client.nickname} connected ({msg.fn_name})")

            elif isinstance(msg, IoDisconnect):
                systray.disconnect(handle)
                nickname = handle_clients[handle].nickname
                del handle_clients[handle]
                print(f"[{nickname}] {msg.reason}")

            elif isinstance(msg, IoImmediateDisconnect):
                print(f"[{msg.client.nickname}] {msg.reason}")

            elif isinstance(msg, IoWorkDone):
                # TODO: statistics
                systray.work_done(handle, msg.is_improvement)

            elif isinstance(msg, IoUserRemovePermuter):
                server.remove_permuter(handle)

            else:
                static_assert_unreachable(msg)


def server_main(options: ServerOptions, use_systray: bool) -> None:
    io_queue: "queue.Queue[IoActivity]" = queue.Queue()

    server = Server(options, io_queue)
    server.start()

    try:

        def cmdline_ui(systray: SystrayState) -> None:
            main_loop(io_queue, server, systray)

        if use_systray:
            run_with_systray(io_queue, cmdline_ui)
        else:
            cmdline_ui(SystrayState())
    finally:
        server.stop()
