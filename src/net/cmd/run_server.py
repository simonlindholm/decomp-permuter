from argparse import ArgumentParser, Namespace
from dataclasses import dataclass
from functools import partial
import os
import queue
import time
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

from PIL import Image
import pystray

from ...helpers import static_assert_unreachable
from ..core import connect, json_prop
from ..server import (
    Client,
    IoActivity,
    IoConnect,
    IoDisconnect,
    IoGlobalMessage,
    IoShutdown,
    IoWillSleep,
    IoWorkDone,
    Server,
    ServerOptions,
    start_evaluator,
)
from .base import Command


SYSTRAY_UPDATE_INTERVAL = 20.0


class RunServerCommand(Command):
    command = "run-server"
    help = (
        "Run a permuter server, allowing anyone with access to the central "
        "server to run sandboxed permuter jobs on your machine."
    )

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
            help="Restrict the sandboxed process to the given amount of memory in "
            "gigabytes (float). If this limit is hit, the permuter will crash "
            "horribly, but at least your system won't lock up.",
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
            help="Only accept jobs from clients who pass --priority with a number "
            "higher or equal to this value. (default: %(default)s)",
        )

    @staticmethod
    def run(args: Namespace) -> None:
        options = ServerOptions(
            num_cores=args.num_cores,
            max_memory_gb=args.max_memory_gb,
            min_priority=args.min_priority,
            systray=args.systray,
        )

        server_main(options)


class SystrayState:
    def connect(self, handle: int, nickname: str, fn_name: str) -> None:
        pass

    def disconnect(self, handle: int) -> None:
        pass

    def work_done(self, handle: int, is_improvement: bool) -> None:
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
    _permuters: Dict[int, Permuter]

    def __init__(
        self,
        server: Server,
        output_queue: "queue.Queue[IoActivity]",
        update_menu: Callable[[List[pystray.MenuItem], bool], None],
    ) -> None:
        self._server = server
        self._output_queue = output_queue
        self._update_menu = update_menu
        self._permuters = {}

    def _remove_permuter(self, handle: int, *_: Any) -> None:
        self._server.remove_permuter(handle)

    def _quit(self) -> None:
        self._output_queue.put(IoShutdown())

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

    def connect(self, handle: int, nickname: str, fn_name: str) -> None:
        self._permuters[handle] = Permuter(nickname, fn_name)
        self._update()

    def disconnect(self, handle: int) -> None:
        del self._permuters[handle]
        self._update()

    def work_done(self, handle: int, is_improvement: bool) -> None:
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
    server: Server,
    output_queue: "queue.Queue[IoActivity]",
    loop: Callable[[SystrayState], None],
) -> None:
    menu_items: List[pystray.MenuItem] = []

    icon = pystray.Icon(
        name="permuter@home",
        title="permuter@home",
        icon=Image.open(os.path.join(os.path.dirname(__file__), "..", "icon.png")),
        menu=pystray.Menu(lambda: menu_items),
    )

    def update_menu(items: List[pystray.MenuItem], flush: bool) -> None:
        nonlocal menu_items
        menu_items = items
        if flush:
            icon.update_menu()

    systray = RealSystrayState(server, output_queue, update_menu)
    systray.initial_update()

    def inner(icon: pystray.Icon) -> None:
        icon.visible = True
        loop(systray)
        icon.stop()

    icon.run(inner)


def output_loop(output_queue: "queue.Queue[IoActivity]", systray: SystrayState) -> None:
    handle_clients: Dict[int, Client] = {}
    while True:
        activity = output_queue.get()
        if not isinstance(activity, tuple):
            if isinstance(activity, IoWillSleep):
                systray.will_sleep()

            elif isinstance(activity, IoShutdown):
                break

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

            elif isinstance(msg, IoWorkDone):
                # TODO: statistics
                systray.work_done(handle, msg.is_improvement)

            else:
                static_assert_unreachable(msg)


def server_main(options: ServerOptions) -> None:
    net_port = connect()
    net_port.send_json(
        {
            "method": "connect_server",
            "min_priority": options.min_priority,
            "num_cores": options.num_cores,
        }
    )
    obj = net_port.receive_json()
    docker_image = json_prop(obj, "docker_image", str)

    output_queue: "queue.Queue[IoActivity]" = queue.Queue()

    evaluator_port = start_evaluator(docker_image, options)

    server = Server(net_port, options, evaluator_port, output_queue)
    server.start()

    try:

        # TODO: regularly check in with the auth server to maintain an up-to-date IP,
        # and to check version.
        def cmdline_ui(systray: SystrayState) -> None:
            output_thread = threading.Thread(
                target=output_loop, args=(output_queue, systray)
            )
            output_thread.daemon = True
            output_thread.start()
            output_thread.join()

        if options.systray:
            run_with_systray(server, output_queue, cmdline_ui)
        else:
            cmdline_ui(SystrayState())
        server.stop()
    finally:
        evaluator_port.shutdown()
