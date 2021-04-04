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
from ..core import connect
from ..server import (
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
            "--host",
            dest="host",
            default="0.0.0.0",
            help="Hostname to listen on. (default: %(default)s)",
        )
        parser.add_argument(
            "--port",
            dest="port",
            type=int,
            required=True,
            help="Port to listen on.",
        )
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
            host=args.host,
            port=args.port,
            num_cores=args.num_cores,
            max_memory_gb=args.max_memory_gb,
            min_priority=args.min_priority,
            systray=args.systray,
        )

        server_main(options)


class SystrayState:
    def connect(self, handle: str, nickname: str, fn_names: List[str]) -> None:
        pass

    def disconnect(self, handle: str) -> None:
        pass

    def work_done(self, handle: str, is_improvement: bool) -> None:
        pass

    def will_sleep(self) -> None:
        pass


@dataclass
class Client:
    nickname: str
    fn_names: List[str]
    iterations: int = 0
    improvements: int = 0
    last_systray_update: float = 0.0


class RealSystrayState(SystrayState):
    _clients: Dict[str, Client]

    def __init__(
        self,
        server: Server,
        output_queue: "queue.Queue[IoActivity]",
        update_menu: Callable[[List[pystray.MenuItem], bool], None],
    ) -> None:
        self._server = server
        self._output_queue = output_queue
        self._update_menu = update_menu
        self._clients = {}

    def _remove_client(self, handle: str, *_: Any) -> None:
        self._server.remove_client(handle)

    def _quit(self) -> None:
        self._output_queue.put(IoShutdown())

    def _update(self, flush: bool = True) -> None:
        title = "Currently permuting:" if self._clients else "<not running>"
        items: List[pystray.MenuItem] = [
            pystray.MenuItem(title, None, enabled=False),
        ]

        for handle, client in self._clients.items():
            fn_names = ", ".join(client.fn_names)
            items.append(
                pystray.MenuItem(
                    f"{fn_names} ({client.nickname})",
                    pystray.Menu(
                        pystray.MenuItem(
                            f"Iterations: {client.iterations}", None, enabled=False
                        ),
                        pystray.MenuItem(
                            f"Improvements found: {client.improvements}",
                            None,
                            enabled=False,
                        ),
                        pystray.MenuItem("Stop", partial(self._remove_client, handle)),
                    ),
                ),
            )

        items.append(pystray.MenuItem("Quit", self._quit))

        self._update_menu(items, flush)

    def initial_update(self) -> None:
        self._update()

    def connect(self, handle: str, nickname: str, fn_names: List[str]) -> None:
        self._clients[handle] = Client(nickname, fn_names)
        self._update()

    def disconnect(self, handle: str) -> None:
        del self._clients[handle]
        self._update()

    def work_done(self, handle: str, is_improvement: bool) -> None:
        client = self._clients[handle]
        client.iterations += 1
        if is_improvement:
            client.improvements += 1
        flush = time.time() > client.last_systray_update + SYSTRAY_UPDATE_INTERVAL
        if flush:
            client.last_systray_update = time.time()
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
            handle, nickname, msg = activity
            prefix = f"[{nickname}]"

            if isinstance(msg, IoConnect):
                systray.connect(handle, nickname, msg.fn_names)
                fn_names = ", ".join(msg.fn_names)
                print(f"{prefix} connected ({fn_names})")

            elif isinstance(msg, IoDisconnect):
                systray.disconnect(handle)
                print(f"{prefix} {msg.reason}")

            elif isinstance(msg, IoWorkDone):
                # TODO: statistics
                systray.work_done(handle, msg.is_improvement)

            else:
                static_assert_unreachable(msg)


def server_main(options: ServerOptions) -> None:
    net_port = connect()
    docker_image = ""  # TODO

    output_queue: "queue.Queue[IoActivity]" = queue.Queue()

    port = start_evaluator(docker_image, options)

    try:
        server = Server(net_port, options, port, output_queue)
        server.start()

        # TODO go_online(config, options.port)

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

        # TODO go_offline(config)
        server.stop()
    finally:
        port.shutdown()
