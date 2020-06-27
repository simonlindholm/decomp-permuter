import argparse
from functools import partial
import os
import queue
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

from PIL import Image
import pystray

from .net.auth import fetch_docker_image_name, go_online, go_offline, setup
from .net.common import static_assert_unreachable
from .net.server import (
    IoActivity,
    IoConnect,
    IoDisconnect,
    IoGlobalMessage,
    IoWillSleep,
    IoWorkDone,
    Server,
    ServerOptions,
    start_evaluator,
)


def noop() -> None:
    pass


class SystrayState:
    def connect(self, handle: str, nickname: str, fn_names: List[str]) -> None:
        pass

    def disconnect(self, handle: str) -> None:
        pass

    def work_done(self, handle: str) -> None:
        pass

    def will_sleep(self) -> None:
        pass


class RealSystrayState(SystrayState):
    _clients: Dict[str, Tuple[str, str]]

    def __init__(
        self, server: Server, update_menu: Callable[[List[pystray.MenuItem]], None]
    ) -> None:
        self._server = server
        self._update_menu = update_menu
        self._clients = {}

    def _remove_client(self, handle: str, *_: Any) -> None:
        self._server.remove_client(handle)

    def _update(self) -> None:
        title = "Currently permuting:" if self._clients else "<not running>"
        items: List[pystray.MenuItem] = [
            pystray.MenuItem(title, noop, enabled=False),
        ]

        for handle, (nickname, fn_names) in self._clients.items():
            items.append(
                pystray.MenuItem(
                    f"{fn_names} ({nickname})",
                    pystray.Menu(
                        pystray.MenuItem("Stop", partial(self._remove_client, handle)),
                    ),
                ),
            )

        self._update_menu(items)

    def initial_update(self) -> None:
        self._update()

    def connect(self, handle: str, nickname: str, fn_names: List[str]) -> None:
        self._clients[handle] = (nickname, ", ".join(fn_names))
        self._update()

    def disconnect(self, handle: str) -> None:
        del self._clients[handle]
        self._update()

    def work_done(self, handle: str) -> None:
        pass

    def will_sleep(self) -> None:
        self._update()


def run_with_systray(server: Server, loop: Callable[[SystrayState], None]) -> None:
    menu_items: List[pystray.MenuItem] = []
    icon: Optional[pystray.Icon] = None

    def update_menu(items: List[pystray.MenuItem]) -> None:
        nonlocal menu_items
        menu_items = items
        if icon is not None:
            icon.update_menu()

    systray = RealSystrayState(server, update_menu)
    systray.initial_update()

    icon = pystray.Icon(
        name="permuter@home",
        title="permuter@home",
        icon=Image.open(os.path.join(os.path.dirname(__file__), "..", "icon.png")),
        menu=pystray.Menu(lambda: menu_items),
    )

    def inner(icon: pystray.Icon) -> None:
        icon.visible = True
        loop(systray)
        icon.stop()

    icon.run(inner)


def output_loop(output_queue: "queue.Queue[IoActivity]", systray: SystrayState) -> None:
    while True:
        activity = output_queue.get()
        if isinstance(activity, IoGlobalMessage):
            if isinstance(activity, IoWillSleep):
                systray.will_sleep()

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
                systray.work_done(handle)

            else:
                static_assert_unreachable(msg)


def run(options: ServerOptions) -> None:
    config = setup()
    docker_image = fetch_docker_image_name(config)

    output_queue: "queue.Queue[IoActivity]" = queue.Queue()

    port = start_evaluator(docker_image, options)

    try:
        server = Server(config, options, port, output_queue)
        server.start()

        go_online(config)

        # TODO: print statistics, run systray, etc.
        # Also regularly check in with the auth server to maintain an up-to-date IP,
        # and to check version.
        def cmdline_ui(systray: SystrayState) -> None:
            output_thread = threading.Thread(
                target=output_loop, args=(output_queue, systray)
            )
            output_thread.daemon = True
            output_thread.start()

            # TODO: print statistics, with ctrl+c for exit instead of enter
            print("Press enter to stop the server.")
            input()

        if options.systray:
            run_with_systray(server, cmdline_ui)
        else:
            cmdline_ui(SystrayState())

        go_offline(config)
        server.stop()
    finally:
        port.shutdown()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a permuter server, allowing anyone with access to "
        "the central -J server to run sandboxed permuter jobs on your machine "
        "(permuter@home)."
    )
    parser.add_argument(
        "--host",
        dest="host",
        default="0.0.0.0",
        help="Hostname to listen on. (default: %(default)s)",
    )
    parser.add_argument(
        "--port", dest="port", type=int, required=True, help="Port to listen on.",
    )
    parser.add_argument(
        "--cpus",
        dest="num_cpus",
        metavar="CPUS",
        type=float,
        required=True,
        help="Number of CPUs to use (float).",
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
    args = parser.parse_args()
    options = ServerOptions(
        host=args.host,
        port=args.port,
        num_cpus=args.num_cpus,
        max_memory_gb=args.max_memory_gb,
        min_priority=args.min_priority,
        systray=args.systray,
    )
    run(options)


if __name__ == "__main__":
    main()
