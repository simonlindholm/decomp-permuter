import argparse
import threading

import attr
import pystray

from .net.server import start_server


@attr.s
class Options:
    host: str = attr.ib()
    port: int = attr.ib()
    cpus: float = attr.ib()
    max_memory_gb: float = attr.ib()
    systray: bool = attr.ib()


def run(options: Options) -> None:
    server = start_server(options.host, options.port)

    # TODO: print statistics, run systray, etc.
    input("Press enter to stop the server.")
    server.shutdown()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a permuter server, allowing anyone with access to the central -J "
        "server to run sandboxed permuter jobs on your machine (permuter@home)."
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
        dest="cpus",
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
        help="Restrict the sandboxed process to the given amount of memory in gigabytes (float). "
        "If this limit is hit, the permuter will crash horribly, but at least your system won't lock up.",
    )
    parser.add_argument(
        "--systray",
        dest="systray",
        action="store_true",
        help="Make the server controllable through the system tray.",
    )
    args = parser.parse_args()
    options = Options(
        host=args.host,
        port=args.port,
        cpus=args.cpus,
        max_memory_gb=args.max_memory_gb,
        systray=args.systray,
    )
    run(options)


if __name__ == "__main__":
    main()
