import argparse

import attr
import pystray


@attr.s
class Options:
    host: str = attr.ib()
    port: int = attr.ib()
    cpus: float = attr.ib()
    max_memory_gb: float = attr.ib()
    systray: bool = attr.ib()


def run(options: Options) -> None:
    print(options.systray)
    pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a permuter server, allowing anyone with access to a central "
        "server to run permuter jobs on your machine (sandboxed)."
    )
    parser.add_argument(
        "--host", dest="host", help="Hostname to listen on. (default: %(default)s)"
    )
    parser.add_argument(
        "--port", dest="port", type=int, required=True, help="Port to use.",
    )
    parser.add_argument(
        "--cpus",
        dest="cpus",
        type=float,
        required=True,
        help="Number of CPUs to use. (float)",
    )
    parser.add_argument(
        "--memory",
        dest="max_memory_gb",
        type=float,
        required=True,
        help="Restrict the sandboxed process to the given amount of memory in gigabytes. "
        "If this limit is hit, the permuter will crash horribly, but your system won't lock up. (float)",
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
