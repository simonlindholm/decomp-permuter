import argparse
import threading

import pystray

from .net.auth import fetch_docker_image_name, go_online, go_offline, setup
from .net.server import Server, ServerOptions, start_inner_server


def run(options: ServerOptions) -> None:
    config = setup()
    docker_image = fetch_docker_image_name(config)

    port = start_inner_server(docker_image, options)

    try:
        server = Server(config, options, port)
        server.start()

        go_online(config)

        # TODO: print statistics, run systray, etc.
        # Also regularly check in with the auth server to maintain an up-to-date IP,
        # and to check version.
        input("Press enter to stop the server.")
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