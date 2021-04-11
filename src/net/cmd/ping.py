from argparse import ArgumentParser, Namespace
import time

from ..core import connect
from .base import Command


class PingCommand(Command):
    command = "ping"
    help = "Check server connectivity."

    @staticmethod
    def add_arguments(parser: ArgumentParser) -> None:
        pass

    @staticmethod
    def run(args: Namespace) -> None:
        run_ping()


def run_ping() -> None:
    port = connect()
    t0 = time.time()
    port.send_json({"method": "ping"})
    port.receive_json()
    rtt = (time.time() - t0) * 1000
    print(f"Connected successfully! Round-trip time: {rtt:.1f} ms")
