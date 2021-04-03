from argparse import ArgumentParser, Namespace

from ..core import connect
from .base import Command


class StatsCommand(Command):
    command = "stats"
    help = "Print statistics."

    @staticmethod
    def add_arguments(parser: ArgumentParser) -> None:
        pass

    @staticmethod
    def run(args: Namespace) -> None:
        run_stats()


def run_stats() -> None:
    port = connect()
    port.send_json({"method": "ping"})
    port.receive_json()
    print("Connected! TODO: actually print stats")
