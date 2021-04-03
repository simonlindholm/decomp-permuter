from argparse import ArgumentParser, Namespace

from ..core import connect2
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
    port = connect2("ping", {})
    port.receive_json()
    print("Success!")
