from argparse import ArgumentParser, RawDescriptionHelpFormatter

from .run_server import RunServerCommand
from .setup import SetupCommand
from .vouch import VouchCommand


def main() -> None:
    parser = ArgumentParser(
        description="permuter@home - run the permuter across the Internet!\n\n"
        "To use p@h as a client, just pass -J when running the permuter. "
        "This script is\nonly necessary for configuration or when running a server.",
        formatter_class=RawDescriptionHelpFormatter,
    )

    commands = [
        RunServerCommand,
        SetupCommand,
        VouchCommand,
    ]

    subparsers = parser.add_subparsers(metavar="<command>")
    for command in commands:
        subparser = subparsers.add_parser(
            command.command,
            help=command.help,
            description=command.help,
        )
        command.add_arguments(subparser)
        subparser.set_defaults(subcommand_handler=command.run)

    args = parser.parse_args()
    if "subcommand_handler" in args:
        args.subcommand_handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()