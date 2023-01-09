"""Command-line interface."""
import click


@click.command()
@click.version_option()
def main() -> None:
    """Iamra."""


if __name__ == "__main__":
    main(prog_name="iamra")  # pragma: no cover
