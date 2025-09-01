"""Command-line interface for Glaurung binary analysis."""

from glaurung.logging import configure_logging, get_logger


def main():
    """Main entry point for the Glaurung CLI."""
    # Configure logging
    configure_logging(level="INFO", json_output=False)
    logger = get_logger(__name__)
    
    logger.info("Starting Glaurung binary analysis tool")
    print("Hello from glaurung!")
    logger.info("Glaurung CLI completed")


if __name__ == "__main__":
    main()
