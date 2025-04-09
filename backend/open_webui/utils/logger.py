import json
import logging
import sys
from typing import TYPE_CHECKING

from loguru import logger

from open_webui.env import (
    AUDIT_LOG_FILE_ROTATION_SIZE,
    AUDIT_LOG_LEVEL,
    AUDIT_LOGS_FILE_PATH,
    GLOBAL_LOG_LEVEL,
)


if TYPE_CHECKING:
    from loguru import Record


def stdout_format(record: "Record") -> str:
    """
    Generates a formatted string for log records that are output to the console. This format includes a timestamp, log level, source location (module, function, and line), the log message, and any extra data (serialized as JSON).

    Parameters:
    record (Record): A Loguru record that contains logging details including time, level, name, function, line, message, and any extra context.
    Returns:
    str: A formatted log string intended for stdout.
    """
    record["extra"]["extra_json"] = json.dumps(record["extra"])
    return (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
        "<level>{message}</level> - {extra[extra_json]}"
        "\n{exception}"
    )


class InterceptHandler(logging.Handler):
    """
    Intercepts log records from Python's standard logging module
    and redirects them to Loguru's logger.
    """

    def emit(self, record):
        """
        Called by the standard logging module for each log event.
        It transforms the standard `LogRecord` into a format compatible with Loguru
        and passes it to Loguru's logger.
        """
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame, depth = sys._getframe(6), 6
        while frame and frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


def file_format(record: "Record"):
    """
    Formats audit log records into a structured JSON string for file output.

    Parameters:
    record (Record): A Loguru record containing extra audit data.
    Returns:
    str: A JSON-formatted string representing the audit data.
    """

    audit_data = {
        "id": record["extra"].get("id", ""),
        "timestamp": int(record["time"].timestamp()),
        "user": record["extra"].get("user", dict()),
        "audit_level": record["extra"].get("audit_level", ""),
        "verb": record["extra"].get("verb", ""),
        "request_uri": record["extra"].get("request_uri", ""),
        "response_status_code": record["extra"].get("response_status_code", 0),
        "source_ip": record["extra"].get("source_ip", ""),
        "user_agent": record["extra"].get("user_agent", ""),
        "request_object": record["extra"].get("request_object", b""),
        "response_object": record["extra"].get("response_object", b""),
        "extra": record["extra"].get("extra", {}),
    }

    record["extra"]["file_extra"] = json.dumps(audit_data, default=str)
    return "{extra[file_extra]}\n"

def dynamic_level_filter(record: "Record"):
    """
    Filters logs based on a 'log_level' specified in the record's extra data.
    If 'log_level' is not present or invalid, it defaults to GLOBAL_LOG_LEVEL.
    Allows a message if its level is >= the specified or default level.
    """
    # Use GLOBAL_LOG_LEVEL from env as the default
    default_level_name = GLOBAL_LOG_LEVEL
    log_level_name = record["extra"].get("log_level", default_level_name)

    message_level = logger.level(record["level"].name).no  # Get numeric level of the message
    try:
        # Get numeric level from 'extra' or use default
        bypass_level = logger.level(log_level_name).no
    except ValueError:
        # Fallback to default if the provided level name is invalid
        print(
            f"Warning: Invalid log level '{log_level_name}' provided in logger.bind(). "
            f"Using default '{default_level_name}' instead.",
            file=sys.stderr # Print warnings to stderr
        )
        bypass_level = logger.level(default_level_name).no

    # Log the message if its level is high enough compared to the bound/default level
    return message_level >= bypass_level

def stdout_filter(record: "Record"):
    """
    Combined filter for the stdout handler.
    1. Excludes messages marked as 'auditable'.
    2. Applies the dynamic level filtering logic.
    """
    # Condition 1: Exclude auditable logs from stdout
    if record["extra"].get("auditable") is True:
        return False

    # Condition 2: Apply dynamic level filtering
    return dynamic_level_filter(record)

def start_logger():
    """
    Initializes and configures Loguru's logger with distinct handlers:

    A console (stdout) handler for general log messages (excluding those marked as auditable).
    An optional file handler for audit logs if audit logging is enabled.
    Additionally, this function reconfigures Python’s standard logging to route through Loguru and adjusts logging levels for Uvicorn.

    Parameters:
    enable_audit_logging (bool): Determines whether audit-specific log entries should be recorded to file.
    """
    logger.remove()

    logger.add(
        sys.stdout,
        level=0,
        format=stdout_format,
        filter=stdout_filter,
    )

    if AUDIT_LOG_LEVEL != "NONE":
        try:
            logger.add(
                AUDIT_LOGS_FILE_PATH,
                level="INFO",
                rotation=AUDIT_LOG_FILE_ROTATION_SIZE,
                compression="zip",
                format=file_format,
                filter=lambda record: record["extra"].get("auditable") is True,
            )
        except Exception as e:
            logger.error(f"Failed to initialize audit log file handler: {str(e)}")

    logging.basicConfig(
        handlers=[InterceptHandler()], level=GLOBAL_LOG_LEVEL, force=True
    )
    for uvicorn_logger_name in ["uvicorn", "uvicorn.error"]:
        uvicorn_logger = logging.getLogger(uvicorn_logger_name)
        uvicorn_logger.setLevel(GLOBAL_LOG_LEVEL)
        uvicorn_logger.handlers = []
    for uvicorn_logger_name in ["uvicorn.access"]:
        uvicorn_logger = logging.getLogger(uvicorn_logger_name)
        uvicorn_logger.setLevel(GLOBAL_LOG_LEVEL)
        uvicorn_logger.handlers = [InterceptHandler()]

    logger.info(f"Logger initialized. Default stdout log level (when not bound): {GLOBAL_LOG_LEVEL}")
    logger.info("Use logger.bind(log_level='LEVEL').<log_method>('...') to set per-message levels.")
