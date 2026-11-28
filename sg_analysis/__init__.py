"""Static APK analysis package for SideloadGuard."""

from loguru import logger

# Androguard uses Loguru under its "androguard" module namespace; disable only its logs
# so importing this library does not write parser diagnostics to the caller's terminal.
logger.disable("androguard")
