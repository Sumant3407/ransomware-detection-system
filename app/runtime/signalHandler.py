"""Signal handling for graceful application shutdown."""

import signal
import logging
import threading
from typing import Callable, Any

logger = logging.getLogger(__name__)


class SignalHandler:
    """Handle OS signals (SIGINT, SIGTERM) for graceful shutdown."""

    def __init__(self):
        """Initialize signal handler."""
        self._shutdown_callbacks = []
        self._shutdown_lock = threading.Lock()
        self._shutdown_event = threading.Event()
        self._original_sigint_handler = None
        self._original_sigterm_handler = None

    def registerCallback(self, callback: Callable[[], Any]) -> None:
        """
        Register a callback to be called on shutdown.

        Callbacks are called in FIFO order (first registered, first called).

        Args:
            callback: Callable with no arguments
        """
        with self._shutdown_lock:
            self._shutdown_callbacks.append(callback)
            callbackName = getattr(callback, "__name__", repr(callback))
            logger.debug(f"Registered shutdown callback: {callbackName}")

    def start(self) -> None:
        """
        Start handling signals (Ctrl+C, SIGTERM).

        Sets up handlers for SIGINT (Ctrl+C) and SIGTERM (termination signal).
        """
        logger.debug("Starting signal handler")

        def _handleSignal(signum: int, frame: Any) -> None:
            """Internal signal handler."""
            signal_name = signal.Signals(signum).name
            logger.warning(f"Received {signal_name}, initiating graceful shutdown")
            self._executeShutdownCallbacks()

        # Register signal handlers
        self._original_sigint_handler = signal.signal(signal.SIGINT, _handleSignal)
        self._original_sigterm_handler = signal.signal(signal.SIGTERM, _handleSignal)
        logger.info("Signal handlers registered (SIGINT, SIGTERM)")

    def stop(self) -> None:
        """
        Stop handling signals and restore original handlers.

        Safe to call multiple times (idempotent).
        """
        logger.debug("Stopping signal handler")

        # Restore original handlers
        if self._original_sigint_handler is not None:
            signal.signal(signal.SIGINT, self._original_sigint_handler)
            self._original_sigint_handler = None

        if self._original_sigterm_handler is not None:
            signal.signal(signal.SIGTERM, self._original_sigterm_handler)
            self._original_sigterm_handler = None

        logger.debug("Signal handlers restored")

    def _executeShutdownCallbacks(self) -> None:
        """Execute all registered shutdown callbacks in order."""
        with self._shutdown_lock:
            logger.info(f"Executing {len(self._shutdown_callbacks)} shutdown callbacks")

            for i, callback in enumerate(self._shutdown_callbacks, 1):
                try:
                    logger.debug(f"Executing shutdown callback {i}/{len(self._shutdown_callbacks)}: {callback.__name__}")
                    callback()
                    logger.debug(f"Shutdown callback {i} completed successfully")
                except Exception as error:
                    logger.error(f"Error in shutdown callback {i} ({callback.__name__}): {error}")

            self._shutdown_event.set()
            logger.info("All shutdown callbacks completed")

    def waitForShutdown(self) -> None:
        """
        Block until shutdown signal is received.

        Useful for keeping main thread alive during monitoring.
        """
        logger.debug("Waiting for shutdown signal")
        self._shutdown_event.wait()
        logger.debug("Shutdown signal received, resuming")

    def isShuttingDown(self) -> bool:
        """
        Check if shutdown has been initiated.

        Returns:
            True if shutdown signal received, False otherwise
        """
        return self._shutdown_event.is_set()

    def __enter__(self):
        """Context manager entry - start signal handling."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - stop signal handling."""
        self.stop()
        return False
