#!/usr/bin/env python3
"""FSD Python Server - Main entry point.

A Python implementation of the FSD (Flight Simulator Daemon) server
with protocol upgrade v2 security enhancements.

Usage:
    python main.py [config_file]

Features:
    - Client protocol (port 6809)
    - Server linking (port 3011)
    - Management console (port 3012, localhost only)
    - SHA-256 hashed certificate passwords
    - Challenge-response authentication ($CH/$SA)
    - Backward compatible with legacy FSD clients
    - Optional TLS support (via proxy/stunnel)
    - METAR weather download
    - Whazzup status file generation
"""

import asyncio
import logging
import os
import signal
import sys

from fsd.config import Config
from fsd.server import FSDServer


def setup_logging(debug: bool = False):
    """Configure logging to both file and console."""
    level = logging.DEBUG if debug else logging.INFO
    fmt = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    logging.basicConfig(
        level=level,
        format=fmt,
        datefmt=datefmt,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("fsd.log"),
        ]
    )


async def main():
    """Start the FSD server."""
    # Parse config
    config_file = sys.argv[1] if len(sys.argv) > 1 else "fsd.conf"
    debug = "-v" in sys.argv or "--debug" in sys.argv

    setup_logging(debug)
    logger = logging.getLogger("fsd")

    # 历史应急后门已移除；若环境里仍残留开关，启动时强告警，便于运维清理。
    for legacy_env in ("FSD_ALLOW_ANY_PASSWORD", "FSD_AUTO_ADD_UNKNOWN"):
        if os.environ.get(legacy_env, "").strip():
            logger.critical(
                "[SECURITY] %s 已废弃且不会生效；请立即从 systemd drop-in / 环境变量中移除",
                legacy_env,
            )

    # Load configuration
    config = Config(config_file)
    loaded = config.load()
    if loaded:
        logger.info(f"Loaded configuration from {config_file}")
    else:
        logger.warning(f"Config file {config_file} not found, using defaults")
        logger.warning("Create fsd.conf or specify a config file path")

    # Check required config
    if not config.system_password:
        logger.warning("System password not configured! Set [system] password= in fsd.conf")

    # Create and start server
    server = FSDServer(config)

    print()
    print("  ╔══════════════════════════════════════╗")
    print("  ║     FSD Python Server v1.0           ║")
    print("  ║     Protocol upgrade v2               ║")
    print("  ╠══════════════════════════════════════╣")
    print(f"  ║  Client port:  {config.client_port:<17}║")
    print(f"  ║  Server port:  {config.server_port:<17}║")
    print(f"  ║  System port:  {config.system_port:<17}║")
    print(f"  ║  (system on 127.0.0.1 only)          ║")
    print(f"  ║  Auth: SHA-256 + Challenge-Response   ║")
    print("  ╚══════════════════════════════════════╝")
    print()

    stop_event = asyncio.Event()

    def _request_stop() -> None:
        logger.info("Shutdown signal received, draining clients...")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig_name in ("SIGTERM", "SIGINT"):
        sig = getattr(signal, sig_name, None)
        if sig is None:
            continue
        try:
            loop.add_signal_handler(sig, _request_stop)
        except (NotImplementedError, RuntimeError):
            # Windows / 受限事件循环：退回 KeyboardInterrupt 路径
            pass

    try:
        await server.start()
        logger.info("Server is running. Send SIGTERM/Ctrl+C to stop.")

        # Keep running until a shutdown signal arrives
        while server.running and not stop_event.is_set():
            await asyncio.sleep(0.5)

    except asyncio.CancelledError:
        pass
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        await server.stop()
        logger.info("Server stopped.")


if __name__ == "__main__":
    asyncio.run(main())
