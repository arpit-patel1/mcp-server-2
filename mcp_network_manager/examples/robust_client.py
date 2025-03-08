#!/usr/bin/env python3
"""
Robust MCP Client Example

This example demonstrates a robust client implementation that handles session initialization
race conditions by implementing retry logic and connection stabilization.
"""

import asyncio
import logging
import time
import sys
import random
from typing import Optional, Dict, Any, List, Callable, Awaitable
import traceback

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Try to import the MCP client library
try:
    from mcp.client import McpClient, McpSession
except ImportError:
    logger.error("Failed to import MCP client library. Make sure it's installed.")
    sys.exit(1)

class RobustMcpClient:
    """A robust MCP client that handles connection issues and session initialization race conditions."""
    
    def __init__(
        self, 
        server_url: str = "http://localhost:8000",
        max_retries: int = 5,
        retry_delay: float = 0.5,
        connection_stabilization_delay: float = 0.2,
        session_init_timeout: float = 5.0
    ):
        """Initialize the robust MCP client.
        
        Args:
            server_url: URL of the MCP server
            max_retries: Maximum number of retries for operations
            retry_delay: Delay between retries in seconds
            connection_stabilization_delay: Delay after connection to allow session initialization
            session_init_timeout: Timeout for session initialization in seconds
        """
        self.server_url = server_url
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.connection_stabilization_delay = connection_stabilization_delay
        self.session_init_timeout = session_init_timeout
        self.client = McpClient(server_url)
        self.session: Optional[McpSession] = None
        self.session_id: Optional[str] = None
        self._connected = False
    
    async def connect(self) -> None:
        """Connect to the MCP server with retry logic."""
        for attempt in range(1, self.max_retries + 1):
            try:
                logger.info(f"Connecting to MCP server at {self.server_url} (attempt {attempt}/{self.max_retries})")
                self.session = await self.client.connect()
                self.session_id = self.session.session_id
                
                # Add a small delay to allow session initialization to complete
                logger.info(f"Connected to MCP server. Session ID: {self.session_id}")
                logger.info(f"Waiting {self.connection_stabilization_delay}s for session initialization...")
                await asyncio.sleep(self.connection_stabilization_delay)
                
                # Verify the connection with a simple ping
                await self._verify_connection()
                
                self._connected = True
                logger.info("Connection verified and ready for use")
                return
            
            except Exception as e:
                logger.warning(f"Connection attempt {attempt} failed: {str(e)}")
                if attempt < self.max_retries:
                    # Add some jitter to the retry delay to prevent thundering herd
                    jittered_delay = self.retry_delay * (0.5 + random.random())
                    logger.info(f"Retrying in {jittered_delay:.2f} seconds...")
                    await asyncio.sleep(jittered_delay)
                else:
                    logger.error(f"Failed to connect after {self.max_retries} attempts")
                    raise ConnectionError(f"Failed to connect to MCP server: {str(e)}")
    
    async def _verify_connection(self) -> None:
        """Verify that the connection is working by sending a simple request."""
        # This is a simple ping to verify the connection
        # We'll use a low-level request to avoid any complex operations
        start_time = time.time()
        while time.time() - start_time < self.session_init_timeout:
            try:
                # Try to get the session info as a simple verification
                await self.session.request("session.info", {})
                return
            except RuntimeError as e:
                if "before initialization was complete" in str(e):
                    # This is the error we're trying to handle
                    logger.debug("Session not yet initialized, waiting...")
                    await asyncio.sleep(0.1)
                else:
                    # Some other RuntimeError
                    raise
            except Exception as e:
                # Any other exception is unexpected
                logger.warning(f"Unexpected error during connection verification: {str(e)}")
                raise
        
        # If we get here, we timed out waiting for initialization
        raise TimeoutError("Timed out waiting for session initialization")
    
    async def disconnect(self) -> None:
        """Disconnect from the MCP server."""
        if self.session and self._connected:
            try:
                await self.session.disconnect()
                logger.info("Disconnected from MCP server")
            except Exception as e:
                logger.warning(f"Error during disconnect: {str(e)}")
            finally:
                self._connected = False
                self.session = None
    
    async def execute_with_retry(
        self, 
        operation: Callable[[], Awaitable[Any]]
    ) -> Any:
        """Execute an operation with retry logic.
        
        Args:
            operation: Async callable to execute
            
        Returns:
            The result of the operation
        """
        if not self._connected or not self.session:
            raise ConnectionError("Not connected to MCP server")
        
        for attempt in range(1, self.max_retries + 1):
            try:
                return await operation()
            
            except RuntimeError as e:
                error_str = str(e)
                if "before initialization was complete" in error_str and attempt < self.max_retries:
                    logger.warning(f"Session initialization error (attempt {attempt}): {error_str}")
                    # This is the specific error we're trying to handle
                    jittered_delay = self.retry_delay * (0.5 + random.random())
                    logger.info(f"Retrying in {jittered_delay:.2f} seconds...")
                    await asyncio.sleep(jittered_delay)
                else:
                    # Other runtime errors or we've exceeded max retries
                    logger.error(f"Operation failed after {attempt} attempts: {error_str}")
                    raise
            
            except Exception as e:
                # For any other exception, we'll retry a few times but log the full traceback
                if attempt < self.max_retries:
                    logger.warning(f"Operation error (attempt {attempt}): {str(e)}")
                    logger.debug(traceback.format_exc())
                    jittered_delay = self.retry_delay * (0.5 + random.random())
                    await asyncio.sleep(jittered_delay)
                else:
                    logger.error(f"Operation failed after {attempt} attempts: {str(e)}")
                    raise
        
        # This should never be reached due to the raise in the loop
        raise RuntimeError("Unexpected error in retry logic")
    
    async def send_request(self, method: str, params: Dict[str, Any] = None) -> Any:
        """Send a request to the MCP server with retry logic.
        
        Args:
            method: The method to call
            params: Parameters for the method
            
        Returns:
            The response from the server
        """
        if params is None:
            params = {}
        
        async def _operation():
            return await self.session.request(method, params)
        
        return await self.execute_with_retry(_operation)
    
    # Add convenience methods for common operations
    
    async def list_devices(self) -> List[Dict[str, Any]]:
        """List all devices in the inventory."""
        response = await self.send_request("network.list_devices")
        return response.get("devices", [])
    
    async def list_clusters(self) -> List[Dict[str, Any]]:
        """List all Kubernetes clusters in the inventory."""
        response = await self.send_request("kubernetes.list_clusters")
        return response.get("clusters", [])
    
    async def get_namespaces(self, cluster_name: str) -> List[Dict[str, Any]]:
        """Get all namespaces in a Kubernetes cluster."""
        response = await self.send_request(
            "kubernetes.get_namespaces", 
            {"cluster_name": cluster_name}
        )
        return response.get("namespaces", [])


async def main():
    """Main function to demonstrate the robust client."""
    client = RobustMcpClient(
        server_url="http://localhost:8000",
        max_retries=5,
        retry_delay=0.5,
        connection_stabilization_delay=0.5
    )
    
    try:
        # Connect to the server
        await client.connect()
        
        # List devices
        devices = await client.list_devices()
        logger.info(f"Found {len(devices)} devices:")
        for device in devices:
            logger.info(f"  - {device.get('device_name')} ({device.get('device_type')})")
        
        # List Kubernetes clusters
        clusters = await client.list_clusters()
        logger.info(f"Found {len(clusters)} Kubernetes clusters:")
        for cluster in clusters:
            logger.info(f"  - {cluster.get('cluster_name')} (Active: {cluster.get('active', False)})")
            
            # If there are active clusters, try to get namespaces
            if cluster.get("active", False):
                try:
                    namespaces = await client.get_namespaces(cluster.get("cluster_name"))
                    logger.info(f"    Found {len(namespaces)} namespaces")
                    for ns in namespaces:
                        logger.info(f"      - {ns.get('name')} ({ns.get('status')})")
                except Exception as e:
                    logger.warning(f"    Failed to get namespaces: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        logger.debug(traceback.format_exc())
    finally:
        # Always disconnect
        await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main()) 