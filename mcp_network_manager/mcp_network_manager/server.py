"""MCP Network Manager server."""

import anyio
import click
import json
import traceback
import os
from contextlib import AsyncExitStack
from typing import Dict, List, Any, Optional, Literal, Union, Tuple
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.sse import SseServerTransport
from mcp.server.lowlevel.server import InitializationOptions
from mcp.shared.exceptions import McpError, ErrorData
from rich.console import Console
from rich.table import Table
from pydantic import BaseModel, Field
from starlette.applications import Starlette
from starlette.routing import Mount, Route
import logging
from dotenv import load_dotenv

from mcp_network_manager.device_manager import DeviceManager, Device
from mcp_network_manager.prompt_manager import PromptManager
from mcp_network_manager.kubernetes_manager import KubernetesManager, KubernetesCluster
from mcp_network_manager.security_utils import encrypt_password, decrypt_password, is_password_encrypted, get_or_create_master_key

# Load environment variables from .env file
load_dotenv()

# Ensure the master key is initialized
get_or_create_master_key()

console = Console()

# Set up logger
logger = logging.getLogger(__name__)


def device_to_dict(device: Device) -> Dict[str, Any]:
    """Convert a device to a dictionary.

    Args:
        device: Device to convert.

    Returns:
        Dictionary representation of the device.
    """
    return {
        "device_type": device.device_type,
        "device_name": device.device_name,
        "ip_address": device.ip_address,
        "username": device.username,
        "password": "********",  # Mask the password
        "ssh_port": device.ssh_port,
        "secret": "********" if device.secret else None,  # Mask the secret
        "session_log": device.session_log,
        "fast_cli": device.fast_cli,
        "timeout": device.timeout,
        "conn_timeout": device.conn_timeout,
        "auth_timeout": device.auth_timeout,
        "banner_timeout": device.banner_timeout,
        "netconf_port": device.netconf_port,
        "restconf_port": device.restconf_port,
        "global_delay_factor": device.global_delay_factor,
    }


# Define Pydantic models for tool schemas
class ListDevicesInput(BaseModel):
    """Input schema for list_devices tool."""
    pass


class AddDeviceInput(BaseModel):
    """Input schema for add_device tool."""
    device_type: str = Field(
        description="The type of device to connect to (e.g., cisco_ios, cisco_xr, juniper_junos, arista_eos). "
                  "This must be a valid Netmiko device type."
    )
    device_name: str = Field(
        description="A unique name to identify this device in the inventory."
    )
    ip_address: str = Field(
        description="The IP address or hostname of the device."
    )
    username: str = Field(
        description="The username to use for authentication."
    )
    password: str = Field(
        description="The password to use for authentication."
    )
    ssh_port: int = Field(
        default=22,
        description="The SSH port to connect to. Default is 22."
    )
    secret: Optional[str] = Field(
        default=None,
        description="The enable secret for privileged mode access on the device. "
                  "Required for devices that need privilege escalation."
    )
    session_log: Optional[str] = Field(
        default=None,
        description="Path to a file where the session log will be written. "
                  "Useful for debugging connection issues."
    )
    fast_cli: bool = Field(
        default=False,
        description="Set to True to use fast_cli mode with Cisco devices, which can significantly "
                  "speed up operations but may cause issues with some devices."
    )
    timeout: int = Field(
        default=100,
        description="The overall timeout in seconds for the connection. "
                  "This is the maximum time to wait for the entire operation."
    )
    conn_timeout: int = Field(
        default=10,
        description="The connection timeout in seconds. "
                  "This is the maximum time to wait for the initial connection."
    )
    auth_timeout: int = Field(
        default=10,
        description="The authentication timeout in seconds. "
                  "This is the maximum time to wait for authentication to complete."
    )
    banner_timeout: int = Field(
        default=15,
        description="The banner timeout in seconds. "
                  "This is the maximum time to wait for the banner to be displayed."
    )
    netconf_port: Optional[int] = Field(
        default=None,
        description="The NETCONF port to connect to. "
                  "Typically 830 for devices that support NETCONF."
    )
    restconf_port: Optional[int] = Field(
        default=None,
        description="The RESTCONF port to connect to. "
                  "Typically 443 for devices that support RESTCONF."
    )
    global_delay_factor: float = Field(
        default=1.0,
        description="A multiplier that affects timing for all Netmiko operations. "
                  "Increase this value for slower devices or connections."
    )


class RemoveDeviceInput(BaseModel):
    """Input schema for remove_device tool."""
    device_name: str = Field(
        description="Device name"
    )


class ConnectInput(BaseModel):
    """Input schema for connect tool."""
    device_name: str = Field(
        description="Device name"
    )
    auto_detect: bool = Field(
        default=False,
        description="Auto-detect device type"
    )
    password: Optional[str] = Field(
        default=None,
        description="The password to use for authentication. Required if the stored password is encrypted."
    )
    secret: Optional[str] = Field(
        default=None,
        description="The enable secret for privileged mode access. Required if the stored secret is encrypted."
    )


class DisconnectInput(BaseModel):
    """Input schema for disconnect tool."""
    device_name: str = Field(
        description="Device name"
    )


class SendCommandInput(BaseModel):
    """Input schema for send_command tool."""
    device_name: str = Field(
        description="Device name"
    )
    command: str = Field(
        description="Command to send"
    )
    password: Optional[str] = Field(
        default=None,
        description="The password to use for authentication. Required if the stored password is encrypted."
    )
    secret: Optional[str] = Field(
        default=None,
        description="The enable secret for privileged mode access. Required if the stored secret is encrypted."
    )
    expect_string: Optional[str] = Field(
        default=None,
        description="String to expect, defaults to prompt"
    )
    delay_factor: float = Field(
        default=1.0,
        description="Multiplier to adjust delays (default: 1.0)"
    )
    max_loops: int = Field(
        default=500,
        description="Maximum number of loops to wait for expect_string (default: 500)"
    )
    strip_prompt: bool = Field(
        default=True,
        description="Remove the prompt from the output (default: true)"
    )
    strip_command: bool = Field(
        default=True,
        description="Remove the command from the output (default: true)"
    )
    normalize: bool = Field(
        default=True,
        description="Normalize line endings (default: true)"
    )
    use_textfsm: bool = Field(
        default=False,
        description="Use TextFSM to parse the output (default: false)"
    )


class SendConfigInput(BaseModel):
    """Input schema for send_config tool."""
    device_name: str = Field(
        description="Device name"
    )
    config_commands: str = Field(
        description="Configuration commands to send (one per line)"
    )
    password: Optional[str] = Field(
        default=None,
        description="The password to use for authentication. Required if the stored password is encrypted."
    )
    secret: Optional[str] = Field(
        default=None,
        description="The enable secret for privileged mode access. Required if the stored secret is encrypted."
    )
    exit_config_mode: bool = Field(
        default=True,
        description="Exit config mode after sending commands (default: true)"
    )
    delay_factor: float = Field(
        default=1.0,
        description="Multiplier to adjust delays (default: 1.0)"
    )
    max_loops: int = Field(
        default=150,
        description="Maximum number of loops to wait for expect_string (default: 150)"
    )
    strip_prompt: bool = Field(
        default=True,
        description="Remove the prompt from the output (default: true)"
    )
    strip_command: bool = Field(
        default=True,
        description="Remove the command from the output (default: true)"
    )
    config_mode_command: Optional[str] = Field(
        default=None,
        description="Command to enter config mode"
    )
    
    def get_config_commands_list(self) -> List[str]:
        """Convert the config_commands string to a list of strings.
        
        Returns:
            List of configuration commands.
        """
        # Strip any trailing whitespace and split by newlines
        config_list = self.config_commands.strip().split('\n')
        
        # Remove any explicit 'exit' command at the end as Netmiko handles this with exit_config_mode
        if config_list and config_list[-1].strip().lower() == 'exit' and self.exit_config_mode:
            config_list = config_list[:-1]
            
        return config_list


class GetConfigInput(BaseModel):
    """Input schema for get_config tool."""
    device_name: str = Field(
        description="Device name"
    )
    config_type: Literal["running", "startup", "candidate"] = Field(
        default="running",
        description="Type of configuration to get (running, startup, candidate)"
    )
    password: Optional[str] = Field(
        default=None,
        description="The password to use for authentication. Required if the stored password is encrypted."
    )
    secret: Optional[str] = Field(
        default=None,
        description="The enable secret for privileged mode access. Required if the stored secret is encrypted."
    )


class CheckConnectionInput(BaseModel):
    """Input schema for check_connection tool."""
    device_name: str = Field(
        description="Device name"
    )


class ListPromptsInput(BaseModel):
    """Input schema for list_prompts tool."""
    device_type: str = Field(
        description="Device type"
    )


class ListDeviceTypesInput(BaseModel):
    """Input schema for list_device_types tool."""
    random_string: Optional[str] = Field(
        default=None,
        description="Dummy parameter for no-parameter tools"
    )


class GetPromptInput(BaseModel):
    """Input schema for get_prompt tool."""
    device_type: str = Field(
        description="Device type"
    )
    prompt_name: str = Field(
        description="Prompt name"
    )


# Kubernetes-related Pydantic models
class ListClustersInput(BaseModel):
    """Input schema for list_clusters tool."""
    pass


class AddClusterInput(BaseModel):
    """Input schema for add_cluster tool."""
    cluster_name: str = Field(
        description="A unique name to identify this cluster in the inventory."
    )
    kubeconfig_path: Optional[str] = Field(
        default=None,
        description="Path to the kubeconfig file for this cluster. If not provided, "
                    "the default kubeconfig will be used."
    )
    context: Optional[str] = Field(
        default=None,
        description="The context to use from the kubeconfig file. If not provided, "
                    "the current context will be used."
    )
    api_server: Optional[str] = Field(
        default=None,
        description="The Kubernetes API server URL. Only used if kubeconfig_path is not provided."
    )
    token: Optional[str] = Field(
        default=None,
        description="The authentication token. Only used if kubeconfig_path is not provided."
    )
    cert_file: Optional[str] = Field(
        default=None,
        description="Path to the client certificate file. Only used if kubeconfig_path is not provided."
    )
    key_file: Optional[str] = Field(
        default=None,
        description="Path to the client key file. Only used if kubeconfig_path is not provided."
    )
    ca_file: Optional[str] = Field(
        default=None,
        description="Path to the CA certificate file. Only used if kubeconfig_path is not provided."
    )
    verify_ssl: bool = Field(
        default=True,
        description="Whether to verify SSL certificates."
    )


class RemoveClusterInput(BaseModel):
    """Input schema for remove_cluster tool."""
    cluster_name: str = Field(
        description="Cluster name"
    )


class ActivateClusterInput(BaseModel):
    """Input schema for activate_cluster tool."""
    cluster_name: str = Field(
        description="Cluster name"
    )


class DeactivateClusterInput(BaseModel):
    """Input schema for deactivate_cluster tool."""
    cluster_name: str = Field(
        description="Cluster name"
    )


class IsActiveClusterInput(BaseModel):
    """Input schema for is_active_cluster tool."""
    cluster_name: str = Field(
        description="Cluster name"
    )


class GetNamespacesInput(BaseModel):
    """Input schema for get_namespaces tool."""
    cluster_name: str = Field(
        description="Cluster name"
    )


class GetPodsInput(BaseModel):
    """Input schema for get_pods tool."""
    cluster_name: str = Field(
        description="Cluster name"
    )
    namespace: str = Field(
        default="default",
        description="Namespace to get pods from"
    )


class GetServicesInput(BaseModel):
    """Input schema for get_services tool."""
    cluster_name: str = Field(
        description="Cluster name"
    )
    namespace: str = Field(
        default="default",
        description="Namespace to get services from"
    )


class GetDeploymentsInput(BaseModel):
    """Input schema for get_deployments tool."""
    cluster_name: str = Field(
        description="Cluster name"
    )
    namespace: str = Field(
        default="default",
        description="Namespace to get deployments from"
    )


class CreateNamespaceInput(BaseModel):
    """Input schema for create_namespace tool."""
    cluster_name: str = Field(
        description="Cluster name"
    )
    namespace: str = Field(
        description="Name of the namespace to create"
    )


class DeleteNamespaceInput(BaseModel):
    """Input schema for delete_namespace tool."""
    cluster_name: str = Field(
        description="Cluster name"
    )
    namespace: str = Field(
        description="Name of the namespace to delete"
    )


class ApplyYamlInput(BaseModel):
    """Input schema for apply_yaml tool."""
    cluster_name: str = Field(
        description="Cluster name"
    )
    yaml_content: str = Field(
        description="YAML manifest to apply"
    )


class ExecCommandInput(BaseModel):
    """Input schema for exec_command tool."""
    cluster_name: str = Field(
        description="Cluster name"
    )
    pod_name: str = Field(
        description="Name of the pod to execute the command in"
    )
    namespace: str = Field(
        default="default",
        description="Namespace of the pod"
    )
    container: Optional[str] = Field(
        default=None,
        description="Name of the container to execute the command in"
    )
    command: List[str] = Field(
        default=["/bin/sh", "-c", "ls"],
        description="Command to execute"
    )


class GetLogsInput(BaseModel):
    """Input schema for get_logs tool."""
    cluster_name: str = Field(
        description="Cluster name"
    )
    pod_name: str = Field(
        description="Name of the pod to get logs from"
    )
    namespace: str = Field(
        default="default",
        description="Namespace of the pod"
    )
    container: Optional[str] = Field(
        default=None,
        description="Name of the container to get logs from"
    )
    tail_lines: int = Field(
        default=100,
        description="Number of lines to get from the end of the logs"
    )


class DeleteResourceInput(BaseModel):
    """Input schema for delete_resource tool."""
    cluster_name: str = Field(
        description="Cluster name"
    )
    kind: str = Field(
        description="Kind of resource to delete (e.g., Pod, Service, Deployment)"
    )
    name: str = Field(
        description="Name of the resource to delete"
    )
    namespace: str = Field(
        default="default",
        description="Namespace of the resource"
    )


class DeleteYamlInput(BaseModel):
    """Input schema for delete_yaml tool."""
    cluster_name: str = Field(
        description="Cluster name"
    )
    yaml_content: str = Field(
        description="YAML manifest defining the resources to delete"
    )


class DeleteResourcesInput(BaseModel):
    """Input schema for delete_resources tool."""
    cluster_name: str = Field(
        description="Cluster name"
    )
    kind: str = Field(
        description="Kind of resources to delete (e.g., Pod, Service, Deployment)"
    )
    namespace: str = Field(
        default="default",
        description="Namespace of the resources"
    )
    label_selector: Optional[str] = Field(
        default=None,
        description="Label selector to filter resources (e.g., \"app=nginx\")"
    )
    field_selector: Optional[str] = Field(
        default=None,
        description="Field selector to filter resources (e.g., \"metadata.name=my-pod\")"
    )


# Convert Pydantic model to JSON schema
def model_to_schema(model_cls):
    """Convert a Pydantic model to a JSON schema for MCP tools."""
    schema = model_cls.model_json_schema()
    # Remove title, description at root level as they're not needed for tool schemas
    if "title" in schema:
        del schema["title"]
    if "description" in schema:
        del schema["description"]
    return schema


@click.command()
@click.option("--port", type=int, default=lambda: int(os.environ.get("MCP_PORT", "8000")), help="Port to listen on for SSE")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse"]),
    default=lambda: os.environ.get("MCP_TRANSPORT", "stdio"),
    help="Transport type",
)
@click.option(
    "--inventory",
    default=lambda: os.environ.get("MCP_INVENTORY", "devices.csv"),
    help="Path to the inventory file",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
    default=lambda: os.environ.get("MCP_LOG_LEVEL", "INFO"),
    help="Set the logging level",
)
def main(port: int, transport: str, inventory: str, log_level: str) -> int:
    """Run the MCP Network Manager server.

    Args:
        port: Port to listen on for SSE.
        transport: Transport type.
        inventory: Path to the inventory file.
        log_level: Logging level.

    Returns:
        Exit code.
    """
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    logger.info(f"Starting MCP Network Manager with transport={transport}, inventory={inventory}, log_level={log_level}")
    
    app = Server("mcp-network-manager")
    device_manager = DeviceManager(inventory_file=inventory)
    prompt_manager = PromptManager()
    kubernetes_manager = KubernetesManager()

    @app.call_tool()
    async def call_tool(
        name: str, arguments: dict
    ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        """Call a tool.

        Args:
            name: Tool name.
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        logger.info(f"Calling tool: {name} with arguments: {arguments}")
        
        # Map tool names to their implementation functions
        tool_map = {
            # Network device tools
            "mcp_device__list_devices": list_devices_tool,
            "mcp_device__add_device": add_device_tool,
            "mcp_device__remove_device": remove_device_tool,
            "mcp_device__connect": connect_tool,
            "mcp_device__disconnect": disconnect_tool,
            "mcp_device__send_command": send_command_tool,
            "mcp_device__send_config": send_config_tool,
            "mcp_device__get_config": get_config_tool,
            "mcp_device__check_connection": check_connection_tool,
            "mcp_device__list_prompts": list_prompts_tool,
            "mcp_device__list_device_types": list_device_types_tool,
            "mcp_device__get_prompt": get_prompt_tool,
            
            # Kubernetes tools
            "mcp_kube__list_clusters": list_clusters_tool,
            "mcp_kube__add_cluster": add_cluster_tool,
            "mcp_kube__remove_cluster": remove_cluster_tool,
            "mcp_kube__activate_cluster": activate_cluster_tool,
            "mcp_kube__deactivate_cluster": deactivate_cluster_tool,
            "mcp_kube__is_active_cluster": is_active_cluster_tool,
            "mcp_kube__get_namespaces": get_namespaces_tool,
            "mcp_kube__get_pods": get_pods_tool,
            "mcp_kube__get_services": get_services_tool,
            "mcp_kube__get_deployments": get_deployments_tool,
            "mcp_kube__create_namespace": create_namespace_tool,
            "mcp_kube__delete_namespace": delete_namespace_tool,
            "mcp_kube__apply_yaml": apply_yaml_tool,
            "mcp_kube__exec_command": exec_command_tool,
            "mcp_kube__get_logs": get_logs_tool,
            "mcp_kube__delete_resource": delete_resource_tool,
            "mcp_kube__delete_yaml": delete_yaml_tool,
            "mcp_kube__delete_resources": delete_resources_tool,
        }
        
        if name not in tool_map:
            return [types.TextContent(type="text", text=f"Unknown tool: {name}. Please use the new naming convention with domain-specific prefixes (mcp_device__ or mcp_kube__).")]
        
        try:
            return await tool_map[name](arguments)
        except Exception as e:
            logger.error(f"Error calling tool {name}: {e}")
            logger.error(traceback.format_exc())
            return [types.TextContent(type="text", text=f"Error calling tool {name}: {str(e)}")]

    async def list_devices_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """List devices tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        try:
            # Use Pydantic model for validation
            input_data = ListDevicesInput(**arguments)
            
            devices = device_manager.list_devices()
            
            # Create a table for the devices
            table = Table(title="Devices")
            table.add_column("Device Type")
            table.add_column("Device Name")
            table.add_column("IP Address")
            table.add_column("Username")
            table.add_column("SSH Port")
            table.add_column("Secret")
            table.add_column("Fast CLI")
            table.add_column("Netconf Port")
            table.add_column("Restconf Port")
            table.add_column("Connected")

            for device in devices:
                connected = device_manager.check_connection(device.device_name)
                table.add_row(
                    device.device_type,
                    device.device_name,
                    device.ip_address,
                    device.username,
                    str(device.ssh_port),
                    "Yes" if device.secret else "No",
                    "Yes" if device.fast_cli else "No",
                    str(device.netconf_port) if device.netconf_port else "N/A",
                    str(device.restconf_port) if device.restconf_port else "N/A",
                    "Yes" if connected else "No",
                )

            # Convert the table to a string
            with console.capture() as capture:
                console.print(table)
            
            return [types.TextContent(type="text", text=capture.get())]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error listing devices: {str(e)}")]

    async def add_device_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Add device tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.

        Raises:
            ValueError: If required arguments are missing.
        """
        try:
            # Use Pydantic model for validation
            device_data = AddDeviceInput(**arguments)
            
            # Create Device from validated data
            device = Device(**device_data.model_dump(exclude_none=True))
            
            # Password hashing is handled in the add_device method
            device_manager.add_device(device)
            
            return [types.TextContent(type="text", text=f"Device {device.device_name} added successfully")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error adding device: {str(e)}")]

    async def remove_device_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Remove device tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.

        Raises:
            ValueError: If required arguments are missing.
        """
        try:
            # Use Pydantic model for validation
            input_data = RemoveDeviceInput(**arguments)
            
            device = device_manager.remove_device(input_data.device_name)
            return [types.TextContent(type="text", text=f"Device {device.device_name} removed successfully")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error removing device: {str(e)}")]

    async def connect_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Connect tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.

        Raises:
            ValueError: If required arguments are missing.
        """
        try:
            # Use Pydantic model for validation
            input_data = ConnectInput(**arguments)
            
            # Pass the provided password and secret to the device manager
            result = device_manager.connect(
                device_name=input_data.device_name, 
                auto_detect=input_data.auto_detect,
                provided_password=input_data.password,
                provided_secret=input_data.secret
            )
            return [types.TextContent(type="text", text=result)]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error connecting to device: {str(e)}")]

    async def disconnect_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Disconnect tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.

        Raises:
            ValueError: If required arguments are missing.
        """
        try:
            # Use Pydantic model for validation
            input_data = DisconnectInput(**arguments)
            
            result = device_manager.disconnect(input_data.device_name)
            return [types.TextContent(type="text", text=result)]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error disconnecting from device: {str(e)}")]

    async def send_command_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Send command tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.

        Raises:
            ValueError: If required arguments are missing.
        """
        try:
            # Use Pydantic model for validation
            input_data = SendCommandInput(**arguments)
            
            # Pass the provided password and secret to the device manager
            result = device_manager.send_command(
                device_name=input_data.device_name,
                command=input_data.command,
                expect_string=input_data.expect_string,
                delay_factor=input_data.delay_factor,
                max_loops=input_data.max_loops,
                strip_prompt=input_data.strip_prompt,
                strip_command=input_data.strip_command,
                normalize=input_data.normalize,
                use_textfsm=input_data.use_textfsm,
                provided_password=input_data.password,
                provided_secret=input_data.secret
            )
            return [types.TextContent(type="text", text=result)]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error sending command: {str(e)}")]

    async def send_config_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Send config tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.

        Raises:
            ValueError: If required arguments are missing.
        """
        try:
            # Use Pydantic model for validation
            input_data = SendConfigInput(**arguments)
            
            # Pass the provided password and secret to the device manager
            result = device_manager.send_config(
                device_name=input_data.device_name,
                config_commands=input_data.get_config_commands_list(),
                exit_config_mode=input_data.exit_config_mode,
                delay_factor=input_data.delay_factor,
                max_loops=input_data.max_loops,
                strip_prompt=input_data.strip_prompt,
                strip_command=input_data.strip_command,
                config_mode_command=input_data.config_mode_command,
                provided_password=input_data.password,
                provided_secret=input_data.secret
            )
            return [types.TextContent(type="text", text=result)]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error sending configuration: {str(e)}")]

    async def get_config_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Get config tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.

        Raises:
            ValueError: If required arguments are missing.
        """
        try:
            # Use Pydantic model for validation
            input_data = GetConfigInput(**arguments)
            
            # Pass the provided password and secret to the device manager
            result = device_manager.get_config(
                device_name=input_data.device_name, 
                config_type=input_data.config_type,
                provided_password=input_data.password,
                provided_secret=input_data.secret
            )
            return [types.TextContent(type="text", text=result)]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error getting config: {str(e)}")]

    async def check_connection_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Check connection tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.

        Raises:
            ValueError: If required arguments are missing.
        """
        try:
            # Use Pydantic model for validation
            input_data = CheckConnectionInput(**arguments)
            
            result = device_manager.check_connection(input_data.device_name)
            return [types.TextContent(type="text", text=f"Device {input_data.device_name} connected: {result}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error checking connection: {str(e)}")]

    async def list_prompts_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """List prompts tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.

        Raises:
            ValueError: If required arguments are missing.
        """
        try:
            # Use Pydantic model for validation
            input_data = ListPromptsInput(**arguments)
            
            prompts = prompt_manager.list_prompts(input_data.device_type)
            
            # Create a table for the prompts
            table = Table(title=f"Prompts for {input_data.device_type}")
            table.add_column("Prompt Name")
            table.add_column("Prompt Value")

            for name, value in prompts.items():
                table.add_row(name, value)

            # Convert the table to a string
            with console.capture() as capture:
                console.print(table)
            
            return [types.TextContent(type="text", text=capture.get())]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error listing prompts: {str(e)}")]

    async def list_device_types_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """List device types tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        try:
            # Use Pydantic model for validation
            input_data = ListDeviceTypesInput(**arguments)
            
            device_types = prompt_manager.list_device_types()
            return [types.TextContent(type="text", text="\n".join(device_types))]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error listing device types: {str(e)}")]

    async def get_prompt_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Get prompt tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.

        Raises:
            ValueError: If required arguments are missing.
        """
        try:
            # Use Pydantic model for validation
            input_data = GetPromptInput(**arguments)
            
            prompt = prompt_manager.get_prompt(input_data.device_type, input_data.prompt_name)
            return [types.TextContent(type="text", text=prompt)]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error getting prompt: {str(e)}")]

    # Kubernetes tool handlers
    async def list_clusters_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """List clusters tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        try:
            # Use Pydantic model for validation
            input_data = ListClustersInput(**arguments)
            
            clusters = kubernetes_manager.list_clusters()
            
            # Create a table for the clusters
            table = Table(title="Kubernetes Clusters")
            table.add_column("Cluster Name")
            table.add_column("API Server")
            table.add_column("Kubeconfig Path")
            table.add_column("Context")
            table.add_column("Verify SSL")
            table.add_column("Active")

            for cluster in clusters:
                table.add_row(
                    cluster.cluster_name,
                    cluster.api_server or "N/A",
                    cluster.kubeconfig_path or "N/A",
                    cluster.context or "Default",
                    "Yes" if cluster.verify_ssl else "No",
                    "Yes" if cluster.active else "No",
                )

            # Convert the table to a string
            with console.capture() as capture:
                console.print(table)
            
            return [types.TextContent(type="text", text=capture.get())]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error listing clusters: {str(e)}")]

    async def add_cluster_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Add cluster tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        try:
            # Use Pydantic model for validation
            input_data = AddClusterInput(**arguments)
            
            # Create KubernetesCluster from validated data
            cluster = KubernetesCluster(**input_data.model_dump(exclude_none=True))
            kubernetes_manager.add_cluster(cluster)
            
            return [types.TextContent(type="text", text=f"Cluster {cluster.cluster_name} added successfully")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error adding cluster: {str(e)}")]

    async def remove_cluster_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Remove cluster tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        try:
            # Use Pydantic model for validation
            input_data = RemoveClusterInput(**arguments)
            
            cluster = kubernetes_manager.remove_cluster(input_data.cluster_name)
            return [types.TextContent(type="text", text=f"Cluster {cluster.cluster_name} removed successfully")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error removing cluster: {str(e)}")]

    async def activate_cluster_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Activate cluster tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        try:
            # Use Pydantic model for validation
            input_data = ActivateClusterInput(**arguments)
            
            result = kubernetes_manager.activate_cluster(input_data.cluster_name)
            return [types.TextContent(type="text", text=result)]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error activating cluster: {str(e)}")]

    async def deactivate_cluster_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Deactivate cluster tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        try:
            # Use Pydantic model for validation
            input_data = DeactivateClusterInput(**arguments)
            
            result = kubernetes_manager.deactivate_cluster(input_data.cluster_name)
            return [types.TextContent(type="text", text=result)]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error deactivating cluster: {str(e)}")]

    async def is_active_cluster_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Is active cluster tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        try:
            # Use Pydantic model for validation
            input_data = IsActiveClusterInput(**arguments)
            
            result = kubernetes_manager.is_active(input_data.cluster_name)
            return [types.TextContent(type="text", text=f"Cluster {input_data.cluster_name} active: {result}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error checking cluster status: {str(e)}")]

    async def get_namespaces_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Get namespaces tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        try:
            # Use Pydantic model for validation
            input_data = GetNamespacesInput(**arguments)
            
            namespaces = kubernetes_manager.get_namespaces(input_data.cluster_name)
            
            # Create a table for the namespaces
            table = Table(title=f"Namespaces in cluster {input_data.cluster_name}")
            table.add_column("Name")
            table.add_column("Status")
            table.add_column("Creation Timestamp")

            for ns in namespaces:
                table.add_row(
                    ns['name'],
                    ns['status'],
                    ns['creation_timestamp'] or "N/A",
                )

            # Convert the table to a string
            with console.capture() as capture:
                console.print(table)
            
            return [types.TextContent(type="text", text=capture.get())]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error getting namespaces: {str(e)}")]

    async def get_pods_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Get pods tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        try:
            # Use Pydantic model for validation
            input_data = GetPodsInput(**arguments)
            
            pods = kubernetes_manager.get_pods(input_data.cluster_name, input_data.namespace)
            
            # Create a table for the pods
            table = Table(title=f"Pods in namespace {input_data.namespace} of cluster {input_data.cluster_name}")
            table.add_column("Name")
            table.add_column("Status")
            table.add_column("IP")
            table.add_column("Node")
            table.add_column("Creation Timestamp")

            for pod in pods:
                table.add_row(
                    pod['name'],
                    pod['status'],
                    pod['ip'] or "N/A",
                    pod['node'] or "N/A",
                    pod['creation_timestamp'] or "N/A",
                )

            # Convert the table to a string
            with console.capture() as capture:
                console.print(table)
            
            return [types.TextContent(type="text", text=capture.get())]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error getting pods: {str(e)}")]

    async def get_services_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Get services tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        try:
            # Use Pydantic model for validation
            input_data = GetServicesInput(**arguments)
            
            services = kubernetes_manager.get_services(input_data.cluster_name, input_data.namespace)
            
            # Create a table for the services
            table = Table(title=f"Services in namespace {input_data.namespace} of cluster {input_data.cluster_name}")
            table.add_column("Name")
            table.add_column("Type")
            table.add_column("Cluster IP")
            table.add_column("Ports")
            table.add_column("Creation Timestamp")

            for svc in services:
                ports_str = ", ".join([
                    f"{p['port']}:{p['target_port']}/{p['protocol']}" for p in svc['ports']
                ]) if svc['ports'] else "N/A"
                
                table.add_row(
                    svc['name'],
                    svc['type'],
                    svc['cluster_ip'] or "N/A",
                    ports_str,
                    svc['creation_timestamp'] or "N/A",
                )

            # Convert the table to a string
            with console.capture() as capture:
                console.print(table)
            
            return [types.TextContent(type="text", text=capture.get())]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error getting services: {str(e)}")]

    async def get_deployments_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Get deployments tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        try:
            # Use Pydantic model for validation
            input_data = GetDeploymentsInput(**arguments)
            
            deployments = kubernetes_manager.get_deployments(input_data.cluster_name, input_data.namespace)
            
            # Create a table for the deployments
            table = Table(title=f"Deployments in namespace {input_data.namespace} of cluster {input_data.cluster_name}")
            table.add_column("Name")
            table.add_column("Replicas")
            table.add_column("Available")
            table.add_column("Ready")
            table.add_column("Creation Timestamp")

            for deploy in deployments:
                table.add_row(
                    deploy['name'],
                    str(deploy['replicas']),
                    str(deploy['available_replicas'] or 0),
                    str(deploy['ready_replicas'] or 0),
                    deploy['creation_timestamp'] or "N/A",
                )

            # Convert the table to a string
            with console.capture() as capture:
                console.print(table)
            
            return [types.TextContent(type="text", text=capture.get())]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error getting deployments: {str(e)}")]

    async def create_namespace_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Create namespace tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        try:
            # Use Pydantic model for validation
            input_data = CreateNamespaceInput(**arguments)
            
            result = kubernetes_manager.create_namespace(input_data.cluster_name, input_data.namespace)
            return [types.TextContent(type="text", text=f"Namespace {result['name']} created with status: {result['status']}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error creating namespace: {str(e)}")]

    async def delete_namespace_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Delete namespace tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        try:
            # Use Pydantic model for validation
            input_data = DeleteNamespaceInput(**arguments)
            
            result = kubernetes_manager.delete_namespace(input_data.cluster_name, input_data.namespace)
            return [types.TextContent(type="text", text=f"Namespace {result['name']} {result['status'].lower()}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error deleting namespace: {str(e)}")]

    async def apply_yaml_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Apply YAML tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        try:
            # Use Pydantic model for validation
            input_data = ApplyYamlInput(**arguments)
            
            result = kubernetes_manager.apply_yaml(input_data.cluster_name, input_data.yaml_content)
            
            # Create a table for the results
            table = Table(title=f"Applied resources to cluster {input_data.cluster_name}")
            table.add_column("Kind")
            table.add_column("Name")
            table.add_column("Namespace")
            table.add_column("Status")

            for res in result['results']:
                table.add_row(
                    res['kind'],
                    res['name'],
                    res.get('namespace', 'N/A'),
                    res['status'],
                )

            # Convert the table to a string
            with console.capture() as capture:
                console.print(table)
            
            return [types.TextContent(type="text", text=capture.get())]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error applying YAML: {str(e)}")]

    async def exec_command_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Execute command tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        try:
            # Use Pydantic model for validation
            input_data = ExecCommandInput(**arguments)
            
            result = kubernetes_manager.exec_command(
                input_data.cluster_name, 
                input_data.pod_name, 
                input_data.namespace, 
                input_data.container, 
                input_data.command
            )
            
            return [types.TextContent(type="text", text=result)]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error executing command: {str(e)}")]

    async def get_logs_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Get logs tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        try:
            # Use Pydantic model for validation
            input_data = GetLogsInput(**arguments)
            
            logs = kubernetes_manager.get_logs(
                input_data.cluster_name, 
                input_data.pod_name, 
                input_data.namespace, 
                input_data.container, 
                input_data.tail_lines
            )
            
            return [types.TextContent(type="text", text=logs)]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error getting logs: {str(e)}")]

    async def delete_resource_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Delete resource tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        try:
            # Use Pydantic model for validation
            input_data = DeleteResourceInput(**arguments)
            
            result = kubernetes_manager.delete_resource(
                input_data.cluster_name, 
                input_data.kind, 
                input_data.name, 
                input_data.namespace
            )
            
            # Format the output in a more readable way
            if 'namespace' in result:
                output = f"Deleted {input_data.kind} '{input_data.name}' from namespace '{input_data.namespace}' in cluster '{input_data.cluster_name}'"
            else:
                output = f"Deleted {input_data.kind} '{input_data.name}' from cluster '{input_data.cluster_name}'"
            
            return [types.TextContent(type="text", text=output)]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error deleting resource: {str(e)}")]

    async def delete_yaml_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Delete YAML tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        try:
            # Use Pydantic model for validation
            input_data = DeleteYamlInput(**arguments)
            
            result = kubernetes_manager.delete_yaml(input_data.cluster_name, input_data.yaml_content)
            
            # Format the results in a more readable way
            formatted_results = []
            for item in result['results']:
                if 'namespace' in item:
                    formatted_results.append(f"{item['kind']} '{item['name']}' in namespace '{item['namespace']}': {item['status']}")
                else:
                    formatted_results.append(f"{item['kind']} '{item['name']}': {item['status']}")
            
            output = f"Deleted resources from cluster '{input_data.cluster_name}':\n" + "\n".join(formatted_results)
            return [types.TextContent(type="text", text=output)]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error deleting YAML: {str(e)}")]

    async def delete_resources_tool(arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Delete resources tool.

        Args:
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        try:
            # Use Pydantic model for validation
            input_data = DeleteResourcesInput(**arguments)
            
            result = kubernetes_manager.delete_resources(
                input_data.cluster_name, 
                input_data.kind, 
                input_data.namespace, 
                input_data.label_selector, 
                input_data.field_selector
            )
            
            # Format the results in a more readable way
            formatted_results = []
            for item in result['results']:
                if 'namespace' in item:
                    formatted_results.append(f"{item['kind']} '{item['name']}' in namespace '{item['namespace']}': {item['status']}")
                else:
                    formatted_results.append(f"{item['kind']} '{item['name']}': {item['status']}")
            
            # Create a summary
            filters = []
            if input_data.label_selector:
                filters.append(f"label selector '{input_data.label_selector}'")
            if input_data.field_selector:
                filters.append(f"field selector '{input_data.field_selector}'")
            
            filter_text = ""
            if filters:
                filter_text = f" matching {' and '.join(filters)}"
            
            output = f"Deleted {result['count']} {input_data.kind} resources from namespace '{input_data.namespace}' in cluster '{input_data.cluster_name}'{filter_text}:\n" + "\n".join(formatted_results)
            return [types.TextContent(type="text", text=output)]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error deleting resources: {str(e)}")]

    @app.list_tools()
    async def list_tools() -> list[types.Tool]:
        """List tools.

        Returns:
            List of tools.
        """
        return [
            # Network device tools
            types.Tool(
                name="mcp_device__list_devices",
                description="List all devices in the inventory",
                inputSchema=model_to_schema(ListDevicesInput),
            ),
            types.Tool(
                name="mcp_device__add_device",
                description="Add a new device to the inventory",
                inputSchema=model_to_schema(AddDeviceInput),
            ),
            types.Tool(
                name="mcp_device__remove_device",
                description="Remove a device from the inventory",
                inputSchema=model_to_schema(RemoveDeviceInput),
            ),
            types.Tool(
                name="mcp_device__connect",
                description="Connect to a device",
                inputSchema=model_to_schema(ConnectInput),
            ),
            types.Tool(
                name="mcp_device__disconnect",
                description="Disconnect from a device",
                inputSchema=model_to_schema(DisconnectInput),
            ),
            types.Tool(
                name="mcp_device__send_command",
                description="Send a command to a device",
                inputSchema=model_to_schema(SendCommandInput),
            ),
            types.Tool(
                name="mcp_device__send_config",
                description="Send configuration commands to a device",
                inputSchema=model_to_schema(SendConfigInput),
            ),
            types.Tool(
                name="mcp_device__get_config",
                description="Get the configuration of a device",
                inputSchema=model_to_schema(GetConfigInput),
            ),
            types.Tool(
                name="mcp_device__check_connection",
                description="Check if a connection to a device is active",
                inputSchema=model_to_schema(CheckConnectionInput),
            ),
            types.Tool(
                name="mcp_device__list_prompts",
                description="List all prompts for a device type",
                inputSchema=model_to_schema(ListPromptsInput),
            ),
            types.Tool(
                name="mcp_device__list_device_types",
                description="List all device types",
                inputSchema=model_to_schema(ListDeviceTypesInput),
            ),
            types.Tool(
                name="mcp_device__get_prompt",
                description="Get a prompt for a device type",
                inputSchema=model_to_schema(GetPromptInput),
            ),
            # Kubernetes tools
            types.Tool(
                name="mcp_kube__list_clusters",
                description="List all Kubernetes clusters in the inventory",
                inputSchema=model_to_schema(ListClustersInput),
            ),
            types.Tool(
                name="mcp_kube__add_cluster",
                description="Add a new Kubernetes cluster to the inventory",
                inputSchema=model_to_schema(AddClusterInput),
            ),
            types.Tool(
                name="mcp_kube__remove_cluster",
                description="Remove a Kubernetes cluster from the inventory",
                inputSchema=model_to_schema(RemoveClusterInput),
            ),
            types.Tool(
                name="mcp_kube__activate_cluster",
                description="Activate a Kubernetes cluster",
                inputSchema=model_to_schema(ActivateClusterInput),
            ),
            types.Tool(
                name="mcp_kube__deactivate_cluster",
                description="Deactivate a Kubernetes cluster",
                inputSchema=model_to_schema(DeactivateClusterInput),
            ),
            types.Tool(
                name="mcp_kube__is_active_cluster",
                description="Check if a Kubernetes cluster is active",
                inputSchema=model_to_schema(IsActiveClusterInput),
            ),
            types.Tool(
                name="mcp_kube__get_namespaces",
                description="Get all namespaces in a Kubernetes cluster",
                inputSchema=model_to_schema(GetNamespacesInput),
            ),
            types.Tool(
                name="mcp_kube__get_pods",
                description="Get all pods in a Kubernetes namespace",
                inputSchema=model_to_schema(GetPodsInput),
            ),
            types.Tool(
                name="mcp_kube__get_services",
                description="Get all services in a Kubernetes namespace",
                inputSchema=model_to_schema(GetServicesInput),
            ),
            types.Tool(
                name="mcp_kube__get_deployments",
                description="Get all deployments in a Kubernetes namespace",
                inputSchema=model_to_schema(GetDeploymentsInput),
            ),
            types.Tool(
                name="mcp_kube__create_namespace",
                description="Create a namespace in a Kubernetes cluster",
                inputSchema=model_to_schema(CreateNamespaceInput),
            ),
            types.Tool(
                name="mcp_kube__delete_namespace",
                description="Delete a namespace from a Kubernetes cluster",
                inputSchema=model_to_schema(DeleteNamespaceInput),
            ),
            types.Tool(
                name="mcp_kube__apply_yaml",
                description="Apply a YAML manifest to a Kubernetes cluster",
                inputSchema=model_to_schema(ApplyYamlInput),
            ),
            types.Tool(
                name="mcp_kube__exec_command",
                description="Execute a command in a Kubernetes pod",
                inputSchema=model_to_schema(ExecCommandInput),
            ),
            types.Tool(
                name="mcp_kube__get_logs",
                description="Get logs from a Kubernetes pod",
                inputSchema=model_to_schema(GetLogsInput),
            ),
            types.Tool(
                name="mcp_kube__delete_resource",
                description="Delete a Kubernetes resource",
                inputSchema=model_to_schema(DeleteResourceInput),
            ),
            types.Tool(
                name="mcp_kube__delete_yaml",
                description="Delete Kubernetes resources defined in a YAML manifest",
                inputSchema=model_to_schema(DeleteYamlInput),
            ),
            types.Tool(
                name="mcp_kube__delete_resources",
                description="Delete Kubernetes resources matching the specified criteria",
                inputSchema=model_to_schema(DeleteResourcesInput),
            ),
        ]

    if transport == "sse":
        sse = SseServerTransport("/messages/")

        async def handle_sse(request):
            logger.info("New SSE connection request received")
            try:
                async with sse.connect_sse(
                    request.scope, request.receive, request._send
                ) as streams:
                    # Create initialization options
                    init_options = app.create_initialization_options()
                    
                    try:
                        # Wait a short time to ensure client is ready for initialization
                        await anyio.sleep(0.5)
                        logger.debug("Starting MCP server run with SSE transport")
                        await app.run(
                            streams[0], streams[1], init_options
                        )
                    except RuntimeError as e:
                        if "Received request before initialization was complete" in str(e):
                            # Log the error but don't crash the server
                            logger.warning("Client sent request before initialization was complete. Reconnection may be needed.")
                            # Send a response to the client indicating they need to reconnect
                            await streams[1].send(types.JSONRPCMessage(types.JSONRPCError(
                                jsonrpc="2.0",
                                id=None,
                                error=types.JSONRPCErrorObject(
                                    code=-32002,
                                    message="Initialization sequence error. Please reconnect and follow the proper initialization sequence."
                                )
                            )))
                        else:
                            # Re-raise other runtime errors
                            logger.error(f"Error in SSE connection: {e}")
                            raise
                    except Exception as e:
                        logger.error(f"Unexpected error in SSE connection: {e}")
                        logger.debug(traceback.format_exc())
                        raise
            except Exception as e:
                logger.error(f"Error establishing SSE connection: {e}")
                logger.debug(traceback.format_exc())
                raise

        starlette_app = Starlette(
            debug=True,
            routes=[
                Route("/sse", endpoint=handle_sse),
                Mount("/messages/", app=sse.handle_post_message),
            ],
        )

        import uvicorn

        # Ensure port is an integer
        port_int = int(port)
        uvicorn.run(starlette_app, host="0.0.0.0", port=port_int)
    else:
        from mcp.server.stdio import stdio_server

        async def arun():
            async with stdio_server() as streams:
                await app.run(
                    streams[0], streams[1], app.create_initialization_options()
                )

        anyio.run(arun)

    return 0


if __name__ == "__main__":
    main() 