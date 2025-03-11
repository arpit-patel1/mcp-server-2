"""Centralized models for the MCP Network Manager.

This module contains all the Pydantic models used across the application,
reducing duplication and improving maintainability.
"""

from typing import Dict, List, Optional, Any, Literal
from pydantic import BaseModel, Field


# Base Device Models
class Device(BaseModel):
    """Device model representing a network device that can be managed.
    
    This model contains all the parameters needed to establish a connection to a network device.
    """
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


# Kubernetes Models
class KubernetesCluster(BaseModel):
    """Kubernetes cluster model representing a Kubernetes cluster that can be managed.
    
    This model contains all the parameters needed to establish a connection to a Kubernetes cluster.
    """
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
    active: bool = Field(
        default=False,
        description="Whether this cluster is currently active."
    )


# Input Models for API/Tools

# Device Input Models
class ListDevicesInput(BaseModel):
    """Input schema for list_devices tool."""
    pass


class AddDeviceInput(Device):
    """Input schema for add_device tool."""
    pass


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
    pass


class GetPromptInput(BaseModel):
    """Input schema for get_prompt tool."""
    device_type: str = Field(
        description="Device type"
    )
    prompt_name: str = Field(
        description="Prompt name"
    )


# Kubernetes Input Models
class ListClustersInput(BaseModel):
    """Input schema for list_clusters tool."""
    pass


class AddClusterInput(KubernetesCluster):
    """Input schema for add_cluster tool."""
    pass


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