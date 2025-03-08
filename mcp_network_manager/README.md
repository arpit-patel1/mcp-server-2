# MCP Network Manager

The MCP Network Manager is a server that provides tools for managing network devices and Kubernetes clusters through a unified API.

## Features

- Network device management (using Netmiko)
- Kubernetes cluster management
- Unified API for both network devices and Kubernetes clusters
- Support for SSE and stdio transport

## Tool Naming Convention

All tools in the MCP Network Manager follow a specific naming convention with domain-specific prefixes to clearly identify their purpose:

### Network Device Management Tools (`mcp_device__` prefix)

- `mcp_device__list_devices` - List all devices in the inventory
- `mcp_device__add_device` - Add a new device to the inventory
- `mcp_device__remove_device` - Remove a device from the inventory
- `mcp_device__connect` - Connect to a device
- `mcp_device__disconnect` - Disconnect from a device
- `mcp_device__send_command` - Send a command to a device
- `mcp_device__send_config` - Send configuration commands to a device
- `mcp_device__get_config` - Get the configuration of a device
- `mcp_device__check_connection` - Check if a connection to a device is active
- `mcp_device__list_prompts` - List all prompts for a device type
- `mcp_device__list_device_types` - List all device types
- `mcp_device__get_prompt` - Get a prompt for a device type

### Kubernetes Management Tools (`mcp_kube__` prefix)

- `mcp_kube__list_clusters` - List all Kubernetes clusters in the inventory
- `mcp_kube__add_cluster` - Add a new Kubernetes cluster to the inventory
- `mcp_kube__remove_cluster` - Remove a Kubernetes cluster from the inventory
- `mcp_kube__activate_cluster` - Activate a Kubernetes cluster
- `mcp_kube__deactivate_cluster` - Deactivate a Kubernetes cluster
- `mcp_kube__is_active_cluster` - Check if a Kubernetes cluster is active
- `mcp_kube__get_namespaces` - Get all namespaces in a Kubernetes cluster
- `mcp_kube__get_pods` - Get all pods in a Kubernetes namespace
- `mcp_kube__get_services` - Get all services in a Kubernetes namespace
- `mcp_kube__get_deployments` - Get all deployments in a Kubernetes namespace
- `mcp_kube__create_namespace` - Create a namespace in a Kubernetes cluster
- `mcp_kube__delete_namespace` - Delete a namespace from a Kubernetes cluster
- `mcp_kube__apply_yaml` - Apply a YAML manifest to a Kubernetes cluster
- `mcp_kube__exec_command` - Execute a command in a Kubernetes pod
- `mcp_kube__get_logs` - Get logs from a Kubernetes pod
- `mcp_kube__delete_resource` - Delete a Kubernetes resource
- `mcp_kube__delete_yaml` - Delete Kubernetes resources defined in a YAML manifest
- `mcp_kube__delete_resources` - Delete Kubernetes resources matching the specified criteria

> **Important**: Only the current naming convention with domain-specific prefixes is supported. Old tool names without prefixes or with the generic `mcp__` prefix are no longer supported.

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Netmiko for network device management
- Kubernetes Python client for Kubernetes management

### Installation

1. Clone the repository
2. Install the dependencies: `pip install -r requirements.txt`
3. Run the server: `./start_server.sh`

### Configuration

The server can be configured using command-line arguments:

```bash
./start_server.sh --port 8000 --inventory devices.csv --transport sse --log-level INFO
```

See `./start_server.sh --help` for more information.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 