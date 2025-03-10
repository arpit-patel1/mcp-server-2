# MCP Network Manager

The MCP Network Manager is a server that provides tools for managing network devices and Kubernetes clusters through a unified API.

## Features

- Network device management (using Netmiko)
- Kubernetes cluster management
- Unified API for both network devices and Kubernetes clusters
- Support for SSE and stdio transport
- Secure password management with Fernet encryption

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
2. Install the dependencies using one of the following methods:
   - Using pip: `pip install -r requirements.txt`
   - Using pip with pyproject.toml: `pip install -e .`
   - Using a modern Python package manager like uv: `uv pip install -e .`
3. Run the server: `./start_server.sh`

### Configuration

The server can be configured using command-line arguments:

```bash
./start_server.sh --port 8000 --inventory devices.csv --transport sse --log-level INFO
```

See `./start_server.sh --help` for more information.

### Environment Variables

The MCP Network Manager supports configuration through environment variables. You can set these variables in a `.env` file in the project root directory or export them in your shell.

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Edit the `.env` file to set your configuration:
   ```
   # Security
   MCP_NETWORK_MANAGER_KEY="your_generated_key_value"

   # Server Configuration
   MCP_PORT=8000
   MCP_TRANSPORT=stdio
   MCP_INVENTORY=devices.csv
   MCP_LOG_LEVEL=INFO
   ```

3. The `MCP_NETWORK_MANAGER_KEY` variable is particularly important for password security. When you first run the server, it will generate a master key if one is not set. You should save this value in your `.env` file to ensure consistent password encryption and decryption.

Environment variables can be overridden by command-line arguments when using `start_server.sh`.

### Password Security

The MCP Network Manager uses Fernet encryption to securely store passwords in the inventory file. This means:

1. Passwords are never stored in plain text
2. Passwords can be decrypted when needed for device connections
3. A system-wide master key protects all encrypted passwords

#### Managing Device Passwords

The MCP Network Manager includes a password management tool to help you encrypt and decrypt device passwords:

```bash
# Run the password management tool
python examples/manage_passwords.py [inventory_file]
```

This tool allows you to:
- List all devices and see which passwords are encrypted
- Encrypt passwords for devices with plain text passwords
- Decrypt passwords to view the original values (for authorized users only)

It's recommended to encrypt all passwords in your inventory file for security.

#### Migrating from Hashed Passwords

If you're upgrading from a previous version that used bcrypt hashing, you can use the migration tool to convert hashed passwords to encrypted passwords:

```bash
# Run the password migration tool
python examples/migrate_passwords.py [inventory_file]
```

This tool will:
1. Identify any passwords that are hashed with bcrypt
2. Prompt you to enter the actual passwords (since hashed passwords cannot be decrypted)
3. Encrypt the passwords using Fernet encryption
4. Save the updated inventory file

#### How Password Handling Works

When you connect to a device with an encrypted password:

1. The system detects that the password is encrypted
2. The system automatically decrypts the password using the master key
3. The decrypted password is used to establish the connection
4. The decrypted password is only held in memory during the connection and is never written to disk in plain text

This approach provides security (passwords are stored encrypted) while still allowing seamless connections to network devices (which require the actual password).

#### Connecting to Devices with Encrypted Passwords

When a device has an encrypted password, the system handles the decryption automatically:

1. **Using the CLI client**:
   ```bash
   # Run the connect_test.py script
   python examples/connect_test.py device_name
   # The password will be decrypted automatically
   ```

2. **Using the Web Client**:
   - Select the device from the list
   - Click "Connect" (no need to enter the password as it will be decrypted automatically)

3. **Using the API**:
   ```python
   # When calling the connect tool, the password will be decrypted automatically
   result = await session.call_tool("mcp_device__connect", {
       "device_name": "device_name"
   })
   
   # The same applies to send_command, send_config, and get_config
   result = await session.call_tool("mcp_device__send_command", {
       "device_name": "device_name",
       "command": "show version"
   })
   ```

> **Note**: If you need to override the stored password for a specific connection, you can still provide a password parameter in the API calls.

### Docker

You can also run the MCP Network Manager using Docker:

1. Build and start the container using Docker Compose:
   ```bash
   docker-compose up -d
   ```

2. Environment variables can be set in the `.env` file or passed directly to Docker Compose:
   ```bash
   MCP_PORT=9000 MCP_LOG_LEVEL=DEBUG docker-compose up -d
   ```

3. The server data will be persisted in the `./data` directory.

4. To view logs:
   ```bash
   docker-compose logs -f
   ```

5. To stop the server:
   ```bash
   docker-compose down
   ```

## License

This project is licensed under the MIT License - see the LICENSE file for details. 