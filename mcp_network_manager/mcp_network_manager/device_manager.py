"""Device manager for the MCP Network Manager."""

import csv
import os
from typing import Dict, List, Optional, Any
import pandas as pd
from netmiko import ConnectHandler
from netmiko.ssh_autodetect import SSHDetect
from netmiko.exceptions import (
    NetMikoTimeoutException,
    NetMikoAuthenticationException,
    ConfigInvalidException,
    ReadTimeout
)
from pydantic import BaseModel, Field


class Device(BaseModel):

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


class DeviceManager:
    """Device manager for the MCP Network Manager."""

    def __init__(self, inventory_file: str = "devices.csv"):
        """Initialize the device manager.

        Args:
            inventory_file: Path to the inventory file.
        """
        self.inventory_file = inventory_file
        self.devices: Dict[str, Device] = {}
        self.connections: Dict[str, Any] = {}
        self._load_inventory()

    def _load_inventory(self) -> None:
        """Load the inventory from the CSV file."""
        if not os.path.exists(self.inventory_file):
            # Create an empty inventory file if it doesn't exist
            with open(self.inventory_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(
                    [
                        "device_type",
                        "device_name",
                        "ip_address",
                        "username",
                        "password",
                        "ssh_port",
                        "secret",
                        "timeout",
                        "session_log",
                        "fast_cli",
                        "netconf_port",
                        "restconf_port",
                        "global_delay_factor",
                    ]
                )
            return

        try:
            df = pd.read_csv(self.inventory_file)
            for _, row in df.iterrows():
                device_data = {
                    "device_type": row["device_type"],
                    "device_name": row["device_name"],
                    "ip_address": row["ip_address"],
                    "username": row["username"],
                    "password": row["password"],
                    "ssh_port": int(row["ssh_port"]) if not pd.isna(row["ssh_port"]) else 22,
                }
                
                # Add optional parameters if they exist
                if "secret" in row and not pd.isna(row["secret"]):
                    device_data["secret"] = row["secret"]
                if "timeout" in row and not pd.isna(row["timeout"]):
                    device_data["timeout"] = int(row["timeout"])
                if "session_log" in row and not pd.isna(row["session_log"]):
                    device_data["session_log"] = row["session_log"]
                if "fast_cli" in row and not pd.isna(row["fast_cli"]):
                    device_data["fast_cli"] = bool(row["fast_cli"])
                if "netconf_port" in row and not pd.isna(row["netconf_port"]):
                    device_data["netconf_port"] = int(row["netconf_port"])
                if "restconf_port" in row and not pd.isna(row["restconf_port"]):
                    device_data["restconf_port"] = int(row["restconf_port"])
                if "global_delay_factor" in row and not pd.isna(row["global_delay_factor"]):
                    device_data["global_delay_factor"] = float(row["global_delay_factor"])
                
                device = Device(**device_data)
                self.devices[device.device_name] = device
        except Exception as e:
            raise ValueError(f"Failed to load inventory: {e}")

    def save_inventory(self) -> None:
        """Save the inventory to the CSV file."""
        df = pd.DataFrame([device.model_dump() for device in self.devices.values()])
        df.to_csv(self.inventory_file, index=False)

    def list_devices(self) -> List[Device]:
        """List all devices in the inventory.

        Returns:
            List of devices.
        """
        return list(self.devices.values())

    def add_device(self, device: Device) -> Device:
        """Add a device to the inventory.

        Args:
            device: Device to add.

        Returns:
            Added device.

        Raises:
            ValueError: If a device with the same name already exists.
        """
        if device.device_name in self.devices:
            raise ValueError(f"Device {device.device_name} already exists")

        self.devices[device.device_name] = device
        self.save_inventory()
        return device

    def remove_device(self, device_name: str) -> Device:
        """Remove a device from the inventory.

        Args:
            device_name: Name of the device to remove.

        Returns:
            Removed device.

        Raises:
            ValueError: If the device doesn't exist.
        """
        if device_name not in self.devices:
            raise ValueError(f"Device {device_name} doesn't exist")

        # Disconnect if connected
        if device_name in self.connections:
            self.disconnect(device_name)
            
        device = self.devices.pop(device_name)
        self.save_inventory()
        return device

    def get_device(self, device_name: str) -> Device:
        """Get a device from the inventory.

        Args:
            device_name: Name of the device to get.

        Returns:
            Device.

        Raises:
            ValueError: If the device doesn't exist.
        """
        if device_name not in self.devices:
            raise ValueError(f"Device {device_name} doesn't exist")

        return self.devices[device_name]

    def connect(self, device_name: str, auto_detect: bool = False) -> str:
        """Connect to a device.

        Args:
            device_name: Name of the device to connect to.
            auto_detect: Whether to auto-detect the device type.

        Returns:
            Connection status message.

        Raises:
            ValueError: If the device doesn't exist or if the connection fails.
        """
        if device_name not in self.devices:
            raise ValueError(f"Device {device_name} doesn't exist")

        if device_name in self.connections:
            return f"Already connected to {device_name}"

        device = self.devices[device_name]
        device_params = {
            "device_type": device.device_type,
            "host": device.ip_address,
            "username": device.username,
            "password": device.password,
            "port": device.ssh_port,
            "timeout": device.timeout,
            "conn_timeout": device.conn_timeout,
            "auth_timeout": device.auth_timeout,
            "banner_timeout": device.banner_timeout,
            "global_delay_factor": device.global_delay_factor,
            "fast_cli": device.fast_cli,
        }
        
        # Add optional parameters if they exist
        if device.secret:
            device_params["secret"] = device.secret
        if device.session_log:
            device_params["session_log"] = device.session_log

        try:
            if auto_detect:
                # Auto-detect the device type
                remote_device = {
                    "device_type": "autodetect",
                    "host": device.ip_address,
                    "username": device.username,
                    "password": device.password,
                    "port": device.ssh_port,
                }
                guesser = SSHDetect(**remote_device)
                best_match = guesser.autodetect()
                if best_match:
                    device_params["device_type"] = best_match
                    # Update the device type in the inventory
                    device.device_type = best_match
                    self.save_inventory()
                else:
                    raise ValueError(f"Could not auto-detect device type for {device_name}")

            # Connect to the device
            connection = ConnectHandler(**device_params)
            
            # Enter enable mode if secret is provided
            if device.secret and connection.secret:
                connection.enable()
                
            self.connections[device_name] = connection
            return f"Connected to {device_name}"
        except NetMikoTimeoutException:
            raise ValueError(f"Connection to {device_name} timed out")
        except NetMikoAuthenticationException:
            raise ValueError(f"Authentication failed for {device_name}")
        except Exception as e:
            raise ValueError(f"Failed to connect to {device_name}: {e}")

    def disconnect(self, device_name: str) -> str:
        """Disconnect from a device.

        Args:
            device_name: Name of the device to disconnect from.

        Returns:
            Disconnection status message.

        Raises:
            ValueError: If the device doesn't exist or if not connected.
        """
        if device_name not in self.devices:
            raise ValueError(f"Device {device_name} doesn't exist")

        if device_name not in self.connections:
            return f"Not connected to {device_name}"

        try:
            self.connections[device_name].disconnect()
            del self.connections[device_name]
            return f"Disconnected from {device_name}"
        except Exception as e:
            raise ValueError(f"Failed to disconnect from {device_name}: {e}")

    def check_connection(self, device_name: str) -> bool:
        """Check if a connection to a device is active.

        Args:
            device_name: Name of the device to check.

        Returns:
            True if connected, False otherwise.

        Raises:
            ValueError: If the device doesn't exist.
        """
        if device_name not in self.devices:
            raise ValueError(f"Device {device_name} doesn't exist")

        if device_name not in self.connections:
            return False
            
        # Try to send a simple command to check if the connection is still active
        try:
            self.connections[device_name].find_prompt()
            return True
        except Exception:
            # Connection is not active, clean it up
            del self.connections[device_name]
            return False

    def send_command(self, device_name: str, command: str, expect_string: Optional[str] = None, 
                    delay_factor: float = 1.0, max_loops: int = 500, 
                    strip_prompt: bool = True, strip_command: bool = True, 
                    normalize: bool = True, use_textfsm: bool = False) -> str:
        """Send a command to a device.

        Args:
            device_name: Name of the device to send the command to.
            command: Command to send.
            expect_string: String to expect, defaults to prompt.
            delay_factor: Multiplier to adjust delays.
            max_loops: Maximum number of loops to wait for expect_string.
            strip_prompt: Remove the prompt from the output.
            strip_command: Remove the command from the output.
            normalize: Normalize line endings.
            use_textfsm: Use TextFSM to parse the output.

        Returns:
            Command output.

        Raises:
            ValueError: If the device doesn't exist or if not connected.
        """
        if device_name not in self.devices:
            raise ValueError(f"Device {device_name} doesn't exist")

        if device_name not in self.connections:
            raise ValueError(f"Not connected to {device_name}")

        try:
            return self.connections[device_name].send_command(
                command, 
                expect_string=expect_string,
                delay_factor=delay_factor,
                max_loops=max_loops,
                strip_prompt=strip_prompt,
                strip_command=strip_command,
                normalize=normalize,
                use_textfsm=use_textfsm
            )
        except ReadTimeout:
            raise ValueError(f"Command timed out on {device_name}")
        except Exception as e:
            raise ValueError(f"Failed to send command to {device_name}: {e}")

    def send_config(self, device_name: str, config_commands: List[str], 
                   exit_config_mode: bool = True, delay_factor: float = 1.0,
                   max_loops: int = 150, strip_prompt: bool = True,
                   strip_command: bool = True, config_mode_command: Optional[str] = None) -> str:
        """Send configuration commands to a device.

        Args:
            device_name: Name of the device to send the commands to.
            config_commands: Configuration commands to send as a list of strings.
            exit_config_mode: Exit config mode after sending commands.
            delay_factor: Multiplier to adjust delays.
            max_loops: Maximum number of loops to wait for expect_string.
            strip_prompt: Remove the prompt from the output.
            strip_command: Remove the command from the output.
            config_mode_command: Command to enter config mode.

        Returns:
            Configuration output.

        Raises:
            ValueError: If the device doesn't exist or if not connected.
        """
        if device_name not in self.devices:
            raise ValueError(f"Device {device_name} doesn't exist")

        if device_name not in self.connections:
            raise ValueError(f"Not connected to {device_name}")

        try:
            # Increase delay factor temporarily for configuration commands if it's set to default
            if delay_factor == 1.0:
                delay_factor = 2.0  # Double the delay factor for config commands
                
            return self.connections[device_name].send_config_set(
                config_commands,
                exit_config_mode=exit_config_mode,
                delay_factor=delay_factor,
                max_loops=max_loops,
                strip_prompt=strip_prompt,
                strip_command=strip_command,
                config_mode_command=config_mode_command
            )
        except ConfigInvalidException:
            raise ValueError(f"Invalid configuration for {device_name}")
        except ReadTimeout:
            # Provide more detailed error message for timeout
            raise ValueError(f"Configuration timed out on {device_name}. Try increasing delay_factor or max_loops.")
        except Exception as e:
            raise ValueError(f"Failed to send configuration to {device_name}: {e}")

    def get_config(self, device_name: str, config_type: str = "running") -> str:
        """Get the configuration of a device.

        Args:
            device_name: Name of the device to get the configuration from.
            config_type: Type of configuration to get (running, startup, candidate).

        Returns:
            Device configuration.

        Raises:
            ValueError: If the device doesn't exist or if not connected.
        """
        if device_name not in self.devices:
            raise ValueError(f"Device {device_name} doesn't exist")

        if device_name not in self.connections:
            raise ValueError(f"Not connected to {device_name}")

        try:
            device = self.devices[device_name]
            connection = self.connections[device_name]
            
            # Use the appropriate command based on device type and config type
            if config_type == "running":
                if device.device_type in ["cisco_ios", "cisco_xe", "cisco_xr", "cisco_nxos"]:
                    return connection.send_command("show running-config")
                elif device.device_type in ["juniper", "juniper_junos"]:
                    return connection.send_command("show configuration")
                elif device.device_type in ["arista_eos"]:
                    return connection.send_command("show running-config")
                else:
                    return connection.send_command("show running-config")
            elif config_type == "startup":
                if device.device_type in ["cisco_ios", "cisco_xe", "cisco_xr", "cisco_nxos"]:
                    return connection.send_command("show startup-config")
                elif device.device_type in ["juniper", "juniper_junos"]:
                    return connection.send_command("show configuration")
                elif device.device_type in ["arista_eos"]:
                    return connection.send_command("show startup-config")
                else:
                    return connection.send_command("show startup-config")
            elif config_type == "candidate":
                if device.device_type in ["juniper", "juniper_junos"]:
                    return connection.send_command("show configuration | display set")
                else:
                    raise ValueError(f"Candidate configuration not supported for {device.device_type}")
            else:
                raise ValueError(f"Invalid configuration type: {config_type}")
        except Exception as e:
            raise ValueError(f"Failed to get configuration from {device_name}: {e}") 