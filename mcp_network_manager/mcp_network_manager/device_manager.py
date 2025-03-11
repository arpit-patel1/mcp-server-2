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
from pydantic import Field

from mcp_network_manager.security_utils import encrypt_password, decrypt_password, is_password_encrypted
from mcp_network_manager.models import Device


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
                    "password": row["password"],  # Password is loaded as is (may be encrypted)
                    "ssh_port": int(row["ssh_port"]) if not pd.isna(row["ssh_port"]) else 22,
                }
                
                # Add optional parameters if they exist
                if "secret" in row and not pd.isna(row["secret"]):
                    device_data["secret"] = row["secret"]  # Secret is loaded as is (may be encrypted)
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
        # Make sure passwords are encrypted before saving
        for device in self.devices.values():
            if not is_password_encrypted(device.password):
                device.password = encrypt_password(device.password)
            if device.secret and not is_password_encrypted(device.secret):
                device.secret = encrypt_password(device.secret)
                
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

        # Encrypt the password and secret before storing
        if not is_password_encrypted(device.password):
            device.password = encrypt_password(device.password)
        if device.secret and not is_password_encrypted(device.secret):
            device.secret = encrypt_password(device.secret)
            
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

    def connect(self, device_name: str, auto_detect: bool = False, provided_password: str = None, provided_secret: str = None) -> str:
        """Connect to a device.

        Args:
            device_name: Name of the device to connect to.
            auto_detect: Whether to auto-detect the device type.
            provided_password: Optional password to use instead of the stored one.
            provided_secret: Optional secret to use instead of the stored one.

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
        
        # Get the actual password for connection
        # If the password is encrypted, decrypt it
        # If a password is provided, use it instead
        actual_password = device.password
        if is_password_encrypted(actual_password):
            if provided_password:
                actual_password = provided_password
            else:
                try:
                    actual_password = decrypt_password(actual_password)
                except Exception as e:
                    raise ValueError(f"Failed to decrypt password for {device_name}: {e}")
        
        # Same logic for secret
        actual_secret = device.secret
        if actual_secret and is_password_encrypted(actual_secret):
            if provided_secret:
                actual_secret = provided_secret
            else:
                try:
                    actual_secret = decrypt_password(actual_secret)
                except Exception as e:
                    raise ValueError(f"Failed to decrypt secret for {device_name}: {e}")
        
        device_params = {
            "device_type": device.device_type,
            "host": device.ip_address,
            "username": device.username,
            "password": actual_password,
            "port": device.ssh_port,
            "timeout": device.timeout,
            "conn_timeout": device.conn_timeout,
            "auth_timeout": device.auth_timeout,
            "banner_timeout": device.banner_timeout,
            "global_delay_factor": device.global_delay_factor,
            "fast_cli": device.fast_cli,
        }
        
        # Add optional parameters if they exist
        if actual_secret:
            device_params["secret"] = actual_secret
        if device.session_log:
            device_params["session_log"] = device.session_log

        try:
            if auto_detect:
                # Auto-detect the device type
                remote_device = {
                    "device_type": "autodetect",
                    "host": device.ip_address,
                    "username": device.username,
                    "password": actual_password,
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
            if actual_secret and connection.secret:
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

        return device_name in self.connections

    def send_command(self, device_name: str, command: str, expect_string: Optional[str] = None, 
                    delay_factor: float = 1.0, max_loops: int = 500, 
                    strip_prompt: bool = True, strip_command: bool = True, 
                    normalize: bool = True, use_textfsm: bool = False,
                    provided_password: str = None, provided_secret: str = None) -> str:
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
            provided_password: Optional password to use if not connected.
            provided_secret: Optional secret to use if not connected.

        Returns:
            Command output.

        Raises:
            ValueError: If the device doesn't exist or if not connected.
        """
        if device_name not in self.devices:
            raise ValueError(f"Device {device_name} doesn't exist")

        # If not connected, try to connect first
        if device_name not in self.connections:
            self.connect(device_name, provided_password=provided_password, provided_secret=provided_secret)

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
            # Provide more detailed error message for timeout
            raise ValueError(f"Command timed out on {device_name}. Try increasing delay_factor or max_loops.")
        except Exception as e:
            raise ValueError(f"Failed to send command to {device_name}: {e}")

    def send_config(self, device_name: str, config_commands: List[str], 
                   exit_config_mode: bool = True, delay_factor: float = 1.0,
                   max_loops: int = 150, strip_prompt: bool = True,
                   strip_command: bool = True, config_mode_command: Optional[str] = None,
                   provided_password: str = None, provided_secret: str = None) -> str:
        """Send configuration commands to a device.

        Args:
            device_name: Name of the device to send the configuration to.
            config_commands: List of configuration commands to send.
            exit_config_mode: Whether to exit config mode after sending commands.
            delay_factor: Multiplier to adjust delays.
            max_loops: Maximum number of loops to wait for expect_string.
            strip_prompt: Remove the prompt from the output.
            strip_command: Remove the command from the output.
            config_mode_command: Command to enter config mode.
            provided_password: Optional password to use if not connected.
            provided_secret: Optional secret to use if not connected.

        Returns:
            Configuration output.

        Raises:
            ValueError: If the device doesn't exist or if not connected.
        """
        if device_name not in self.devices:
            raise ValueError(f"Device {device_name} doesn't exist")

        # If not connected, try to connect first
        if device_name not in self.connections:
            self.connect(device_name, provided_password=provided_password, provided_secret=provided_secret)

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

    def get_config(self, device_name: str, config_type: str = "running", 
                  provided_password: str = None, provided_secret: str = None) -> str:
        """Get the configuration of a device.

        Args:
            device_name: Name of the device to get the configuration from.
            config_type: Type of configuration to get (running, startup, candidate).
            provided_password: Optional password to use if not connected.
            provided_secret: Optional secret to use if not connected.

        Returns:
            Device configuration.

        Raises:
            ValueError: If the device doesn't exist or if not connected.
        """
        if device_name not in self.devices:
            raise ValueError(f"Device {device_name} doesn't exist")

        # If not connected, try to connect first
        if device_name not in self.connections:
            self.connect(device_name, provided_password=provided_password, provided_secret=provided_secret)

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