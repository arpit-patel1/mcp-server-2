"""Prompt manager for the MCP Network Manager."""

from typing import Dict, List


class PromptManager:
    """Prompt manager for the MCP Network Manager."""

    def __init__(self):
        """Initialize the prompt manager."""
        self.prompts: Dict[str, Dict[str, str]] = {
            "cisco_ios": self._get_cisco_ios_prompts(),
            "cisco_xr": self._get_cisco_xr_prompts(),
            "cisco_nxos": self._get_cisco_nxos_prompts(),
            "juniper": self._get_juniper_prompts(),
            "arista_eos": self._get_arista_prompts(),
        }

    def _get_cisco_ios_prompts(self) -> Dict[str, str]:
        """Get prompts for Cisco IOS devices.

        Returns:
            Dictionary of prompts.
        """
        return {
            "show_version": "show version",
            "show_interfaces": "show interfaces",
            "show_ip_interfaces": "show ip interface brief",
            "show_running_config": "show running-config",
            "show_startup_config": "show startup-config",
            "show_cdp_neighbors": "show cdp neighbors",
            "show_cdp_neighbors_detail": "show cdp neighbors detail",
            "show_inventory": "show inventory",
            "show_ip_route": "show ip route",
            "show_vlan": "show vlan",
            "show_mac_address_table": "show mac address-table",
            "show_spanning_tree": "show spanning-tree",
            "show_logging": "show logging",
            "show_ntp_status": "show ntp status",
            "show_ntp_associations": "show ntp associations",
            "show_environment": "show environment all",
            "show_processes_cpu": "show processes cpu",
            "show_processes_memory": "show processes memory",
            "show_tech_support": "show tech-support",
            "configure_interface": "interface {interface}\n{commands}\nexit",
            "configure_acl": "ip access-list {acl_type} {acl_name}\n{commands}\nexit",
            "configure_vlan": "vlan {vlan_id}\nname {vlan_name}\nexit",
            "configure_router": "router {protocol} {process_id}\n{commands}\nexit",
        }

    def _get_cisco_xr_prompts(self) -> Dict[str, str]:
        """Get prompts for Cisco XR devices.

        Returns:
            Dictionary of prompts.
        """
        return {
            "show_version": "show version",
            "show_interfaces": "show interfaces",
            "show_ip_interfaces": "show ipv4 interface brief",
            "show_running_config": "show running-config",
            "show_cdp_neighbors": "show cdp neighbors",
            "show_cdp_neighbors_detail": "show cdp neighbors detail",
            "show_inventory": "show inventory",
            "show_ip_route": "show route",
            "show_logging": "show logging",
            "show_ntp_status": "show ntp status",
            "show_environment": "show environment",
            "show_processes_cpu": "show processes cpu",
            "show_processes_memory": "show processes memory",
            "show_tech_support": "show tech-support",
            "configure_interface": "interface {interface}\n{commands}\nexit",
            "configure_acl": "ipv4 access-list {acl_name}\n{commands}\nexit",
            "configure_router": "router {protocol} {process_id}\n{commands}\nexit",
        }

    def _get_cisco_nxos_prompts(self) -> Dict[str, str]:
        """Get prompts for Cisco NX-OS devices.

        Returns:
            Dictionary of prompts.
        """
        return {
            "show_version": "show version",
            "show_interfaces": "show interface",
            "show_ip_interfaces": "show ip interface brief",
            "show_running_config": "show running-config",
            "show_startup_config": "show startup-config",
            "show_cdp_neighbors": "show cdp neighbors",
            "show_cdp_neighbors_detail": "show cdp neighbors detail",
            "show_inventory": "show inventory",
            "show_ip_route": "show ip route",
            "show_vlan": "show vlan",
            "show_mac_address_table": "show mac address-table",
            "show_spanning_tree": "show spanning-tree",
            "show_logging": "show logging",
            "show_ntp_status": "show ntp status",
            "show_ntp_associations": "show ntp peers",
            "show_environment": "show environment",
            "show_processes_cpu": "show processes cpu",
            "show_processes_memory": "show processes memory",
            "show_tech_support": "show tech-support",
            "configure_interface": "interface {interface}\n{commands}\nexit",
            "configure_acl": "ip access-list {acl_name}\n{commands}\nexit",
            "configure_vlan": "vlan {vlan_id}\nname {vlan_name}\nexit",
            "configure_router": "router {protocol} {process_id}\n{commands}\nexit",
        }

    def _get_juniper_prompts(self) -> Dict[str, str]:
        """Get prompts for Juniper devices.

        Returns:
            Dictionary of prompts.
        """
        return {
            "show_version": "show version",
            "show_interfaces": "show interfaces",
            "show_ip_interfaces": "show interfaces terse",
            "show_running_config": "show configuration",
            "show_inventory": "show chassis hardware",
            "show_ip_route": "show route",
            "show_vlan": "show vlans",
            "show_mac_address_table": "show ethernet-switching table",
            "show_spanning_tree": "show spanning-tree bridge",
            "show_logging": "show log messages",
            "show_ntp_status": "show ntp status",
            "show_ntp_associations": "show ntp associations",
            "show_environment": "show chassis environment",
            "show_processes_cpu": "show system processes extensive",
            "show_processes_memory": "show system memory",
            "show_tech_support": "request support information",
            "configure_interface": "edit interfaces {interface}\n{commands}\nexit",
            "configure_acl": "edit firewall family inet filter {acl_name}\n{commands}\nexit",
            "configure_vlan": "edit vlans {vlan_name}\nset vlan-id {vlan_id}\nexit",
            "configure_router": "edit protocols {protocol}\n{commands}\nexit",
        }

    def _get_arista_prompts(self) -> Dict[str, str]:
        """Get prompts for Arista devices.

        Returns:
            Dictionary of prompts.
        """
        return {
            "show_version": "show version",
            "show_interfaces": "show interfaces",
            "show_ip_interfaces": "show ip interface brief",
            "show_running_config": "show running-config",
            "show_startup_config": "show startup-config",
            "show_inventory": "show inventory",
            "show_ip_route": "show ip route",
            "show_vlan": "show vlan",
            "show_mac_address_table": "show mac address-table",
            "show_spanning_tree": "show spanning-tree",
            "show_logging": "show logging",
            "show_ntp_status": "show ntp status",
            "show_ntp_associations": "show ntp associations",
            "show_environment": "show environment all",
            "show_processes_cpu": "show processes top",
            "show_processes_memory": "show processes top memory",
            "show_tech_support": "show tech-support",
            "configure_interface": "interface {interface}\n{commands}\nexit",
            "configure_acl": "ip access-list {acl_type} {acl_name}\n{commands}\nexit",
            "configure_vlan": "vlan {vlan_id}\nname {vlan_name}\nexit",
            "configure_router": "router {protocol} {process_id}\n{commands}\nexit",
        }

    def get_prompt(self, device_type: str, prompt_name: str) -> str:
        """Get a prompt for a device type.

        Args:
            device_type: Device type.
            prompt_name: Prompt name.

        Returns:
            Prompt.

        Raises:
            ValueError: If the device type or prompt doesn't exist.
        """
        if device_type not in self.prompts:
            raise ValueError(f"Device type {device_type} doesn't exist")

        if prompt_name not in self.prompts[device_type]:
            raise ValueError(f"Prompt {prompt_name} doesn't exist for {device_type}")

        return self.prompts[device_type][prompt_name]

    def list_prompts(self, device_type: str) -> List[str]:
        """List all prompts for a device type.

        Args:
            device_type: Device type.

        Returns:
            List of prompts.

        Raises:
            ValueError: If the device type doesn't exist.
        """
        if device_type not in self.prompts:
            raise ValueError(f"Device type {device_type} doesn't exist")

        return list(self.prompts[device_type].keys())

    def list_device_types(self) -> List[str]:
        """List all device types.

        Returns:
            List of device types.
        """
        return list(self.prompts.keys()) 