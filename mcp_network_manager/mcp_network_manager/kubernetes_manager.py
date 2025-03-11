"""Kubernetes manager for the MCP Network Manager."""

import os
import json
import yaml
from typing import Dict, List, Optional, Any, Union
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream

from mcp_network_manager.models import KubernetesCluster


class KubernetesManager:
    """Kubernetes manager for the MCP Network Manager."""

    def __init__(self, clusters_file: str = "kubernetes_clusters.json"):
        """Initialize the Kubernetes manager.

        Args:
            clusters_file: Path to the clusters file.
        """
        self.clusters_file = clusters_file
        self.clusters: Dict[str, KubernetesCluster] = {}
        self.active_clients: Dict[str, Any] = {}
        self._load_clusters()

    def _load_clusters(self) -> None:
        """Load the clusters from the JSON file."""
        if not os.path.exists(self.clusters_file):
            # Create an empty clusters file if it doesn't exist
            with open(self.clusters_file, "w") as f:
                json.dump([], f)
            return

        try:
            with open(self.clusters_file, "r") as f:
                clusters_data = json.load(f)
                
            for cluster_data in clusters_data:
                cluster = KubernetesCluster(**cluster_data)
                self.clusters[cluster.cluster_name] = cluster
                
                # Initialize client for active clusters
                if cluster.active:
                    self._init_client(cluster.cluster_name)
        except Exception as e:
            raise ValueError(f"Failed to load clusters: {e}")

    def save_clusters(self) -> None:
        """Save the clusters to the JSON file."""
        clusters_data = [cluster.model_dump() for cluster in self.clusters.values()]
        with open(self.clusters_file, "w") as f:
            json.dump(clusters_data, f, indent=2)

    def list_clusters(self) -> List[KubernetesCluster]:
        """List all clusters in the inventory.

        Returns:
            List of clusters.
        """
        return list(self.clusters.values())

    def add_cluster(self, cluster: KubernetesCluster) -> KubernetesCluster:
        """Add a cluster to the inventory.

        Args:
            cluster: Cluster to add.

        Returns:
            Added cluster.

        Raises:
            ValueError: If a cluster with the same name already exists.
        """
        if cluster.cluster_name in self.clusters:
            raise ValueError(f"Cluster {cluster.cluster_name} already exists")

        self.clusters[cluster.cluster_name] = cluster
        self.save_clusters()
        
        # Initialize client if the cluster is active
        if cluster.active:
            self._init_client(cluster.cluster_name)
            
        return cluster

    def remove_cluster(self, cluster_name: str) -> KubernetesCluster:
        """Remove a cluster from the inventory.

        Args:
            cluster_name: Name of the cluster to remove.

        Returns:
            Removed cluster.

        Raises:
            ValueError: If the cluster doesn't exist.
        """
        if cluster_name not in self.clusters:
            raise ValueError(f"Cluster {cluster_name} doesn't exist")

        # Remove client if it exists
        if cluster_name in self.active_clients:
            del self.active_clients[cluster_name]
            
        cluster = self.clusters.pop(cluster_name)
        self.save_clusters()
        return cluster

    def get_cluster(self, cluster_name: str) -> KubernetesCluster:
        """Get a cluster from the inventory.

        Args:
            cluster_name: Name of the cluster to get.

        Returns:
            Cluster.

        Raises:
            ValueError: If the cluster doesn't exist.
        """
        if cluster_name not in self.clusters:
            raise ValueError(f"Cluster {cluster_name} doesn't exist")

        return self.clusters[cluster_name]

    def _init_client(self, cluster_name: str) -> None:
        """Initialize a Kubernetes client for a cluster.

        Args:
            cluster_name: Name of the cluster to initialize the client for.

        Raises:
            ValueError: If the cluster doesn't exist or if initialization fails.
        """
        if cluster_name not in self.clusters:
            raise ValueError(f"Cluster {cluster_name} doesn't exist")

        cluster = self.clusters[cluster_name]
        
        try:
            # Create a new client configuration
            configuration = client.Configuration()
            
            if cluster.kubeconfig_path:
                # Load from kubeconfig file
                if cluster.context:
                    config.load_kube_config(
                        config_file=cluster.kubeconfig_path,
                        context=cluster.context
                    )
                else:
                    config.load_kube_config(config_file=cluster.kubeconfig_path)
                
                # Get the current configuration
                configuration = client.Configuration().get_default_copy()
            else:
                # Configure using provided parameters
                if cluster.api_server:
                    configuration.host = cluster.api_server
                else:
                    # If no kubeconfig_path and no api_server, load from default kubeconfig
                    try:
                        config.load_kube_config()
                        configuration = client.Configuration().get_default_copy()
                    except Exception as e:
                        raise ValueError(f"Failed to load default kubeconfig: {e}")
                
                if cluster.token:
                    configuration.api_key['authorization'] = cluster.token
                    configuration.api_key_prefix['authorization'] = 'Bearer'
                
                if cluster.cert_file and cluster.key_file:
                    configuration.cert_file = cluster.cert_file
                    configuration.key_file = cluster.key_file
                
                if cluster.ca_file:
                    configuration.ssl_ca_cert = cluster.ca_file
                
                configuration.verify_ssl = cluster.verify_ssl
            
            # Create API clients
            api_client = client.ApiClient(configuration)
            core_v1_api = client.CoreV1Api(api_client)
            apps_v1_api = client.AppsV1Api(api_client)
            networking_v1_api = client.NetworkingV1Api(api_client)
            batch_v1_api = client.BatchV1Api(api_client)
            
            # Store clients
            self.active_clients[cluster_name] = {
                'api_client': api_client,
                'core_v1_api': core_v1_api,
                'apps_v1_api': apps_v1_api,
                'networking_v1_api': networking_v1_api,
                'batch_v1_api': batch_v1_api
            }
            
            # Mark cluster as active
            cluster.active = True
            self.save_clusters()
            
        except Exception as e:
            # Mark cluster as inactive
            cluster.active = False
            self.save_clusters()
            raise ValueError(f"Failed to initialize client for cluster {cluster_name}: {e}")

    def activate_cluster(self, cluster_name: str) -> str:
        """Activate a cluster.

        Args:
            cluster_name: Name of the cluster to activate.

        Returns:
            Activation status message.

        Raises:
            ValueError: If the cluster doesn't exist or if activation fails.
        """
        if cluster_name not in self.clusters:
            raise ValueError(f"Cluster {cluster_name} doesn't exist")

        if cluster_name in self.active_clients:
            return f"Cluster {cluster_name} is already active"

        try:
            self._init_client(cluster_name)
            return f"Activated cluster {cluster_name}"
        except Exception as e:
            raise ValueError(f"Failed to activate cluster {cluster_name}: {e}")

    def deactivate_cluster(self, cluster_name: str) -> str:
        """Deactivate a cluster.

        Args:
            cluster_name: Name of the cluster to deactivate.

        Returns:
            Deactivation status message.

        Raises:
            ValueError: If the cluster doesn't exist.
        """
        if cluster_name not in self.clusters:
            raise ValueError(f"Cluster {cluster_name} doesn't exist")

        if cluster_name not in self.active_clients:
            return f"Cluster {cluster_name} is not active"

        # Remove client
        del self.active_clients[cluster_name]
        
        # Mark cluster as inactive
        cluster = self.clusters[cluster_name]
        cluster.active = False
        self.save_clusters()
        
        return f"Deactivated cluster {cluster_name}"

    def is_active(self, cluster_name: str) -> bool:
        """Check if a cluster is active.

        Args:
            cluster_name: Name of the cluster to check.

        Returns:
            True if the cluster is active, False otherwise.

        Raises:
            ValueError: If the cluster doesn't exist.
        """
        if cluster_name not in self.clusters:
            raise ValueError(f"Cluster {cluster_name} doesn't exist")

        return cluster_name in self.active_clients

    def get_namespaces(self, cluster_name: str) -> List[Dict[str, Any]]:
        """Get all namespaces in a cluster.

        Args:
            cluster_name: Name of the cluster to get namespaces from.

        Returns:
            List of namespaces.

        Raises:
            ValueError: If the cluster doesn't exist or is not active.
        """
        if cluster_name not in self.clusters:
            raise ValueError(f"Cluster {cluster_name} doesn't exist")

        if cluster_name not in self.active_clients:
            raise ValueError(f"Cluster {cluster_name} is not active")

        try:
            core_v1_api = self.active_clients[cluster_name]['core_v1_api']
            namespaces = core_v1_api.list_namespace()
            
            result = []
            for ns in namespaces.items:
                result.append({
                    'name': ns.metadata.name,
                    'status': ns.status.phase,
                    'creation_timestamp': ns.metadata.creation_timestamp.isoformat() if ns.metadata.creation_timestamp else None
                })
            
            return result
        except ApiException as e:
            raise ValueError(f"Failed to get namespaces from cluster {cluster_name}: {e}")

    def get_pods(self, cluster_name: str, namespace: str = "default") -> List[Dict[str, Any]]:
        """Get all pods in a namespace.

        Args:
            cluster_name: Name of the cluster to get pods from.
            namespace: Namespace to get pods from.

        Returns:
            List of pods.

        Raises:
            ValueError: If the cluster doesn't exist or is not active.
        """
        if cluster_name not in self.clusters:
            raise ValueError(f"Cluster {cluster_name} doesn't exist")

        if cluster_name not in self.active_clients:
            raise ValueError(f"Cluster {cluster_name} is not active")

        try:
            core_v1_api = self.active_clients[cluster_name]['core_v1_api']
            pods = core_v1_api.list_namespaced_pod(namespace)
            
            result = []
            for pod in pods.items:
                result.append({
                    'name': pod.metadata.name,
                    'namespace': pod.metadata.namespace,
                    'status': pod.status.phase,
                    'ip': pod.status.pod_ip,
                    'node': pod.spec.node_name,
                    'creation_timestamp': pod.metadata.creation_timestamp.isoformat() if pod.metadata.creation_timestamp else None
                })
            
            return result
        except ApiException as e:
            raise ValueError(f"Failed to get pods from cluster {cluster_name}: {e}")

    def get_services(self, cluster_name: str, namespace: str = "default") -> List[Dict[str, Any]]:
        """Get all services in a namespace.

        Args:
            cluster_name: Name of the cluster to get services from.
            namespace: Namespace to get services from.

        Returns:
            List of services.

        Raises:
            ValueError: If the cluster doesn't exist or is not active.
        """
        if cluster_name not in self.clusters:
            raise ValueError(f"Cluster {cluster_name} doesn't exist")

        if cluster_name not in self.active_clients:
            raise ValueError(f"Cluster {cluster_name} is not active")

        try:
            core_v1_api = self.active_clients[cluster_name]['core_v1_api']
            services = core_v1_api.list_namespaced_service(namespace)
            
            result = []
            for svc in services.items:
                ports = []
                if svc.spec.ports:
                    for port in svc.spec.ports:
                        ports.append({
                            'name': port.name,
                            'port': port.port,
                            'target_port': port.target_port,
                            'protocol': port.protocol
                        })
                
                result.append({
                    'name': svc.metadata.name,
                    'namespace': svc.metadata.namespace,
                    'cluster_ip': svc.spec.cluster_ip,
                    'type': svc.spec.type,
                    'ports': ports,
                    'creation_timestamp': svc.metadata.creation_timestamp.isoformat() if svc.metadata.creation_timestamp else None
                })
            
            return result
        except ApiException as e:
            raise ValueError(f"Failed to get services from cluster {cluster_name}: {e}")

    def get_deployments(self, cluster_name: str, namespace: str = "default") -> List[Dict[str, Any]]:
        """Get all deployments in a namespace.

        Args:
            cluster_name: Name of the cluster to get deployments from.
            namespace: Namespace to get deployments from.

        Returns:
            List of deployments.

        Raises:
            ValueError: If the cluster doesn't exist or is not active.
        """
        if cluster_name not in self.clusters:
            raise ValueError(f"Cluster {cluster_name} doesn't exist")

        if cluster_name not in self.active_clients:
            raise ValueError(f"Cluster {cluster_name} is not active")

        try:
            apps_v1_api = self.active_clients[cluster_name]['apps_v1_api']
            deployments = apps_v1_api.list_namespaced_deployment(namespace)
            
            result = []
            for deploy in deployments.items:
                result.append({
                    'name': deploy.metadata.name,
                    'namespace': deploy.metadata.namespace,
                    'replicas': deploy.spec.replicas,
                    'available_replicas': deploy.status.available_replicas,
                    'ready_replicas': deploy.status.ready_replicas,
                    'creation_timestamp': deploy.metadata.creation_timestamp.isoformat() if deploy.metadata.creation_timestamp else None
                })
            
            return result
        except ApiException as e:
            raise ValueError(f"Failed to get deployments from cluster {cluster_name}: {e}")

    def create_namespace(self, cluster_name: str, namespace: str) -> Dict[str, Any]:
        """Create a namespace in a cluster.

        Args:
            cluster_name: Name of the cluster to create the namespace in.
            namespace: Name of the namespace to create.

        Returns:
            Created namespace.

        Raises:
            ValueError: If the cluster doesn't exist or is not active.
        """
        if cluster_name not in self.clusters:
            raise ValueError(f"Cluster {cluster_name} doesn't exist")

        if cluster_name not in self.active_clients:
            raise ValueError(f"Cluster {cluster_name} is not active")

        try:
            core_v1_api = self.active_clients[cluster_name]['core_v1_api']
            
            # Create namespace object
            namespace_manifest = client.V1Namespace(
                metadata=client.V1ObjectMeta(name=namespace)
            )
            
            # Create namespace
            ns = core_v1_api.create_namespace(namespace_manifest)
            
            return {
                'name': ns.metadata.name,
                'status': ns.status.phase,
                'creation_timestamp': ns.metadata.creation_timestamp.isoformat() if ns.metadata.creation_timestamp else None
            }
        except ApiException as e:
            raise ValueError(f"Failed to create namespace in cluster {cluster_name}: {e}")

    def delete_namespace(self, cluster_name: str, namespace: str) -> Dict[str, Any]:
        """Delete a namespace from a cluster.

        Args:
            cluster_name: Name of the cluster to delete the namespace from.
            namespace: Name of the namespace to delete.

        Returns:
            Status of the deletion.

        Raises:
            ValueError: If the cluster doesn't exist or is not active.
        """
        if cluster_name not in self.clusters:
            raise ValueError(f"Cluster {cluster_name} doesn't exist")

        if cluster_name not in self.active_clients:
            raise ValueError(f"Cluster {cluster_name} is not active")

        try:
            core_v1_api = self.active_clients[cluster_name]['core_v1_api']
            
            # Delete namespace
            core_v1_api.delete_namespace(namespace)
            
            return {
                'name': namespace,
                'status': 'Deleted'
            }
        except ApiException as e:
            raise ValueError(f"Failed to delete namespace from cluster {cluster_name}: {e}")

    def apply_yaml(self, cluster_name: str, yaml_content: str) -> Dict[str, Any]:
        """Apply a YAML manifest to a cluster.

        Args:
            cluster_name: Name of the cluster to apply the manifest to.
            yaml_content: YAML manifest to apply.

        Returns:
            Status of the application.

        Raises:
            ValueError: If the cluster doesn't exist or is not active.
        """
        if cluster_name not in self.clusters:
            raise ValueError(f"Cluster {cluster_name} doesn't exist")

        if cluster_name not in self.active_clients:
            raise ValueError(f"Cluster {cluster_name} is not active")

        try:
            # Parse YAML
            docs = yaml.safe_load_all(yaml_content)
            
            # Apply each document
            results = []
            for doc in docs:
                if not doc:
                    continue
                
                kind = doc.get('kind', '')
                name = doc.get('metadata', {}).get('name', '')
                namespace = doc.get('metadata', {}).get('namespace', 'default')
                
                # Get the appropriate API based on the kind
                api_client = self.active_clients[cluster_name]['api_client']
                
                if kind.lower() == 'namespace':
                    api_instance = self.active_clients[cluster_name]['core_v1_api']
                    obj = api_instance.create_namespace(doc)
                    results.append({
                        'kind': kind,
                        'name': name,
                        'status': 'Created'
                    })
                elif kind.lower() == 'pod':
                    api_instance = self.active_clients[cluster_name]['core_v1_api']
                    obj = api_instance.create_namespaced_pod(namespace, doc)
                    results.append({
                        'kind': kind,
                        'name': name,
                        'namespace': namespace,
                        'status': 'Created'
                    })
                elif kind.lower() == 'service':
                    api_instance = self.active_clients[cluster_name]['core_v1_api']
                    obj = api_instance.create_namespaced_service(namespace, doc)
                    results.append({
                        'kind': kind,
                        'name': name,
                        'namespace': namespace,
                        'status': 'Created'
                    })
                elif kind.lower() == 'deployment':
                    api_instance = self.active_clients[cluster_name]['apps_v1_api']
                    obj = api_instance.create_namespaced_deployment(namespace, doc)
                    results.append({
                        'kind': kind,
                        'name': name,
                        'namespace': namespace,
                        'status': 'Created'
                    })
                elif kind.lower() == 'ingress':
                    api_instance = self.active_clients[cluster_name]['networking_v1_api']
                    obj = api_instance.create_namespaced_ingress(namespace, doc)
                    results.append({
                        'kind': kind,
                        'name': name,
                        'namespace': namespace,
                        'status': 'Created'
                    })
                elif kind.lower() == 'job':
                    api_instance = self.active_clients[cluster_name]['batch_v1_api']
                    obj = api_instance.create_namespaced_job(namespace, doc)
                    results.append({
                        'kind': kind,
                        'name': name,
                        'namespace': namespace,
                        'status': 'Created'
                    })
                else:
                    # Use dynamic client for other kinds
                    utils = client.ApiClient()
                    utils.call_api(
                        f'/apis/{doc.get("apiVersion")}/{namespace}/{doc.get("kind").lower()}s',
                        'POST',
                        body=doc
                    )
                    results.append({
                        'kind': kind,
                        'name': name,
                        'namespace': namespace,
                        'status': 'Created'
                    })
            
            return {
                'cluster': cluster_name,
                'results': results
            }
        except Exception as e:
            raise ValueError(f"Failed to apply YAML to cluster {cluster_name}: {e}")

    def exec_command(self, cluster_name: str, pod_name: str, namespace: str = "default", 
                    container: Optional[str] = None, command: List[str] = None) -> str:
        """Execute a command in a pod.

        Args:
            cluster_name: Name of the cluster to execute the command in.
            pod_name: Name of the pod to execute the command in.
            namespace: Namespace of the pod.
            container: Name of the container to execute the command in.
            command: Command to execute.

        Returns:
            Command output.

        Raises:
            ValueError: If the cluster doesn't exist or is not active.
        """
        if cluster_name not in self.clusters:
            raise ValueError(f"Cluster {cluster_name} doesn't exist")

        if cluster_name not in self.active_clients:
            raise ValueError(f"Cluster {cluster_name} is not active")

        if not command:
            command = ['/bin/sh', '-c', 'ls']

        try:
            core_v1_api = self.active_clients[cluster_name]['core_v1_api']
            
            # Execute command using stream
            exec_command = stream(
                core_v1_api.connect_get_namespaced_pod_exec,
                name=pod_name,
                namespace=namespace,
                container=container,
                command=command,
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False
            )
            
            return exec_command
        except ApiException as e:
            raise ValueError(f"Failed to execute command in pod {pod_name} in cluster {cluster_name}: {e}")

    def get_logs(self, cluster_name: str, pod_name: str, namespace: str = "default", 
                container: Optional[str] = None, tail_lines: int = 100) -> str:
        """Get logs from a pod.

        Args:
            cluster_name: Name of the cluster to get logs from.
            pod_name: Name of the pod to get logs from.
            namespace: Namespace of the pod.
            container: Name of the container to get logs from.
            tail_lines: Number of lines to get from the end of the logs.

        Returns:
            Logs from the pod.

        Raises:
            ValueError: If the cluster doesn't exist or is not active.
        """
        if cluster_name not in self.clusters:
            raise ValueError(f"Cluster {cluster_name} doesn't exist")

        if cluster_name not in self.active_clients:
            raise ValueError(f"Cluster {cluster_name} is not active")

        try:
            api_instance = self.active_clients[cluster_name]['core_v1_api']
            logs = api_instance.read_namespaced_pod_log(
                name=pod_name,
                namespace=namespace,
                container=container,
                tail_lines=tail_lines
            )
            return logs
        except ApiException as e:
            if e.status == 404:
                raise ValueError(f"Pod {pod_name} not found in namespace {namespace}")
            else:
                raise ValueError(f"Failed to get logs from pod {pod_name}: {e}")
        except Exception as e:
            raise ValueError(f"Failed to get logs from pod {pod_name}: {e}")

    def delete_resource(self, cluster_name: str, kind: str, name: str, namespace: str = "default") -> Dict[str, Any]:
        """Delete a resource from a cluster.

        Args:
            cluster_name: Name of the cluster to delete the resource from.
            kind: Kind of resource to delete (e.g., Pod, Service, Deployment).
            name: Name of the resource to delete.
            namespace: Namespace of the resource.

        Returns:
            Status of the deletion.

        Raises:
            ValueError: If the cluster doesn't exist or is not active, or if the resource kind is not supported.
        """
        if cluster_name not in self.clusters:
            raise ValueError(f"Cluster {cluster_name} doesn't exist")

        if cluster_name not in self.active_clients:
            raise ValueError(f"Cluster {cluster_name} is not active")

        try:
            # Normalize kind to lowercase for case-insensitive comparison
            kind_lower = kind.lower()
            
            # Get the appropriate API based on the kind
            if kind_lower == 'namespace':
                api_instance = self.active_clients[cluster_name]['core_v1_api']
                api_instance.delete_namespace(name)
                return {
                    'kind': kind,
                    'name': name,
                    'status': 'Deleted'
                }
            elif kind_lower == 'pod':
                api_instance = self.active_clients[cluster_name]['core_v1_api']
                api_instance.delete_namespaced_pod(name, namespace)
                return {
                    'kind': kind,
                    'name': name,
                    'namespace': namespace,
                    'status': 'Deleted'
                }
            elif kind_lower == 'service':
                api_instance = self.active_clients[cluster_name]['core_v1_api']
                api_instance.delete_namespaced_service(name, namespace)
                return {
                    'kind': kind,
                    'name': name,
                    'namespace': namespace,
                    'status': 'Deleted'
                }
            elif kind_lower == 'deployment':
                api_instance = self.active_clients[cluster_name]['apps_v1_api']
                api_instance.delete_namespaced_deployment(name, namespace)
                return {
                    'kind': kind,
                    'name': name,
                    'namespace': namespace,
                    'status': 'Deleted'
                }
            elif kind_lower == 'ingress':
                api_instance = self.active_clients[cluster_name]['networking_v1_api']
                api_instance.delete_namespaced_ingress(name, namespace)
                return {
                    'kind': kind,
                    'name': name,
                    'namespace': namespace,
                    'status': 'Deleted'
                }
            elif kind_lower == 'job':
                api_instance = self.active_clients[cluster_name]['batch_v1_api']
                api_instance.delete_namespaced_job(name, namespace)
                return {
                    'kind': kind,
                    'name': name,
                    'namespace': namespace,
                    'status': 'Deleted'
                }
            elif kind_lower == 'configmap':
                api_instance = self.active_clients[cluster_name]['core_v1_api']
                api_instance.delete_namespaced_config_map(name, namespace)
                return {
                    'kind': kind,
                    'name': name,
                    'namespace': namespace,
                    'status': 'Deleted'
                }
            elif kind_lower == 'secret':
                api_instance = self.active_clients[cluster_name]['core_v1_api']
                api_instance.delete_namespaced_secret(name, namespace)
                return {
                    'kind': kind,
                    'name': name,
                    'namespace': namespace,
                    'status': 'Deleted'
                }
            elif kind_lower == 'persistentvolumeclaim' or kind_lower == 'pvc':
                api_instance = self.active_clients[cluster_name]['core_v1_api']
                api_instance.delete_namespaced_persistent_volume_claim(name, namespace)
                return {
                    'kind': kind,
                    'name': name,
                    'namespace': namespace,
                    'status': 'Deleted'
                }
            elif kind_lower == 'persistentvolume' or kind_lower == 'pv':
                api_instance = self.active_clients[cluster_name]['core_v1_api']
                api_instance.delete_persistent_volume(name)
                return {
                    'kind': kind,
                    'name': name,
                    'status': 'Deleted'
                }
            elif kind_lower == 'statefulset':
                api_instance = self.active_clients[cluster_name]['apps_v1_api']
                api_instance.delete_namespaced_stateful_set(name, namespace)
                return {
                    'kind': kind,
                    'name': name,
                    'namespace': namespace,
                    'status': 'Deleted'
                }
            elif kind_lower == 'daemonset':
                api_instance = self.active_clients[cluster_name]['apps_v1_api']
                api_instance.delete_namespaced_daemon_set(name, namespace)
                return {
                    'kind': kind,
                    'name': name,
                    'namespace': namespace,
                    'status': 'Deleted'
                }
            else:
                raise ValueError(f"Unsupported resource kind: {kind}")
        except ApiException as e:
            if e.status == 404:
                raise ValueError(f"{kind} {name} not found in namespace {namespace}")
            else:
                raise ValueError(f"Failed to delete {kind} {name}: {e}")
        except Exception as e:
            raise ValueError(f"Failed to delete {kind} {name}: {e}")

    def delete_yaml(self, cluster_name: str, yaml_content: str) -> Dict[str, Any]:
        """Delete resources defined in a YAML manifest from a cluster.

        Args:
            cluster_name: Name of the cluster to delete resources from.
            yaml_content: YAML manifest defining the resources to delete.

        Returns:
            Status of the deletion.

        Raises:
            ValueError: If the cluster doesn't exist or is not active.
        """
        if cluster_name not in self.clusters:
            raise ValueError(f"Cluster {cluster_name} doesn't exist")

        if cluster_name not in self.active_clients:
            raise ValueError(f"Cluster {cluster_name} is not active")

        try:
            # Parse YAML
            docs = yaml.safe_load_all(yaml_content)
            
            # Delete each document
            results = []
            for doc in docs:
                if not doc:
                    continue
                
                kind = doc.get('kind', '')
                name = doc.get('metadata', {}).get('name', '')
                namespace = doc.get('metadata', {}).get('namespace', 'default')
                
                try:
                    # Use the delete_resource method to delete each resource
                    result = self.delete_resource(cluster_name, kind, name, namespace)
                    results.append(result)
                except ValueError as e:
                    # If the resource doesn't exist, add it to the results with a "Not Found" status
                    if "not found" in str(e).lower():
                        results.append({
                            'kind': kind,
                            'name': name,
                            'namespace': namespace,
                            'status': 'Not Found'
                        })
                    else:
                        # For other errors, add it to the results with a "Failed" status
                        results.append({
                            'kind': kind,
                            'name': name,
                            'namespace': namespace,
                            'status': f'Failed: {str(e)}'
                        })
            
            return {
                'cluster': cluster_name,
                'results': results
            }
        except Exception as e:
            raise ValueError(f"Failed to delete resources from YAML in cluster {cluster_name}: {e}")
            
    def delete_resources(self, cluster_name: str, kind: str, namespace: str = "default", 
                        label_selector: Optional[str] = None, field_selector: Optional[str] = None) -> Dict[str, Any]:
        """Delete multiple resources of the same kind from a cluster.

        Args:
            cluster_name: Name of the cluster to delete resources from.
            kind: Kind of resources to delete (e.g., Pod, Service, Deployment).
            namespace: Namespace of the resources.
            label_selector: Label selector to filter resources (e.g., "app=nginx").
            field_selector: Field selector to filter resources (e.g., "metadata.name=my-pod").

        Returns:
            Status of the deletion.

        Raises:
            ValueError: If the cluster doesn't exist or is not active, or if the resource kind is not supported.
        """
        if cluster_name not in self.clusters:
            raise ValueError(f"Cluster {cluster_name} doesn't exist")

        if cluster_name not in self.active_clients:
            raise ValueError(f"Cluster {cluster_name} is not active")

        try:
            # Normalize kind to lowercase for case-insensitive comparison
            kind_lower = kind.lower()
            
            # Get the appropriate API based on the kind
            if kind_lower == 'namespace':
                api_instance = self.active_clients[cluster_name]['core_v1_api']
                
                # List namespaces with the given selectors
                namespaces = api_instance.list_namespace(
                    label_selector=label_selector,
                    field_selector=field_selector
                )
                
                # Delete each namespace
                results = []
                for ns in namespaces.items:
                    try:
                        api_instance.delete_namespace(ns.metadata.name)
                        results.append({
                            'kind': kind,
                            'name': ns.metadata.name,
                            'status': 'Deleted'
                        })
                    except ApiException as e:
                        results.append({
                            'kind': kind,
                            'name': ns.metadata.name,
                            'status': f'Failed: {str(e)}'
                        })
                
                return {
                    'cluster': cluster_name,
                    'kind': kind,
                    'count': len(results),
                    'results': results
                }
            elif kind_lower == 'pod':
                api_instance = self.active_clients[cluster_name]['core_v1_api']
                
                # List pods with the given selectors
                pods = api_instance.list_namespaced_pod(
                    namespace,
                    label_selector=label_selector,
                    field_selector=field_selector
                )
                
                # Delete each pod
                results = []
                for pod in pods.items:
                    try:
                        api_instance.delete_namespaced_pod(pod.metadata.name, namespace)
                        results.append({
                            'kind': kind,
                            'name': pod.metadata.name,
                            'namespace': namespace,
                            'status': 'Deleted'
                        })
                    except ApiException as e:
                        results.append({
                            'kind': kind,
                            'name': pod.metadata.name,
                            'namespace': namespace,
                            'status': f'Failed: {str(e)}'
                        })
                
                return {
                    'cluster': cluster_name,
                    'kind': kind,
                    'namespace': namespace,
                    'count': len(results),
                    'results': results
                }
            elif kind_lower == 'service':
                api_instance = self.active_clients[cluster_name]['core_v1_api']
                
                # List services with the given selectors
                services = api_instance.list_namespaced_service(
                    namespace,
                    label_selector=label_selector,
                    field_selector=field_selector
                )
                
                # Delete each service
                results = []
                for svc in services.items:
                    try:
                        api_instance.delete_namespaced_service(svc.metadata.name, namespace)
                        results.append({
                            'kind': kind,
                            'name': svc.metadata.name,
                            'namespace': namespace,
                            'status': 'Deleted'
                        })
                    except ApiException as e:
                        results.append({
                            'kind': kind,
                            'name': svc.metadata.name,
                            'namespace': namespace,
                            'status': f'Failed: {str(e)}'
                        })
                
                return {
                    'cluster': cluster_name,
                    'kind': kind,
                    'namespace': namespace,
                    'count': len(results),
                    'results': results
                }
            elif kind_lower == 'deployment':
                api_instance = self.active_clients[cluster_name]['apps_v1_api']
                
                # List deployments with the given selectors
                deployments = api_instance.list_namespaced_deployment(
                    namespace,
                    label_selector=label_selector,
                    field_selector=field_selector
                )
                
                # Delete each deployment
                results = []
                for deploy in deployments.items:
                    try:
                        api_instance.delete_namespaced_deployment(deploy.metadata.name, namespace)
                        results.append({
                            'kind': kind,
                            'name': deploy.metadata.name,
                            'namespace': namespace,
                            'status': 'Deleted'
                        })
                    except ApiException as e:
                        results.append({
                            'kind': kind,
                            'name': deploy.metadata.name,
                            'namespace': namespace,
                            'status': f'Failed: {str(e)}'
                        })
                
                return {
                    'cluster': cluster_name,
                    'kind': kind,
                    'namespace': namespace,
                    'count': len(results),
                    'results': results
                }
            elif kind_lower == 'configmap':
                api_instance = self.active_clients[cluster_name]['core_v1_api']
                
                # List configmaps with the given selectors
                configmaps = api_instance.list_namespaced_config_map(
                    namespace,
                    label_selector=label_selector,
                    field_selector=field_selector
                )
                
                # Delete each configmap
                results = []
                for cm in configmaps.items:
                    try:
                        api_instance.delete_namespaced_config_map(cm.metadata.name, namespace)
                        results.append({
                            'kind': kind,
                            'name': cm.metadata.name,
                            'namespace': namespace,
                            'status': 'Deleted'
                        })
                    except ApiException as e:
                        results.append({
                            'kind': kind,
                            'name': cm.metadata.name,
                            'namespace': namespace,
                            'status': f'Failed: {str(e)}'
                        })
                
                return {
                    'cluster': cluster_name,
                    'kind': kind,
                    'namespace': namespace,
                    'count': len(results),
                    'results': results
                }
            else:
                raise ValueError(f"Bulk deletion not supported for resource kind: {kind}. Use delete_resource for individual resources.")
        except ApiException as e:
            raise ValueError(f"Failed to delete {kind} resources: {e}")
        except Exception as e:
            raise ValueError(f"Failed to delete {kind} resources: {e}") 