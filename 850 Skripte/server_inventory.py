#!/usr/bin/env python3
"""
Server Inventory Generator

Dieses Skript sammelt automatisch Informationen über Server in Hetzner Cloud, AWS und Azure
und erstellt ein strukturiertes Dokument (Markdown und HTML).

Benötigte Umgebungsvariablen:
- HCLOUD_TOKEN: Hetzner Cloud API Token
- AWS_ACCESS_KEY_ID: AWS Access Key
- AWS_SECRET_ACCESS_KEY: AWS Secret Key
- AWS_SESSION_TOKEN: AWS Session Token (optional)
- AZURE_TENANT_ID: Azure Tenant ID (falls Azure verwendet wird)
- AZURE_CLIENT_ID: Azure Client ID (falls Azure verwendet wird)
- AZURE_CLIENT_SECRET: Azure Client Secret (falls Azure verwendet wird)
"""

import os
import sys
import json
import datetime
import argparse
from typing import Dict, List, Any, Optional

# Abhängigkeiten prüfen und installieren wenn nötig
try:
    import boto3
    import hcloud
    import requests
    import markdownify
    from hcloud.client import Client as HetznerClient
    from azure.identity import ClientSecretCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
except ImportError:
    print("Installiere benötigte Abhängigkeiten...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", 
                          "boto3", "hcloud", "requests", "markdownify", 
                          "azure-identity", "azure-mgmt-compute", "azure-mgmt-network"])
    import boto3
    import hcloud
    import requests
    import markdownify
    from hcloud.client import Client as HetznerClient
    from azure.identity import ClientSecretCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient

class ServerInventory:
    def __init__(self):
        self.servers = []
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
    def collect_all(self):
        """Sammelt Informationen von allen konfigurierten Cloud-Diensten"""
        try:
            self.collect_hetzner()
        except Exception as e:
            print(f"Fehler beim Sammeln von Hetzner-Informationen: {e}")
        
        try:
            self.collect_aws()
        except Exception as e:
            print(f"Fehler beim Sammeln von AWS-Informationen: {e}")
        
        try:
            self.collect_azure()
        except Exception as e:
            print(f"Fehler beim Sammeln von Azure-Informationen: {e}")
    
    def collect_hetzner(self):
        """Sammelt Server-Informationen von Hetzner Cloud"""
        token = os.environ.get('HCLOUD_TOKEN')
        if not token:
            print("HCLOUD_TOKEN nicht gefunden. Überspringe Hetzner Cloud.")
            return
        
        client = HetznerClient(token=token)
        servers = client.servers.get_all()
        
        for server in servers:
            # IP-Adressen sammeln
            ipv4 = server.public_net.ipv4.ip if server.public_net.ipv4 else None
            ipv6 = server.public_net.ipv6.ip if server.public_net.ipv6 else None
            
            # FQDN ermitteln (falls möglich)
            fqdn = None
            if ipv4:
                try:
                    response = requests.get(f"https://dns.hetzner.com/api/v1/records", 
                                           headers={"Auth-API-Token": os.environ.get('HETZNER_DNS_API_TOKEN')})
                    if response.status_code == 200:
                        records = response.json().get('records', [])
                        for record in records:
                            if record.get('value') == ipv4 and record.get('type') == 'A':
                                fqdn = f"{record.get('name')}.{record.get('zone_name')}"
                                break
                except Exception:
                    pass
            
            self.servers.append({
                'name': server.name,
                'provider': 'Hetzner Cloud',
                'os': server.image.name if server.image else 'Unbekannt',
                'fqdn': fqdn,
                'ipv4': ipv4,
                'ipv6': ipv6,
                'status': server.status,
                'region': server.datacenter.name if server.datacenter else 'Unbekannt',
                'type': server.server_type.name if server.server_type else 'Unbekannt'
            })
    
    def collect_aws(self):
        """Sammelt Server-Informationen von AWS EC2"""
        if not os.environ.get('AWS_ACCESS_KEY_ID') or not os.environ.get('AWS_SECRET_ACCESS_KEY'):
            print("AWS Credentials nicht gefunden. Überspringe AWS.")
            return
        
        # Alle Regionen abrufen
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        for region in regions:
            try:
                ec2 = boto3.resource('ec2', region_name=region)
                instances = ec2.instances.all()
                
                for instance in instances:
                    # Name Tag finden
                    name = 'Unbenannt'
                    for tag in instance.tags or []:
                        if tag['Key'] == 'Name':
                            name = tag['Value']
                            break
                    
                    # Betriebssystem ermitteln
                    os_info = 'Unbekannt'
                    if instance.platform:
                        os_info = instance.platform
                    elif instance.image_id:
                        try:
                            image = ec2.Image(instance.image_id)
                            os_info = image.description or image.name
                        except Exception:
                            pass
                    
                    self.servers.append({
                        'name': name,
                        'provider': 'AWS',
                        'os': os_info,
                        'fqdn': instance.public_dns_name,
                        'ipv4': instance.public_ip_address,
                        'ipv6': None,  # AWS liefert IPv6 anders, kann bei Bedarf ergänzt werden
                        'status': instance.state['Name'],
                        'region': region,
                        'type': instance.instance_type
                    })
            except Exception as e:
                print(f"Fehler beim Abrufen von AWS-Instanzen in {region}: {e}")
    
    def collect_azure(self):
        """Sammelt Server-Informationen von Azure"""
        tenant_id = os.environ.get('AZURE_TENANT_ID')
        client_id = os.environ.get('AZURE_CLIENT_ID')
        client_secret = os.environ.get('AZURE_CLIENT_SECRET')
        
        if not all([tenant_id, client_id, client_secret]):
            print("Azure Credentials nicht vollständig. Überspringe Azure.")
            return
        
        # Azure Credentials
        credentials = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )
        
        # Azure Subscriptions abrufen
        from azure.mgmt.subscription import SubscriptionClient
        subscription_client = SubscriptionClient(credentials)
        subscriptions = list(subscription_client.subscriptions.list())
        
        for subscription in subscriptions:
            subscription_id = subscription.subscription_id
            
            # Compute-Client für VMs
            compute_client = ComputeManagementClient(credentials, subscription_id)
            network_client = NetworkManagementClient(credentials, subscription_id)
            
            # VMs abrufen
            for vm in compute_client.virtual_machines.list_all():
                resource_group = vm.id.split('/')[4]
                
                # Betriebssystem-Info
                os_info = 'Unbekannt'
                if vm.storage_profile.os_disk.os_type:
                    os_info = vm.storage_profile.os_disk.os_type
                
                # IP-Adressen abrufen
                ipv4 = None
                fqdn = None
                network_interfaces = []
                
                for interface_ref in vm.network_profile.network_interfaces:
                    interface_id = interface_ref.id
                    interface_name = interface_id.split('/')[-1]
                    interface = network_client.network_interfaces.get(resource_group, interface_name)
                    network_interfaces.append(interface)
                
                # Public IP suchen
                for interface in network_interfaces:
                    for ip_config in interface.ip_configurations:
                        if ip_config.public_ip_address:
                            public_ip_id = ip_config.public_ip_address.id
                            public_ip_name = public_ip_id.split('/')[-1]
                            public_ip = network_client.public_ip_addresses.get(resource_group, public_ip_name)
                            ipv4 = public_ip.ip_address
                            fqdn = public_ip.dns_settings.fqdn if public_ip.dns_settings else None
                
                self.servers.append({
                    'name': vm.name,
                    'provider': 'Azure',
                    'os': os_info,
                    'fqdn': fqdn,
                    'ipv4': ipv4,
                    'ipv6': None,  # Azure IPv6 kann bei Bedarf ergänzt werden
                    'status': vm.provisioning_state,
                    'region': vm.location,
                    'type': vm.hardware_profile.vm_size
                })
    
    def generate_markdown(self) -> str:
        """Erstellt eine Markdown-Darstellung der Server-Informationen"""
        markdown = f"# Server Inventar\n\n"
        markdown += f"Erstellt am: {self.timestamp}\n\n"
        
        # Nach Anbieter gruppieren
        providers = {}
        for server in self.servers:
            provider = server['provider']
            if provider not in providers:
                providers[provider] = []
            providers[provider].append(server)
        
        # Für jeden Anbieter eine Tabelle erstellen
        for provider, server_list in providers.items():
            markdown += f"## {provider}\n\n"
            markdown += "| Name | Betriebssystem | FQDN | IP-Adresse | Status | Region | Typ |\n"
            markdown += "|------|---------------|------|------------|--------|--------|------|\n"
            
            for server in server_list:
                ip = server['ipv4'] or server['ipv6'] or 'N/A'
                fqdn = server['fqdn'] or 'N/A'
                markdown += f"| {server['name']} | {server['os']} | {fqdn} | {ip} | {server['status']} | {server['region']} | {server['type']} |\n"
            
            markdown += "\n"
        
        return markdown
    
    def generate_html(self) -> str:
        """Erstellt eine HTML-Darstellung der Server-Informationen"""
        markdown = self.generate_markdown()
        html = markdownify.markdownify(markdown, heading_style="ATX")
        
        # Füge ein einfaches CSS hinzu
        style = """
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
            th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }
            th { background-color: #f2f2f2; }
            tr:hover { background-color: #f5f5f5; }
            h1, h2 { color: #333; }
        </style>
        """
        
        html = f"""<!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Server Inventar</title>
            {style}
        </head>
        <body>
            {html}
        </body>
        </html>
        """
        
        return html
    
    def save_output(self, output_dir="./"):
        """Speichert die Ausgabe als Markdown und HTML"""
        date_str = datetime.datetime.now().strftime("%Y%m%d")
        
        # Markdown speichern
        md_filename = os.path.join(output_dir, f"server_inventory_{date_str}.md")
        with open(md_filename, 'w') as f:
            f.write(self.generate_markdown())
        print(f"Markdown-Datei gespeichert: {md_filename}")
        
        # HTML speichern
        html_filename = os.path.join(output_dir, f"server_inventory_{date_str}.html")
        with open(html_filename, 'w') as f:
            f.write(self.generate_html())
        print(f"HTML-Datei gespeichert: {html_filename}")

def main():
    parser = argparse.ArgumentParser(description='Server Inventory Generator')
    parser.add_argument('-o', '--output-dir', default='./output', help='Ausgabeverzeichnis für Dateien')
    args = parser.parse_args()
    
    # Ausgabeverzeichnis erstellen falls nicht vorhanden
    os.makedirs(args.output_dir, exist_ok=True)
    
    inventory = ServerInventory()
    print("Sammle Server-Informationen...")
    inventory.collect_all()
    print(f"Gefundene Server: {len(inventory.servers)}")
    inventory.save_output(args.output_dir)

if __name__ == "__main__":
    main() 