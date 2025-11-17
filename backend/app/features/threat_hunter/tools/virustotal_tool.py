from crewai.tools import BaseTool
from typing import Type, Dict, Any, Optional, List
from pydantic import BaseModel, Field, field_validator
import requests
import re
import base64
import json
import os
from datetime import datetime
from app.core.settings.api_keys.cache import APIKeyCache


class VirusTotalInput(BaseModel):
    """Input schema for VirusTotal IOC Analysis Tool."""
    ioc: str = Field(..., description="The IOC to analyze - IP address, domain, hash, URL, or filename")
    ioc_type: str = Field(..., description="Type of IOC: 'ip', 'domain', 'hash', 'url', or 'filename'")

    @field_validator('ioc', mode='before')
    @classmethod
    def parse_ioc(cls, v):
        """Handle LLM wrapping args as dict instead of string"""
        if isinstance(v, dict):
            return v.get('description', v.get('value', str(v)))
        return v

    @field_validator('ioc_type', mode='before')
    @classmethod
    def parse_ioc_type(cls, v):
        """Handle LLM wrapping args as dict instead of string"""
        if isinstance(v, dict):
            return v.get('description', v.get('value', str(v)))
        return v


class VirusTotalTool(BaseTool):
    name: str = "VirusTotal IOC Analyzer"
    description: str = (
        "Efficient VirusTotal analysis tool for threat hunting. Makes only essential API calls to extract "
        "critical behavioral indicators, C2 infrastructure, persistence mechanisms, and file relationships. "
        "Optimized to provide maximum threat hunting value with minimal API overhead."
    )
    args_schema: Type[BaseModel] = VirusTotalInput
    api_key: str = Field(default="", exclude=True)

    def __init__(self, api_key: str = None):
        super().__init__()
        # Try API key cache first, then environment variable
        if api_key:
            self.api_key = api_key
        else:
            cache = APIKeyCache.get_instance()
            vt_key_data = cache.get_key('virustotal')
            self.api_key = vt_key_data.get('key') if vt_key_data and vt_key_data.get('key') else os.getenv('VIRUSTOTAL_API_KEY')

        if not self.api_key:
            raise ValueError("VirusTotal API key not found. Please configure in Settings or set VIRUSTOTAL_API_KEY environment variable.")

    def _run(self, ioc: str, ioc_type: str) -> str:
        """Execute focused VirusTotal analysis with essential threat hunting data only."""
        try:
            # Fix: LLM sometimes wraps args as {"description": "value", "type": "str"} instead of just "value"
            # This happens when GPT-4 misinterprets Pydantic Field metadata as actual data structure
            if isinstance(ioc, dict):
                ioc = ioc.get('description', ioc.get('value', str(ioc)))
            if isinstance(ioc_type, dict):
                ioc_type = ioc_type.get('description', ioc_type.get('value', str(ioc_type)))
            print(f"🔍 VT Analysis: {ioc} ({ioc_type})")
            
            # Get primary data + essential relationships in minimal API calls
            if ioc_type == 'hash':
                return self._analyze_hash(ioc)
            elif ioc_type == 'ip':
                return self._analyze_ip(ioc)
            elif ioc_type == 'domain':
                return self._analyze_domain(ioc)
            elif ioc_type == 'url':
                return self._analyze_url(ioc)
            elif ioc_type == 'filename':
                return self._analyze_filename(ioc)
            else:
                return f"Unsupported IOC type: {ioc_type}"
                
        except Exception as error:
            return f"VirusTotal analysis failed for {ioc}: {str(error)}"
    
    def _safe_join(self, items: list, separator: str = ', ') -> str:
        """Safely join list items, converting non-strings to strings."""
        if not items:
            return 'None'
        safe_items = [str(item) for item in items if item is not None]
        return separator.join(safe_items) if safe_items else 'None'

    def _analyze_hash(self, hash_value: str) -> str:
        """Analyze hash with essential behavioral data for threat hunting."""
        print(f"🔍 Analyzing hash: {hash_value}")
        
        # Primary file data
        primary = self._get_file_data(hash_value)
        if not primary or not primary.get('data'):
            return f"Hash {hash_value} not found in VirusTotal"
        
        print(f"✅ Primary data retrieved")
        attrs = primary['data']['attributes']
        stats = attrs.get('last_analysis_stats', {})
        
        # Essential relationships for threat hunting
        print(f"🔗 Getting C2 infrastructure...")
        c2_infrastructure = self._get_c2_infrastructure(hash_value)
        
        print(f"📁 Getting file relationships...")
        file_relationships = self._get_file_relationships(hash_value)
        
        print(f"🔬 Getting behavioral data...")
        behavioral_data = self._get_behavior_summary(hash_value)
        
        print(f"📝 Formatting analysis...")
        return self._format_hash_analysis(attrs, stats, c2_infrastructure, file_relationships, behavioral_data, hash_value)

    def _analyze_ip(self, ip: str) -> str:
        """Analyze IP with essential infrastructure data."""
        print(f"🔍 Analyzing IP: {ip}")
        
        # Primary IP data
        primary = self._make_request(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}')
        if not primary or not primary.get('data'):
            return f"IP {ip} not found in VirusTotal"
        
        attrs = primary['data']['attributes']
        stats = attrs.get('last_analysis_stats', {})
        
        print(f"🔗 Getting IP relationships...")
        # Essential relationships (4 critical API calls for comprehensive analysis)
        passive_dns = self._make_request(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions?limit=25')
        communicating_files = self._make_request(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}/communicating_files?limit=15')
        downloaded_files = self._make_request(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}/downloaded_files?limit=15')
        hosted_urls = self._make_request(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}/urls?limit=15')
        
        return self._format_ip_analysis(attrs, stats, passive_dns, communicating_files, downloaded_files, hosted_urls, ip)

    def _analyze_domain(self, domain: str) -> str:
        """Analyze domain with essential infrastructure data."""
        print(f"🔍 Analyzing domain: {domain}")
        
        # Primary domain data
        primary = self._make_request(f'https://www.virustotal.com/api/v3/domains/{domain}')
        if not primary or not primary.get('data'):
            return f"Domain {domain} not found in VirusTotal"
        
        attrs = primary['data']['attributes']
        stats = attrs.get('last_analysis_stats', {})
        
        print(f"🔗 Getting domain relationships...")
        # Essential relationships (5 critical API calls for comprehensive analysis)
        resolutions = self._make_request(f'https://www.virustotal.com/api/v3/domains/{domain}/resolutions?limit=25')
        subdomains = self._make_request(f'https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=20')
        communicating_files = self._make_request(f'https://www.virustotal.com/api/v3/domains/{domain}/communicating_files?limit=15')
        referring_files = self._make_request(f'https://www.virustotal.com/api/v3/domains/{domain}/referrer_files?limit=15')
        urls = self._make_request(f'https://www.virustotal.com/api/v3/domains/{domain}/urls?limit=15')
        
        return self._format_domain_analysis(attrs, stats, resolutions, subdomains, communicating_files, referring_files, urls, domain)

    def _analyze_url(self, url: str) -> str:
        """Analyze URL with essential data."""
        print(f"🔍 Analyzing URL: {url}")
        
        url_id = base64.urlsafe_b64encode(url.encode()).decode()
        primary = self._make_request(f'https://www.virustotal.com/api/v3/urls/{url_id}')
        
        if not primary or not primary.get('data'):
            return f"URL {url} not found in VirusTotal"
        
        attrs = primary['data']['attributes']
        stats = attrs.get('last_analysis_stats', {})
        
        return self._format_url_analysis(attrs, stats, url)
    


    def _analyze_filename(self, filename: str) -> str:
        """Analyze filename with search results."""
        print(f"🔍 Analyzing filename: {filename}")
        
        search_results = self._make_request(f'https://www.virustotal.com/api/v3/search?query=name:"{filename}"&limit=5')
        
        if not search_results or not search_results.get('data'):
            return f"No files found with filename: {filename}"
        
        return self._format_filename_analysis(search_results, filename)

    def _get_file_data(self, hash_value: str) -> Dict[str, Any]:
        """Get primary file data."""
        return self._make_request(f'https://www.virustotal.com/api/v3/files/{hash_value}')

    def _get_c2_infrastructure(self, hash_value: str) -> Dict[str, Any]:
        """Get C2 infrastructure data."""
        base_url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
        
        return {
            'contacted_ips': self._make_request(f'{base_url}/contacted_ips?limit=20'),
            'contacted_domains': self._make_request(f'{base_url}/contacted_domains?limit=20'),
            'contacted_urls': self._make_request(f'{base_url}/contacted_urls?limit=15')
        }

    def _get_file_relationships(self, hash_value: str) -> Dict[str, Any]:
        """Get comprehensive file relationships."""
        base_url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
        
        return {
            'execution_parents': self._make_request(f'{base_url}/execution_parents?limit=10'),
            'dropped_files': self._make_request(f'{base_url}/dropped_files?limit=10'),
            'similar_files': self._make_request(f'{base_url}/similar_files?limit=5'),
            'itw_urls': self._make_request(f'{base_url}/itw_urls?limit=10')
        }

    def _get_behavior_summary(self, hash_value: str) -> Dict[str, Any]:
        """Get comprehensive behavioral data."""
        base_url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
        
        return {
            'behavior_summary': self._make_request(f'{base_url}/behaviour_summary'),
            'detailed_behaviors': self._make_request(f'{base_url}/behaviours?limit=2')
        }

    def _make_request(self, url: str) -> Dict[str, Any]:
        """Make efficient VT API request."""
        try:
            headers = {'x-apikey': self.api_key}
            response = requests.get(url, headers=headers, timeout=15)
            return response.json()
        except:
            return {}

    def _format_behavioral_analysis(self, behavior: Dict[str, Any]) -> str:
        """Format comprehensive behavioral analysis from sandbox data."""
        response = "\nBEHAVIORAL INDICATORS:\n"
        
        # Behavior summary data
        behavior_summary = behavior.get('behavior_summary', {}).get('data', {})
        if behavior_summary:
            techniques = behavior_summary.get('mitre_attack_techniques', [])
            if techniques:
                response += f"- MITRE ATT&CK Techniques: {self._safe_join(techniques[:8])}\n"

            else:
                response += "- MITRE ATT&CK Techniques: None found\n"
            
            tags = behavior_summary.get('tags', [])
            
            if tags:
                response += f"- Behavior Tags: {self._safe_join(tags[:10])}\n"

            else:
                response += "- Behavior Tags: None found\n"
            
            verdicts = behavior_summary.get('verdicts', {})
            if verdicts:
                if isinstance(verdicts, dict):
                    response += f"- Sandbox Verdicts: {dict(list(verdicts.items())[:5])}\n"
                elif isinstance(verdicts, list):
                    response += f"- Sandbox Verdicts: {self._safe_join(verdicts[:5])}\n"
                else:
                    response += f"- Sandbox Verdicts: {str(verdicts)}\n"
            else:
                response += "- Sandbox Verdicts: None found\n"
        
        # Detailed behavioral analysis
        detailed_behaviors = behavior.get('detailed_behaviors', {}).get('data', [])
        if detailed_behaviors:
            response += "\nDETAILED SANDBOX ANALYSIS:\n"
            
            for i, behavior_data in enumerate(detailed_behaviors[:1], 1):  # Use first sandbox
                attrs = behavior_data.get('attributes', {})
                sandbox_name = attrs.get('sandbox_name', 'Unknown Sandbox')
                analysis_date = attrs.get('analysis_date')
                if analysis_date:
                    analysis_date = datetime.fromtimestamp(analysis_date).strftime('%Y-%m-%d %H:%M')
                
                response += f"--- Sandbox {i}: {sandbox_name} ({analysis_date or 'N/A'}) ---\n"
                
                summary = attrs.get('summary', {})
                if summary:
                    # Files written/dropped (persistence indicators)
                    files_written = summary.get('files_written', [])
                    if files_written:
                        response += f"FILES WRITTEN ({len(files_written)}):\n"
                        for file_path in files_written[:8]:
                            response += f"- {file_path}\n"
                    
                    # Files dropped (payload deployment)
                    files_dropped = summary.get('files_dropped', [])
                    if files_dropped:
                        response += f"FILES DROPPED ({len(files_dropped)}):\n"
                        for file_path in files_dropped[:8]:
                            response += f"- {file_path}\n"
                    
                    # Registry modifications (persistence mechanisms)
                    registry_set = summary.get('registry_keys_set', [])
                    if registry_set:
                        response += f"REGISTRY KEYS SET ({len(registry_set)}):\n"
                        for reg_key in registry_set[:8]:
                            response += f"- {reg_key}\n"
                    
                    # Process creation (execution chain)
                    processes = summary.get('processes_created', [])
                    if processes:
                        response += f"PROCESSES CREATED ({len(processes)}):\n"
                        for proc in processes[:8]:
                            if isinstance(proc, dict):
                                proc_name = proc.get('process_name', str(proc))
                                proc_id = proc.get('process_id', '')
                                response += f"- {proc_name}"
                                if proc_id:
                                    response += f" (PID: {proc_id})"
                                response += "\n"
                            else:
                                response += f"- {str(proc)}\n"
                    
                    # Network communications (C2 activity)
                    dns_lookups = summary.get('dns_lookups', [])
                    if dns_lookups:
                        response += f"DNS LOOKUPS ({len(dns_lookups)}):\n"
                        for dns in dns_lookups[:8]:
                            if isinstance(dns, dict):
                                hostname = dns.get('hostname', str(dns))
                                resolved_ips = dns.get('resolved_ips', [])
                                response += f"- {hostname}"
                                if resolved_ips:
                                    response += f" -> {resolved_ips[0]}"
                                response += "\n"
                            else:
                                response += f"- {str(dns)}\n"
                    
                    # HTTP communications (web-based C2)
                    http_conversations = summary.get('http_conversations', [])
                    if http_conversations:
                        response += f"HTTP REQUESTS ({len(http_conversations)}):\n"
                        for http in http_conversations[:8]:
                            if isinstance(http, dict):
                                method = http.get('request_method', 'GET')
                                url = http.get('url', str(http))
                                response += f"- {method} {url}\n"
                            else:
                                response += f"- {str(http)}\n"
                    
                    # Mutexes (anti-analysis/synchronization)
                    mutexes = summary.get('mutexes_created', [])
                    if mutexes:
                        response += f"MUTEXES CREATED ({len(mutexes)}):\n"
                        for mutex in mutexes[:8]:
                            response += f"- {mutex}\n"
                    
                    # Services (persistence)
                    services = summary.get('services_created', [])
                    if services:
                        response += f"SERVICES CREATED ({len(services)}):\n"
                        for service in services[:5]:
                            response += f"- {service}\n"
        
        if not behavior_summary and not detailed_behaviors:
            response += "No sandbox data available\n"
        
        return response
    
    def _get_safe_filename(self, attrs: Dict) -> str:
        """Safely extract filename from attributes."""
        # Try meaningful_name first
        meaningful_name = attrs.get('meaningful_name')
        if meaningful_name and isinstance(meaningful_name, str):
            return meaningful_name
        
        # Try names array
        names = attrs.get('names', [])
        if names and isinstance(names, list):
            for name in names:
                if isinstance(name, str):
                    return name
        
        return 'Unknown'

    def _format_hash_analysis(self, attrs: Dict, stats: Dict, c2_data: Dict, file_rels: Dict, behavior: Dict, hash_value: str) -> str:
        """Format comprehensive hash analysis with all discovered relations."""
        file_name = self._get_safe_filename(attrs)
        
        response = f"""=== VIRUSTOTAL COMPREHENSIVE ANALYSIS ===
IOC: {hash_value} (HASH)
Analysis Date: {datetime.now().isoformat()}

DETECTION SUMMARY:
- Malicious: {stats.get('malicious', 0)}
- Suspicious: {stats.get('suspicious', 0)}
- Clean: {stats.get('harmless', 0)}
- Undetected: {stats.get('undetected', 0)}
- Total Engines: {sum(stats.values()) if stats else 0}

FILE DETAILS:
- Filename: {file_name}
- File Type: {attrs.get('type_description', 'N/A')}
- Size: {attrs.get('size', 'N/A')} bytes
- MD5: {attrs.get('md5', 'N/A')}
- SHA1: {attrs.get('sha1', 'N/A')}
- SHA256: {attrs.get('sha256', 'N/A')}"""
        
        # Add timestamps
        first_seen = attrs.get('first_submission_date')
        if first_seen:
            response += f"\n- First Seen: {datetime.fromtimestamp(first_seen).strftime('%Y-%m-%d %H:%M:%S')}"
        
        last_analysis = attrs.get('last_analysis_date')
        if last_analysis:
            response += f"\n- Last Analysis: {datetime.fromtimestamp(last_analysis).strftime('%Y-%m-%d %H:%M:%S')}"
        
        # Digital signature
        signature_info = attrs.get('signature_info', {})
        if signature_info:
            response += f"\n- Digital Signature: {signature_info.get('product', 'N/A')}"
            response += f"\n- Signer: {signature_info.get('copyright', 'N/A')}"
        
        response += "\n\nC2 INFRASTRUCTURE:"
        
        # C2 IPs discovered
        contacted_ips = c2_data.get('contacted_ips', {}).get('data', [])
        if contacted_ips:
            response += f"\n- Contacted IPs ({len(contacted_ips)} found):\n"
            for ip in contacted_ips[:15]:
                response += f"  * {ip.get('id', 'N/A')}\n"
        else:
            response += "\n- Contacted IPs: None found\n"
        
        # C2 Domains discovered
        contacted_domains = c2_data.get('contacted_domains', {}).get('data', [])
        if contacted_domains:
            response += f"- Contacted Domains ({len(contacted_domains)} found):\n"
            for domain in contacted_domains[:15]:
                response += f"  * {domain.get('id', 'N/A')}\n"
        else:
            response += "- Contacted Domains: None found\n"
        
        response += "\n\nCONTACTED URLS (C2 Communication):"
        contacted_urls = c2_data.get('contacted_urls', {}).get('data', [])
        if contacted_urls:
            response += f"\n"
            for url in contacted_urls[:10]:
                response += f"- {url.get('id', 'N/A')}\n"
        else:
            response += " None found\n"
        
        # File relationships discovered
        response += "\nFILE RELATIONSHIPS:"
        
        parents = file_rels.get('execution_parents', {}).get('data', [])
        if parents:
            response += f"\n- Parent Files ({len(parents)} found):\n"
            for parent in parents:
                p_attrs = parent.get('attributes', {})
                p_name = p_attrs.get('meaningful_name', 'Unknown')
                p_stats = p_attrs.get('last_analysis_stats', {})
                p_malicious = p_stats.get('malicious', 0)
                p_total = sum(p_stats.values()) if p_stats else 0
                response += f"  * {parent.get('id', 'N/A')} ({p_name}) - {p_malicious}/{p_total} detections\n"
        else:
            response += "\n- Parent Files: None found\n"
        
        dropped = file_rels.get('dropped_files', {}).get('data', [])
        if dropped:
            response += f"- Dropped Files ({len(dropped)} found):\n"
            for drop in dropped:
                d_attrs = drop.get('attributes', {})
                d_name = d_attrs.get('meaningful_name', 'Unknown')
                d_stats = d_attrs.get('last_analysis_stats', {})
                d_malicious = d_stats.get('malicious', 0)
                d_total = sum(d_stats.values()) if d_stats else 0
                response += f"  * {drop.get('id', 'N/A')} ({d_name}) - {d_malicious}/{d_total} detections\n"
        else:
            response += "- Dropped Files: None found\n"
        
        # Similar files
        similar = file_rels.get('similar_files', {}).get('data', [])
        if similar:
            response += f"- Similar Files ({len(similar)} found):\n"
            for sim in similar:
                s_attrs = sim.get('attributes', {})
                s_name = s_attrs.get('meaningful_name', 'Unknown')
                s_stats = s_attrs.get('last_analysis_stats', {})
                s_malicious = s_stats.get('malicious', 0)
                s_total = sum(s_stats.values()) if s_stats else 0
                response += f"  * {sim.get('id', 'N/A')} ({s_name}) - {s_malicious}/{s_total} detections\n"
        else:
            response += "- Similar Files: None found\n"
        
        # ITW URLs
        itw_urls = file_rels.get('itw_urls', {}).get('data', [])
        if itw_urls:
            response += f"- In-the-Wild URLs ({len(itw_urls)} found):\n"
            for url in itw_urls[:5]:
                response += f"  * {url.get('id', 'N/A')}\n"
        else:
            response += "- In-the-Wild URLs: None found\n"
        
        # Behavioral indicators discovered
        response += self._format_behavioral_analysis(behavior)
        
        # Add reputation context
        response += f"\nREPUTATION CONTEXT:\n"
        response += f"- VT Community Score: {attrs.get('reputation', 'N/A')}\n"
        response += f"- Threat Level: {self._calculate_threat_level(stats)}"
        

        
        response += f"\nSource: https://www.virustotal.com/gui/file/{hash_value}"
        return response

    def _format_ip_analysis(self, attrs: Dict, stats: Dict, passive_dns: Dict, comm_files: Dict, downloaded_files: Dict, hosted_urls: Dict, ip: str) -> str:
        """Format comprehensive IP analysis with all discovered relations."""
        response = f"""=== VIRUSTOTAL COMPREHENSIVE ANALYSIS ===
IOC: {ip} (IP)
Analysis Date: {datetime.now().isoformat()}

DETECTION SUMMARY:
- Malicious: {stats.get('malicious', 0)}
- Suspicious: {stats.get('suspicious', 0)}
- Clean: {stats.get('harmless', 0)}
- Undetected: {stats.get('undetected', 0)}
- Total Engines: {sum(stats.values()) if stats else 0}

INFRASTRUCTURE DETAILS:
- AS Owner: {attrs.get('as_owner', 'N/A')}
- ASN: {attrs.get('asn', 'N/A')}
- Country: {attrs.get('country', 'N/A')}
- Network: {attrs.get('network', 'N/A')}

PASSIVE DNS (Domains pointing to this IP):"""
        
        # Domains resolving to this IP
        dns_data = passive_dns.get('data', [])
        if dns_data:
            response += f"\n"
            for dns in dns_data[:15]:
                dns_attrs = dns.get('attributes', {})
                domain = dns_attrs.get('host_name', 'N/A')
                last_seen = dns_attrs.get('date')
                if last_seen:
                    last_seen = datetime.fromtimestamp(last_seen).strftime('%Y-%m-%d')
                response += f"- {domain} (Last: {last_seen or 'N/A'})\n"
        else:
            response += " None found\n"
        
        response += "\nCOMMUNICATING FILES (files that contact this IP):"
        # Malware communicating with this IP
        files_data = comm_files.get('data', [])
        if files_data:
            response += f"\n"
            for file_data in files_data[:10]:
                f_attrs = file_data.get('attributes', {})
                f_name = f_attrs.get('meaningful_name', 'Unknown')
                f_stats = f_attrs.get('last_analysis_stats', {})
                f_malicious = f_stats.get('malicious', 0)
                f_total = sum(f_stats.values()) if f_stats else 0
                response += f"- {file_data.get('id', 'N/A')} ({f_name}) - Detections: {f_malicious}/{f_total}\n"
        else:
            response += " None found\n"
        
        response += "\nDOWNLOADED FILES (files downloaded from this IP):"
        # Files downloaded from this IP
        downloaded_data = downloaded_files.get('data', [])
        if downloaded_data:
            response += f"\n"
            for file_data in downloaded_data[:10]:
                f_attrs = file_data.get('attributes', {})
                f_name = f_attrs.get('meaningful_name', 'Unknown')
                f_stats = f_attrs.get('last_analysis_stats', {})
                f_malicious = f_stats.get('malicious', 0)
                f_total = sum(f_stats.values()) if f_stats else 0
                response += f"- {file_data.get('id', 'N/A')} ({f_name}) - Detections: {f_malicious}/{f_total}\n"
        else:
            response += " None found\n"
        
        response += "\nHOSTED URLS (URLs hosted on this IP):"
        # URLs hosted on this IP
        hosted_data = hosted_urls.get('data', [])
        if hosted_data:
            response += f"\n"
            for url in hosted_data[:10]:
                response += f"- {url.get('id', 'N/A')}\n"
        else:
            response += " None found\n"
        
        # Add reputation context
        response += f"\nREPUTATION CONTEXT:\n"
        response += f"- VT Community Score: {attrs.get('reputation', 'N/A')}"
        

        
        response += f"\nSource: https://www.virustotal.com/gui/ip-address/{ip}"
        return response

    def _format_domain_analysis(self, attrs: Dict, stats: Dict, resolutions: Dict, subdomains: Dict, comm_files: Dict, referring_files: Dict, urls: Dict, domain: str) -> str:
        """Format comprehensive domain analysis with all discovered relations."""
        response = f"""=== VIRUSTOTAL COMPREHENSIVE ANALYSIS ===
IOC: {domain} (DOMAIN)
Analysis Date: {datetime.now().isoformat()}

DETECTION SUMMARY:
- Malicious: {stats.get('malicious', 0)}
- Suspicious: {stats.get('suspicious', 0)}
- Clean: {stats.get('harmless', 0)}
- Undetected: {stats.get('undetected', 0)}
- Total Engines: {sum(stats.values()) if stats else 0}

DOMAIN DETAILS:
- Registrar: {attrs.get('registrar', 'N/A')}"""
        
        creation_date = attrs.get('creation_date')
        if creation_date:
            response += f"\n- Creation Date: {datetime.fromtimestamp(creation_date).strftime('%Y-%m-%d')}"
        
        categories = attrs.get('categories', {})
        if categories:
            response += f"\n- Categories: {self._safe_join(categories.values)}\n"

            
        
        response += "\n\nDNS RESOLUTIONS (IPs this domain pointed to):"
        
        # IP resolutions
        res_data = resolutions.get('data', [])
        if res_data:
            response += f"\n"
            for res in res_data[:15]:
                res_attrs = res.get('attributes', {})
                ip_addr = res_attrs.get('ip_address', 'N/A')
                last_seen = res_attrs.get('date')
                if last_seen:
                    last_seen = datetime.fromtimestamp(last_seen).strftime('%Y-%m-%d')
                response += f"- {ip_addr} (Last: {last_seen or 'N/A'})\n"
        else:
            response += " None found\n"
        
        response += "\nSUBDOMAINS:"
        # Subdomains
        subdomain_data = subdomains.get('data', [])
        if subdomain_data:
            response += f"\n"
            for sub in subdomain_data[:15]:
                response += f"- {sub.get('id', 'N/A')}\n"
        else:
            response += " None found\n"
        
        response += "\nCOMMUNICATING FILES (files that contact this domain):"
        # Malware communicating with this domain
        files_data = comm_files.get('data', [])
        if files_data:
            response += f"\n"
            for file_data in files_data[:10]:
                f_attrs = file_data.get('attributes', {})
                f_name = f_attrs.get('meaningful_name', 'Unknown')
                f_stats = f_attrs.get('last_analysis_stats', {})
                f_malicious = f_stats.get('malicious', 0)
                f_total = sum(f_stats.values()) if f_stats else 0
                response += f"- {file_data.get('id', 'N/A')} ({f_name}) - Detections: {f_malicious}/{f_total}\n"
        else:
            response += " None found\n"
        
        response += "\nREFERRING FILES (files that embed/reference this domain):"
        # Files that reference this domain
        referring_data = referring_files.get('data', [])
        if referring_data:
            response += f"\n"
            for file_data in referring_data[:10]:
                f_attrs = file_data.get('attributes', {})
                f_name = f_attrs.get('meaningful_name', 'Unknown')
                f_stats = f_attrs.get('last_analysis_stats', {})
                f_malicious = f_stats.get('malicious', 0)
                f_total = sum(f_stats.values()) if f_stats else 0
                response += f"- {file_data.get('id', 'N/A')} ({f_name}) - Detections: {f_malicious}/{f_total}\n"
        else:
            response += " None found\n"
        
        response += "\nURLs ON DOMAIN:"
        # URLs on this domain
        url_data = urls.get('data', [])
        if url_data:
            response += f"\n"
            for url in url_data[:10]:
                response += f"- {url.get('id', 'N/A')}\n"
        else:
            response += " None found\n"
        
        # Add reputation context
        response += f"\nREPUTATION CONTEXT:\n"
        response += f"- VT Community Score: {attrs.get('reputation', 'N/A')}"
        

        
        response += f"\nSource: https://www.virustotal.com/gui/domain/{domain}"
        return response

    def _format_url_analysis(self, attrs: Dict, stats: Dict, url: str) -> str:
        """Format comprehensive URL analysis."""
        response = f"""=== VIRUSTOTAL COMPREHENSIVE ANALYSIS ===
IOC: {url} (URL)
Analysis Date: {datetime.now().isoformat()}

DETECTION SUMMARY:
- Malicious: {stats.get('malicious', 0)}
- Suspicious: {stats.get('suspicious', 0)}
- Clean: {stats.get('harmless', 0)}
- Undetected: {stats.get('undetected', 0)}
- Total Engines: {sum(stats.values()) if stats else 0}

URL DETAILS:
- Final URL: {attrs.get('url', 'N/A')}
- Title: {attrs.get('title', 'N/A')}"""
        
        last_analysis = attrs.get('last_analysis_date')
        if last_analysis:
            response += f"\n- Last Analysis: {datetime.fromtimestamp(last_analysis).strftime('%Y-%m-%d %H:%M:%S')}"
        
        # Add reputation context
        response += f"\n\nREPUTATION CONTEXT:\n"
        response += f"- VT Community Score: {attrs.get('reputation', 'N/A')}"
        
        response += f"\nSource: https://www.virustotal.com/gui/url/{base64.urlsafe_b64encode(url.encode()).decode()}"
        return response

    def _format_filename_analysis(self, search_results: Dict, filename: str) -> str:
        """Format comprehensive filename analysis with discovered files."""
        files_found = search_results.get('data', [])
        
        response = f"""=== VIRUSTOTAL COMPREHENSIVE ANALYSIS ===
IOC: {filename} (FILENAME)
Analysis Date: {datetime.now().isoformat()}

FILENAME SEARCH RESULTS:
- Files Found: {len(files_found)}

FILES WITH THIS FILENAME:"""
        
        if files_found:
            for i, file_data in enumerate(files_found, 1):
                attrs = file_data.get('attributes', {})
                file_hash = file_data.get('id', 'N/A')
                stats = attrs.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                total = sum(stats.values()) if stats else 0
                file_size = attrs.get('size', 'N/A')
                file_type = attrs.get('type_description', 'N/A')
                
                response += f"\n\n--- File {i} ---"
                response += f"\n- Hash: {file_hash}"
                response += f"\n- Name: {attrs.get('meaningful_name', filename)}"
                response += f"\n- Detections: {malicious}/{total}"
                response += f"\n- Size: {file_size} bytes"
                response += f"\n- Type: {file_type}"
                
                first_seen = attrs.get('first_submission_date')
                if first_seen:
                    response += f"\n- First Seen: {datetime.fromtimestamp(first_seen).strftime('%Y-%m-%d')}"
        else:
            response += " None found"
        
        return response

    def _calculate_threat_level(self, stats: Dict[str, int]) -> str:
        """Calculate threat level for quick assessment."""
        if not stats:
            return "UNKNOWN"
        
        total = sum(stats.values())
        malicious = stats.get('malicious', 0)
        
        if total == 0:
            return "UNKNOWN"
        
        ratio = malicious / total
        if ratio >= 0.1:
            return "HIGH"
        elif ratio >= 0.05:
            return "MEDIUM"
        elif stats.get('suspicious', 0) > 0:
            return "LOW"
        else:
            return "CLEAN"