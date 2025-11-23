from crewai.tools import BaseTool
from typing import Type, Dict, Any, Optional, List, Union
from pydantic import BaseModel, Field, field_validator
import requests
import re
import base64
import json
import os
from datetime import datetime
from app.core.settings.api_keys.cache import APIKeyCache
from app.core.cache.redis_cache import RedisCache
from ..schemas.tool_outputs import (
    VirusTotalHashOutput,
    VirusTotalDomainOutput,
    VirusTotalIPOutput,
    DetectionStats,
    CommunicatingFile,
    ContactedIP,
    ContactedDomain,
    DNSResolution,
    BehavioralIndicators
)


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
    redis_cache: Any = Field(default=None, exclude=True)

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

        # Initialize Redis cache
        self.redis_cache = RedisCache.get_instance()

    def _run(self, ioc: str, ioc_type: str) -> Union[VirusTotalHashOutput, VirusTotalDomainOutput, VirusTotalIPOutput, str]:
        """Execute focused VirusTotal analysis - returns structured Pydantic objects."""
        try:
            # Fix: LLM sometimes wraps args as {"description": "value", "type": "str"} instead of just "value"
            # This happens when GPT-4 misinterprets Pydantic Field metadata as actual data structure
            if isinstance(ioc, dict):
                ioc = ioc.get('description', ioc.get('value', str(ioc)))
            if isinstance(ioc_type, dict):
                ioc_type = ioc_type.get('description', ioc_type.get('value', str(ioc_type)))

            # Redis Cache Check
            cached_result = self.redis_cache.get_ioc_result('virustotal', ioc_type, ioc)
            if cached_result:
                print(f"[CACHE HIT] VT {ioc} ({ioc_type})")
                # Reconstruct Pydantic object from cached dict
                if ioc_type == 'hash':
                    return VirusTotalHashOutput(**cached_result)
                elif ioc_type == 'ip':
                    return VirusTotalIPOutput(**cached_result)
                elif ioc_type == 'domain':
                    return VirusTotalDomainOutput(**cached_result)
                else:
                    return cached_result.get('result', cached_result)

            print(f"[VT API] Analyzing {ioc} ({ioc_type})")

            # Get primary data + essential relationships in minimal API calls
            if ioc_type == 'hash':
                result = self._analyze_hash(ioc)
            elif ioc_type == 'ip':
                result = self._analyze_ip(ioc)
            elif ioc_type == 'domain':
                result = self._analyze_domain(ioc)
            elif ioc_type == 'url':
                result = self._analyze_url(ioc)
            elif ioc_type == 'filename':
                result = self._analyze_filename(ioc)
            else:
                return f"Unsupported IOC type: {ioc_type}"

            # Save to Redis Cache
            if isinstance(result, (VirusTotalHashOutput, VirusTotalIPOutput, VirusTotalDomainOutput)):
                self.redis_cache.set_ioc_result('virustotal', ioc_type, ioc, result.model_dump())
            elif isinstance(result, str):
                self.redis_cache.set_ioc_result('virustotal', ioc_type, ioc, {'result': result})

            return result

        except Exception as error:
            return f"VirusTotal analysis failed for {ioc}: {str(error)}"
    
    def _safe_join(self, items: list, separator: str = ', ') -> str:
        """Safely join list items, converting non-strings to strings."""
        if not items:
            return 'None'
        safe_items = [str(item) for item in items if item is not None]
        return separator.join(safe_items) if safe_items else 'None'

    def _analyze_hash(self, hash_value: str) -> Union[VirusTotalHashOutput, str]:
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

    def _format_hash_analysis(self, attrs: Dict, stats: Dict, c2_data: Dict, file_rels: Dict, behavior: Dict, hash_value: str) -> VirusTotalHashOutput:
        """Format comprehensive hash analysis as Pydantic object - NO DATA LOSS!"""
        file_name = self._get_safe_filename(attrs)

        # Build DetectionStats
        detection_stats = DetectionStats(
            malicious=stats.get('malicious', 0),
            suspicious=stats.get('suspicious', 0),
            harmless=stats.get('harmless', 0),
            undetected=stats.get('undetected', 0),
            total=sum(stats.values()) if stats else 0
        )

        # Parse timestamps
        first_seen = None
        if attrs.get('first_submission_date'):
            first_seen = datetime.fromtimestamp(attrs['first_submission_date']).isoformat()

        last_analysis = None
        if attrs.get('last_analysis_date'):
            last_analysis = datetime.fromtimestamp(attrs['last_analysis_date']).isoformat()

        # Parse Contacted IPs - NO TRUNCATION!
        contacted_ips = []
        for ip_data in c2_data.get('contacted_ips', {}).get('data', []):
            contacted_ips.append(ContactedIP(
                ip=ip_data.get('id', ''),
                port=None,  # VT doesn't provide port in this endpoint
                protocol=None,
                country=None,
                asn=None,
                asn_name=None
            ))

        # Parse Contacted Domains - NO TRUNCATION!
        contacted_domains = []
        for domain_data in c2_data.get('contacted_domains', {}).get('data', []):
            contacted_domains.append(ContactedDomain(
                domain=domain_data.get('id', ''),
                detection_stats=None  # Would need separate API call
            ))

        # Parse Contacted URLs - NO TRUNCATION!
        contacted_urls = []
        for url_data in c2_data.get('contacted_urls', {}).get('data', []):
            contacted_urls.append(url_data.get('id', ''))

        # Parse Parent Files - NO TRUNCATION!
        parent_files = []
        for parent in file_rels.get('execution_parents', {}).get('data', []):
            p_attrs = parent.get('attributes', {})
            p_stats = p_attrs.get('last_analysis_stats', {})
            parent_files.append(CommunicatingFile(
                hash_sha256=parent.get('id', ''),
                hash_md5=p_attrs.get('md5'),
                hash_sha1=p_attrs.get('sha1'),
                filename=p_attrs.get('meaningful_name', 'Unknown'),
                file_type=p_attrs.get('type_description'),
                file_size=p_attrs.get('size'),
                detection_stats=DetectionStats(
                    malicious=p_stats.get('malicious', 0),
                    suspicious=p_stats.get('suspicious', 0),
                    harmless=p_stats.get('harmless', 0),
                    undetected=p_stats.get('undetected', 0),
                    total=sum(p_stats.values()) if p_stats else 0
                ),
                first_seen=None,
                last_seen=None,
                tags=p_attrs.get('tags', [])
            ))

        # Parse Dropped Files - NO TRUNCATION!
        dropped_files = []
        for drop in file_rels.get('dropped_files', {}).get('data', []):
            d_attrs = drop.get('attributes', {})
            d_stats = d_attrs.get('last_analysis_stats', {})
            dropped_files.append(CommunicatingFile(
                hash_sha256=drop.get('id', ''),
                hash_md5=d_attrs.get('md5'),
                hash_sha1=d_attrs.get('sha1'),
                filename=d_attrs.get('meaningful_name', 'Unknown'),
                file_type=d_attrs.get('type_description'),
                file_size=d_attrs.get('size'),
                detection_stats=DetectionStats(
                    malicious=d_stats.get('malicious', 0),
                    suspicious=d_stats.get('suspicious', 0),
                    harmless=d_stats.get('harmless', 0),
                    undetected=d_stats.get('undetected', 0),
                    total=sum(d_stats.values()) if d_stats else 0
                ),
                first_seen=None,
                last_seen=None,
                tags=d_attrs.get('tags', [])
            ))

        # Parse Similar Files - NO TRUNCATION!
        similar_files = []
        for sim in file_rels.get('similar_files', {}).get('data', []):
            similar_files.append(sim.get('id', ''))

        # Parse Behavioral Indicators
        behavioral_indicators = None
        if behavior and behavior.get('data'):
            b_attrs = behavior['data'][0].get('attributes', {}) if behavior.get('data') else {}
            behavioral_indicators = BehavioralIndicators(
                mitre_tactics=b_attrs.get('mitre_attack_tactics', []),
                processes_created=b_attrs.get('processes_created', []),
                files_written=b_attrs.get('files_written', []),
                files_dropped=b_attrs.get('files_dropped', []),
                registry_keys_set=b_attrs.get('registry_keys_set', []),
                dns_lookups=b_attrs.get('dns_lookups', []),
                http_requests=b_attrs.get('http_conversations', []),
                mutexes_created=b_attrs.get('mutexes_created', [])
            )

        # Parse Digital Signature
        signature_info = None
        sig_data = attrs.get('signature_info', {})
        if sig_data:
            signature_info = {
                'product': sig_data.get('product', ''),
                'copyright': sig_data.get('copyright', ''),
                'description': sig_data.get('description', '')
            }

        return VirusTotalHashOutput(
            hash_sha256=attrs.get('sha256', hash_value),
            hash_md5=attrs.get('md5'),
            hash_sha1=attrs.get('sha1'),
            filename=file_name,
            file_type=attrs.get('type_description', 'Unknown'),
            file_size=attrs.get('size'),
            detection_stats=detection_stats,
            first_seen=first_seen,
            last_analysis=last_analysis,
            contacted_ips=contacted_ips,
            contacted_domains=contacted_domains,
            contacted_urls=contacted_urls,
            parent_files=parent_files,
            dropped_files=dropped_files,
            similar_files=similar_files,
            behavioral_indicators=behavioral_indicators,
            signature_info=signature_info
        )

    def _format_ip_analysis(self, attrs: Dict, stats: Dict, passive_dns: Dict, comm_files: Dict, downloaded_files: Dict, hosted_urls: Dict, ip: str) -> VirusTotalIPOutput:
        """Format comprehensive IP analysis as Pydantic object - NO DATA LOSS!"""

        # Build DetectionStats
        detection_stats = DetectionStats(
            malicious=stats.get('malicious', 0),
            suspicious=stats.get('suspicious', 0),
            harmless=stats.get('harmless', 0),
            undetected=stats.get('undetected', 0),
            total=sum(stats.values()) if stats else 0
        )

        # Parse Passive DNS - NO TRUNCATION! (was [:15])
        # For IP analysis, passive DNS contains domains that resolved to this IP
        passive_dns_resolutions = []
        for dns in passive_dns.get('data', []):  # ALL DNS records!
            dns_attrs = dns.get('attributes', {})
            last_seen = None
            if dns_attrs.get('date'):
                try:
                    last_seen = datetime.fromtimestamp(dns_attrs['date']).isoformat()
                except:
                    pass

            # DNSResolution schema expects 'ip' field for the hostname that resolved
            # For IP passive DNS, we store the domain name in the 'ip' field
            passive_dns_resolutions.append(DNSResolution(
                ip=dns_attrs.get('host_name', 'N/A'),
                last_seen=last_seen
            ))

        # Parse Communicating Files - NO TRUNCATION! (was [:10])
        communicating_files = []
        for file_data in comm_files.get('data', []):  # ALL files!
            f_attrs = file_data.get('attributes', {})
            f_stats = f_attrs.get('last_analysis_stats', {})

            communicating_files.append(CommunicatingFile(
                hash_sha256=file_data.get('id', ''),
                hash_md5=f_attrs.get('md5'),
                hash_sha1=f_attrs.get('sha1'),
                filename=f_attrs.get('meaningful_name', 'Unknown'),
                file_type=f_attrs.get('type_description'),
                file_size=f_attrs.get('size'),
                detection_stats=DetectionStats(
                    malicious=f_stats.get('malicious', 0),
                    suspicious=f_stats.get('suspicious', 0),
                    harmless=f_stats.get('harmless', 0),
                    undetected=f_stats.get('undetected', 0),
                    total=sum(f_stats.values()) if f_stats else 0
                ),
                first_seen=None,
                last_seen=None,
                tags=f_attrs.get('tags', [])
            ))

        # Parse Downloaded Files - NO TRUNCATION! (was [:10])
        downloaded_files_list = []
        for file_data in downloaded_files.get('data', []):  # ALL files!
            f_attrs = file_data.get('attributes', {})
            f_stats = f_attrs.get('last_analysis_stats', {})

            downloaded_files_list.append(CommunicatingFile(
                hash_sha256=file_data.get('id', ''),
                hash_md5=f_attrs.get('md5'),
                hash_sha1=f_attrs.get('sha1'),
                filename=f_attrs.get('meaningful_name', 'Unknown'),
                file_type=f_attrs.get('type_description'),
                file_size=f_attrs.get('size'),
                detection_stats=DetectionStats(
                    malicious=f_stats.get('malicious', 0),
                    suspicious=f_stats.get('suspicious', 0),
                    harmless=f_stats.get('harmless', 0),
                    undetected=f_stats.get('undetected', 0),
                    total=sum(f_stats.values()) if f_stats else 0
                ),
                first_seen=None,
                last_seen=None,
                tags=f_attrs.get('tags', [])
            ))

        # Parse Hosted URLs - NO TRUNCATION! (was [:10])
        hosted_urls_list = []
        for url in hosted_urls.get('data', []):  # ALL URLs!
            hosted_urls_list.append(url.get('id', 'N/A'))

        return VirusTotalIPOutput(
            ip=ip,
            asn=str(attrs.get('asn')) if attrs.get('asn') else None,
            asn_name=attrs.get('as_owner'),
            country=attrs.get('country'),
            detection_stats=detection_stats,
            passive_dns=passive_dns_resolutions,  # ALL DNS records, not [:15]!
            communicating_files=communicating_files,  # ALL files, not [:10]!
            downloaded_files=downloaded_files_list,  # ALL files, not [:10]!
            hosted_urls=hosted_urls_list  # ALL URLs, not [:10]!
        )

    def _format_domain_analysis(self, attrs: Dict, stats: Dict, resolutions: Dict, subdomains: Dict, comm_files: Dict, referring_files: Dict, urls: Dict, domain: str) -> VirusTotalDomainOutput:
        """Format comprehensive domain analysis as Pydantic object - NO DATA LOSS!"""

        # Build DetectionStats
        detection_stats = DetectionStats(
            malicious=stats.get('malicious', 0),
            suspicious=stats.get('suspicious', 0),
            harmless=stats.get('harmless', 0),
            undetected=stats.get('undetected', 0),
            total=sum(stats.values()) if stats else 0
        )

        # Parse creation date
        creation_date = None
        if attrs.get('creation_date'):
            try:
                creation_date = datetime.fromtimestamp(attrs['creation_date']).isoformat()
            except:
                pass

        # Parse categories
        categories = []
        if attrs.get('categories'):
            categories = list(attrs['categories'].values()) if hasattr(attrs['categories'], 'values') else []

        # Parse DNS Resolutions - NO TRUNCATION! (was [:15])
        # For domain analysis, DNS resolutions contain IPs the domain pointed to
        resolved_ips_list = []
        for res in resolutions.get('data', []):  # ALL resolutions!
            res_attrs = res.get('attributes', {})
            last_seen = None
            if res_attrs.get('date'):
                try:
                    last_seen = datetime.fromtimestamp(res_attrs['date']).isoformat()
                except:
                    pass

            resolved_ips_list.append(DNSResolution(
                ip=res_attrs.get('ip_address', 'N/A'),
                last_seen=last_seen
            ))

        # Parse Subdomains - NO TRUNCATION! (was [:15])
        subdomain_list = []
        for sub in subdomains.get('data', []):  # ALL subdomains!
            subdomain_list.append(sub.get('id', 'N/A'))

        # Parse Communicating Files - NO TRUNCATION! (was [:10])
        communicating_files = []
        for file_data in comm_files.get('data', []):  # ALL files!
            f_attrs = file_data.get('attributes', {})
            f_stats = f_attrs.get('last_analysis_stats', {})

            communicating_files.append(CommunicatingFile(
                hash_sha256=file_data.get('id', ''),
                hash_md5=f_attrs.get('md5'),
                hash_sha1=f_attrs.get('sha1'),
                filename=f_attrs.get('meaningful_name', 'Unknown'),
                file_type=f_attrs.get('type_description'),
                file_size=f_attrs.get('size'),
                detection_stats=DetectionStats(
                    malicious=f_stats.get('malicious', 0),
                    suspicious=f_stats.get('suspicious', 0),
                    harmless=f_stats.get('harmless', 0),
                    undetected=f_stats.get('undetected', 0),
                    total=sum(f_stats.values()) if f_stats else 0
                ),
                first_seen=None,
                last_seen=None,
                tags=f_attrs.get('tags', [])
            ))

        # Parse Referring Files - NO TRUNCATION! (was [:10])
        referring_files_list = []
        for file_data in referring_files.get('data', []):  # ALL files!
            f_attrs = file_data.get('attributes', {})
            f_stats = f_attrs.get('last_analysis_stats', {})

            referring_files_list.append(CommunicatingFile(
                hash_sha256=file_data.get('id', ''),
                hash_md5=f_attrs.get('md5'),
                hash_sha1=f_attrs.get('sha1'),
                filename=f_attrs.get('meaningful_name', 'Unknown'),
                file_type=f_attrs.get('type_description'),
                file_size=f_attrs.get('size'),
                detection_stats=DetectionStats(
                    malicious=f_stats.get('malicious', 0),
                    suspicious=f_stats.get('suspicious', 0),
                    harmless=f_stats.get('harmless', 0),
                    undetected=f_stats.get('undetected', 0),
                    total=sum(f_stats.values()) if f_stats else 0
                ),
                first_seen=None,
                last_seen=None,
                tags=f_attrs.get('tags', [])
            ))

        # Parse URLs on Domain - NO TRUNCATION! (was [:10])
        url_list = []
        for url in urls.get('data', []):  # ALL URLs!
            url_list.append(url.get('id', 'N/A'))

        return VirusTotalDomainOutput(
            domain=domain,
            detection_stats=detection_stats,
            registrar=attrs.get('registrar'),
            creation_date=creation_date,
            categories=categories,
            resolved_ips=resolved_ips_list,  # ALL resolutions, not [:15]!
            subdomains=subdomain_list,  # ALL subdomains, not [:15]!
            communicating_files=communicating_files,  # ALL files, not [:10]!
            referring_files=referring_files_list,  # ALL files, not [:10]!
            urls=url_list,  # ALL URLs, not [:10]!
            vt_community_score=attrs.get('reputation')
        )

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