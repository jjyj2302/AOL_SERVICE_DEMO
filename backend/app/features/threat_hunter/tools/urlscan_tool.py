from crewai.tools import BaseTool
from typing import Type, Dict, Any, Set
from pydantic import BaseModel, Field, field_validator
import requests
import re
import json
import os
from datetime import datetime, timedelta
from urllib.parse import quote
import time
from app.core.settings.api_keys.cache import APIKeyCache


class URLScanInput(BaseModel):
    """Input schema for URLScan Search Tool."""
    query: str = Field(..., description="The search query/dork for URLScan.io - can include operators like domain:, ip:, asn:, page.url:, etc.")

    @field_validator('query', mode='before')
    @classmethod
    def parse_query(cls, v):
        """Handle LLM wrapping args as dict instead of string"""
        if isinstance(v, dict):
            return v.get('description', v.get('value', str(v)))
        return v


class URLScanTool(BaseTool):
    name: str = "URLScan Search Tool"
    description: str = (
        "URLScan.io API tool for threat hunting and IOC discovery. Searches URLScan database using various operators "
        "like domain:, ip:, asn:, page.url:, etc. Returns detailed scan results with extracted IOCs, patterns, "
        "and infrastructure information. Essential for pivoting on IOCs and discovering related infrastructure."
    )
    args_schema: Type[BaseModel] = URLScanInput
    api_key: str = Field(default="", exclude=True)

    def __init__(self, api_key: str = None):
        super().__init__()
        # Try API key cache first, then environment variable
        if api_key:
            self.api_key = api_key
        else:
            cache = APIKeyCache.get_instance()
            urlscan_key_data = cache.get_key('urlscanio')
            self.api_key = urlscan_key_data.get('key') if urlscan_key_data and urlscan_key_data.get('key') else os.getenv('URLSCAN_API_KEY')

        if not self.api_key:
            print("Warning: URLScan API key not found. Using public API with limited features.")
        else:
            print("URLScan API key loaded successfully.")

    def _run(self, query: str) -> str:
        """Execute URLScan search for the given query."""
        try:
            # Fix: LLM sometimes wraps args as {"description": "value", "type": "str"} instead of just "value"
            # This happens when GPT-4 misinterprets Pydantic Field metadata as actual data structure
            if isinstance(query, dict):
                query = query.get('description', query.get('value', str(query)))

            # Simple query validation and cleaning
            clean_query = self._validate_and_clean_query(query)
            
            # URLScan search API endpoint
            search_url = f"https://urlscan.io/api/v1/search/?q={quote(clean_query)}"
            
            print(f"Executing URLScan query: {clean_query}")
            
            # Prepare headers with API key if available
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'ThreatHunter/1.0'
            }
            
            if self.api_key:
                headers['API-Key'] = self.api_key
            
            response = requests.get(search_url, headers=headers)
            
            # Handle rate limiting
            if response.status_code == 429:
                print("Rate limit hit, waiting 5 seconds...")
                time.sleep(5)
                response = requests.get(search_url, headers=headers)
            
            if not response.ok:
                raise Exception(f"URLScan API error: {response.status_code} {response.reason} - {response.text}")
            
            data = response.json()
            
            # Format results - let AI analyze patterns
            return self._format_urlscan_results(data, clean_query)
            
        except Exception as error:
            print(f'URLScan search error: {error}')
            return f'URLScan search failed for query "{query}": {str(error)}'

    def _validate_and_clean_query(self, query: str) -> str:
        """Only fix obvious syntax errors - let AI handle logic."""
        clean_query = query.strip()
        
        # Fix common syntax mistakes only
        clean_query = re.sub(r'ip:"([^"]+)"', r'ip:\1', clean_query)
        clean_query = re.sub(r'domain:"([^"]+)"', r'domain:\1', clean_query)
        clean_query = re.sub(r'page\.ip:"([^"]+)"', r'page.ip:\1', clean_query)
        clean_query = re.sub(r'server\.ip:"([^"]+)"', r'server.ip:\1', clean_query)
        
        return clean_query

    def _format_urlscan_results(self, data: Dict[str, Any], query: str) -> str:
        """Format URLScan results with simple IOC extraction."""
        results = data.get('results', [])
        total = data.get('total', 0)
        
        response = f"=== URLSCAN SEARCH RESULTS ===\n"
        response += f"Query: {query}\n"
        response += f"Total Results: {total}\n"
        response += f"Showing: {len(results)} results\n"
        response += f"API Status: {'Authenticated' if self.api_key else 'Public (Limited)'}\n"
        response += f"Search Date: {datetime.now().isoformat()}\n\n"
        
        if len(results) == 0:
            response += "No results found for this query.\n"
            return response
        
        # Simple IOC extraction - let AI analyze significance
        extracted_iocs = {
            'domains': set(),
            'ips': set(),
            'urls': set(),
            'asns': set(),
            'countries': set()
        }
        
        response += "DETAILED RESULTS:\n"
        for index, result in enumerate(results[:20]):
            task = result.get('task', {})
            page = result.get('page', {})
            
            response += f"\n--- Result {index + 1} ---\n"
            response += f"URL: {task.get('url', 'N/A')}\n"
            response += f"Domain: {task.get('domain', 'N/A')}\n"
            response += f"Time: {task.get('time', 'N/A')}\n"
            response += f"Country: {page.get('country', 'N/A')}\n"
            response += f"Server IP: {page.get('ip', 'N/A')}\n"
            response += f"ASN: {page.get('asn', 'N/A')}\n"
            response += f"ASN Name: {page.get('asnname', 'N/A')}\n"
            response += f"Status: {page.get('status', 'N/A')}\n"
            response += f"URLScan Link: {result.get('result', 'N/A')}\n"
            
            # Simple extraction - no filtering logic
            if task.get('domain'):
                extracted_iocs['domains'].add(task['domain'])
            if page.get('ip'):
                extracted_iocs['ips'].add(page['ip'])
            if task.get('url'):
                extracted_iocs['urls'].add(task['url'])
            if page.get('asn') and page.get('asnname'):
                extracted_iocs['asns'].add(f"{page['asn']} ({page['asnname']})")
            if page.get('country'):
                extracted_iocs['countries'].add(page['country'])
        
        # Simple summary - let AI decide what's significant
        response += f"\n=== EXTRACTED IOCS SUMMARY ===\n"
        response += f"Unique Domains: {len(extracted_iocs['domains'])}\n"
        response += f"Unique IPs: {len(extracted_iocs['ips'])}\n"
        response += f"Unique URLs: {len(extracted_iocs['urls'])}\n"
        response += f"Unique ASNs: {len(extracted_iocs['asns'])}\n"
        response += f"Unique Countries: {len(extracted_iocs['countries'])}\n"
        
        if extracted_iocs['domains']:
            response += f"\nDOMAINS FOUND:\n"
            for domain in list(extracted_iocs['domains'])[:20]:
                response += f"- {domain}\n"
        
        if extracted_iocs['ips']:
            response += f"\nIPS FOUND:\n"
            for ip in list(extracted_iocs['ips'])[:20]:
                response += f"- {ip}\n"
        
        if extracted_iocs['asns']:
            response += f"\nASNS FOUND:\n"
            for asn in list(extracted_iocs['asns'])[:10]:
                response += f"- {asn}\n"
        
        if extracted_iocs['countries']:
            response += f"\nCOUNTRIES FOUND:\n"
            for country in extracted_iocs['countries']:
                response += f"- {country}\n"
        
        # Simple pattern suggestions - let AI decide significance
        response += f"\n=== BASIC PATTERNS IDENTIFIED ===\n"
        
        # Simple TLD analysis without hardcoded "suspicious" lists
        domains = list(extracted_iocs['domains'])
        if domains:
            tlds = [domain.split('.')[-1] for domain in domains if '.' in domain]
            tld_counts = {}
            for tld in tlds:
                tld_counts[tld] = tld_counts.get(tld, 0) + 1
            response += f"TLD Distribution: {json.dumps(tld_counts)}\n"
        
        # Simple timing analysis
        timestamps = []
        for result in results:
            task_time = result.get('task', {}).get('time')
            if task_time:
                try:
                    # Parse the timestamp and convert to timezone-naive UTC
                    dt = datetime.fromisoformat(task_time.replace('Z', '+00:00'))
                    # Convert to naive datetime in UTC
                    timestamps.append(dt.replace(tzinfo=None))
                except:
                    pass
        
        if timestamps:
            oldest_date = min(timestamps).strftime('%Y-%m-%d')
            newest_date = max(timestamps).strftime('%Y-%m-%d')
            response += f"Date Range: {oldest_date} to {newest_date}\n"
            
            # Use timezone-naive datetime for comparison
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            recent_results = [t for t in timestamps if t > thirty_days_ago]
            response += f"Recent Activity (30 days): {len(recent_results)}/{len(results)} results\n"
        
        return response