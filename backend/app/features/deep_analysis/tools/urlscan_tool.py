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
from app.core.cache.redis_cache import RedisCache
from ..schemas.tool_outputs import URLScanOutput, URLScanResult


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
    redis_cache: Any = Field(default=None, exclude=True)

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

        # Initialize Redis cache
        self.redis_cache = RedisCache.get_instance()

    def _run(self, query: str) -> URLScanOutput:
        """Execute URLScan search for the given query."""
        try:
            # Fix: LLM sometimes wraps args as {"description": "value", "type": "str"} instead of just "value"
            # This happens when GPT-4 misinterprets Pydantic Field metadata as actual data structure
            if isinstance(query, dict):
                query = query.get('description', query.get('value', str(query)))

            # Simple query validation and cleaning
            clean_query = self._validate_and_clean_query(query)

            # Redis Cache Check
            cached_result = self.redis_cache.get_ioc_result('urlscan', 'query', clean_query)
            if cached_result:
                print(f"[CACHE HIT] URLScan query: {clean_query}")
                return URLScanOutput(**cached_result)

            # URLScan search API endpoint
            search_url = f"https://urlscan.io/api/v1/search/?q={quote(clean_query)}"

            print(f"[URLScan API] Executing query: {clean_query}")

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

            # Format results as Pydantic object
            result = self._format_urlscan_results(data, clean_query)

            # Save to Redis Cache
            self.redis_cache.set_ioc_result('urlscan', 'query', clean_query, result.model_dump())

            return result

        except Exception as error:
            print(f'URLScan search error: {error}')
            # Return empty URLScanOutput on error
            return URLScanOutput(
                query=query,
                total_results=0,
                results_shown=0,
                results=[],
                unique_domains=[],
                unique_ips=[],
                unique_urls=[],
                unique_asns=[],
                unique_countries=[]
            )

    def _validate_and_clean_query(self, query: str) -> str:
        """Only fix obvious syntax errors - let AI handle logic."""
        clean_query = query.strip()
        
        # Fix common syntax mistakes only
        clean_query = re.sub(r'ip:"([^"]+)"', r'ip:\1', clean_query)
        clean_query = re.sub(r'domain:"([^"]+)"', r'domain:\1', clean_query)
        clean_query = re.sub(r'page\.ip:"([^"]+)"', r'page.ip:\1', clean_query)
        clean_query = re.sub(r'server\.ip:"([^"]+)"', r'server.ip:\1', clean_query)
        
        return clean_query

    def _format_urlscan_results(self, data: Dict[str, Any], query: str) -> URLScanOutput:
        """Format URLScan results as structured Pydantic object - NO DATA LOSS!"""
        results_data = data.get('results', [])
        total = data.get('total', 0)

        if len(results_data) == 0:
            return URLScanOutput(
                query=query,
                total_results=total,
                results_shown=0,
                results=[],
                unique_domains=[],
                unique_ips=[],
                unique_urls=[],
                unique_asns=[],
                unique_countries=[]
            )

        # Parse ALL results - NO TRUNCATION!
        urlscan_results = []
        unique_domains = set()
        unique_ips = set()
        unique_urls = set()
        unique_asns = set()
        unique_countries = set()
        timestamps = []

        for result in results_data:  # Process ALL results, not [:20]!
            task = result.get('task', {})
            page = result.get('page', {})

            # Create URLScanResult object
            urlscan_result = URLScanResult(
                url=task.get('url', ''),
                domain=task.get('domain', ''),
                scan_time=task.get('time', ''),
                page_ip=page.get('ip'),
                server_ip=page.get('server', {}).get('ip') if isinstance(page.get('server'), dict) else None,
                country=page.get('country'),
                asn=page.get('asn'),
                asn_name=page.get('asnname'),
                status_code=page.get('status'),
                urlscan_link=result.get('result', '')
            )
            urlscan_results.append(urlscan_result)

            # Extract unique IOCs
            if task.get('domain'):
                unique_domains.add(task['domain'])
            if page.get('ip'):
                unique_ips.add(page['ip'])
            if task.get('url'):
                unique_urls.add(task['url'])
            if page.get('asn'):
                asn_str = f"{page['asn']}"
                if page.get('asnname'):
                    asn_str += f" ({page['asnname']})"
                unique_asns.add(asn_str)
            if page.get('country'):
                unique_countries.add(page['country'])

            # Collect timestamps
            task_time = task.get('time')
            if task_time:
                try:
                    dt = datetime.fromisoformat(task_time.replace('Z', '+00:00'))
                    timestamps.append(dt.replace(tzinfo=None))
                except:
                    pass

        # Calculate temporal patterns
        date_range_start = None
        date_range_end = None
        recent_activity_count = 0

        if timestamps:
            date_range_start = min(timestamps).isoformat()
            date_range_end = max(timestamps).isoformat()

            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            recent_activity_count = len([t for t in timestamps if t > thirty_days_ago])

        # Calculate TLD distribution
        tld_distribution = {}
        for domain in unique_domains:
            if '.' in domain:
                tld = domain.split('.')[-1]
                tld_distribution[tld] = tld_distribution.get(tld, 0) + 1

        return URLScanOutput(
            query=query,
            total_results=total,
            results_shown=len(urlscan_results),
            results=urlscan_results,  # ALL results!
            unique_domains=sorted(list(unique_domains)),
            unique_ips=sorted(list(unique_ips)),
            unique_urls=sorted(list(unique_urls)),
            unique_asns=sorted(list(unique_asns)),
            unique_countries=sorted(list(unique_countries)),
            date_range_start=date_range_start,
            date_range_end=date_range_end,
            recent_activity_count=recent_activity_count,
            tld_distribution=tld_distribution
        )