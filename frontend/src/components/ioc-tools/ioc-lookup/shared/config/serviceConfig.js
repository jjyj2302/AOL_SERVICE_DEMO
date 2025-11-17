import AbuseIpdbDetails from '../services/AbuseIPDB/AbuseIpdbDetails';
import AlienvaultDetails from '../services/Alienvault/AlienvaultDetails';
import CheckphishDetails from '../services/Checkphish/CheckphishDetails';
import CrowdSecDetailsComponent from '../services/CrowdSec/CrowdSecDetails';
import EmailrepioDetails from '../services/EmailrepIO/EmailrepioDetails';
import GithubDetails from '../services/GitHub/GithubDetails';
import HaveibeenpwndDetails from '../services/HIBP/HaveibeenpwndDetails';
import HunterioDetails from '../services/HunterIO/HunterioDetails';
import IpQualityscoreDetails from '../services/IpQualityScore/IpqualityscoreDetails';
import MaltiverseDetails from '../services/Maltiverse/MaltiverseDetails';
import MalwarebazaarDetails from '../services/Malwarebazaar/MalwarebazaarDetails';
import NistNvdDetailsComponent from '../services/NistNVD/NistNvdDetails';
import PulsediveDetails from '../services/Pulsedive/PulsediveDetails';
import RedditDetails from '../services/Reddit/RedditDetails';
import SafeBrowseDetails from '../services/GoogleSafeBrowsing/SafebrowsingDetails';
import ShodanDetailsComponent from '../services/Shodan/ShodanDetails';
import ThreatfoxDetails from '../services/ThreatFox/ThreatfoxDetails';
import TwitterDetails from '../services/Twitter/TwitterDetails';
import VirustotalDetailsComponent from '../services/Virustotal/VirustotalDetails';
import UrlHausDetails from '../services/UrlHaus/UrlHausDetails';
import BGPViewDetails from '../services/BGPView/BGPViewDetails';
import UrlScanDetails from '../services/UrlScan/UrlScanDetails';


/**
 * Creates a simple endpoint generator for the unified backend API.
 * @param {string} serviceKey - The unique key for the service (e.g., 'virustotal').
 * @returns {function} A function that takes an IOC and its type and returns the API endpoint URL.
 */
const createSingleEndpoint = (serviceKey) => (ioc, iocType) =>
  `/api/ioc/lookup/${serviceKey}?ioc=${encodeURIComponent(ioc)}&ioc_type=${encodeURIComponent(iocType)}`;

/**
 * Unified service definitions. Each service has:
 * - name: Display name for the UI.
 * - icon: Filename for the service's icon.
 * - detailComponent: The React component used to render detailed results.
 * - requiredKeys: An array of API key names needed from global state.
 * - supportedIocTypes: An array of IOC types the service supports.
 * - lookupEndpoint: A function to generate the API request URL.
 * - getSummaryAndTlp: A function to process the API response into a display summary and TLP color.
 */
export const SERVICE_DEFINITIONS = {
  abuseipdb: {
    name: 'AbuseIPDB',
    icon: 'aipdb_logo_small',
    detailComponent: AbuseIpdbDetails,
    requiredKeys: ['abuseipdb'],
    supportedIocTypes: ['IPv4'],
    lookupEndpoint: createSingleEndpoint('abuseipdb'),
    getSummaryAndTlp: (responseData) => {
      if (responseData?.error) return { summary: `오류: ${responseData.message || responseData.error}`, tlp: 'WHITE' };
      if (!responseData?.data) return { summary: "데이터 없음", tlp: 'WHITE' };
      const { abuseConfidenceScore } = responseData.data;
      let tlp = 'GREEN';
      if (abuseConfidenceScore >= 75) tlp = 'RED';
      else if (abuseConfidenceScore >= 25) tlp = 'AMBER';
      return { summary: `악용 점수: ${abuseConfidenceScore}%`, tlp, keyMetric: `${abuseConfidenceScore}%` };
    },
  },
  alienvault: {
    name: 'AlienVault OTX',
    icon: 'avotx_logo_small',
    detailComponent: AlienvaultDetails,
    requiredKeys: ['alienvault'],
    supportedIocTypes: ['IPv4', 'IPv6', 'Domain', 'URL', 'MD5', 'SHA1', 'SHA256'],
    lookupEndpoint: createSingleEndpoint('alienvault'),
    getSummaryAndTlp: (responseData) => {
        if (responseData?.error) return { summary: `오류: ${responseData.message || responseData.error}`, tlp: 'WHITE' };
        if (!responseData) return { summary: "데이터 없음", tlp: 'WHITE' };
        const pulseCount = responseData.pulse_info?.count || 0;
        let tlp = pulseCount > 0 ? 'AMBER' : 'GREEN';
        if (responseData.reputation?.activities?.some(act => act.name?.toLowerCase().includes('malicious'))) {
            tlp = 'RED';
        }
        return { summary: `${pulseCount}개 펄스에서 발견됨`, tlp, keyMetric: pulseCount };
    },
  },
  bgpview: {
    name: 'BGPView',
    icon: 'bgpview_logo_small',
    detailComponent: BGPViewDetails,
    requiredKeys: [],
    supportedIocTypes: ['IPv4', 'IPv6', 'ASN'],
    lookupEndpoint: createSingleEndpoint('bgpview'),
    getSummaryAndTlp: (responseData) => {
        if (responseData?.error) {
            return { summary: `오류: ${responseData.message || responseData.error}`, tlp: 'WHITE' };
        }
        if (!responseData?.data) {
            return { summary: "데이터 없음", tlp: 'WHITE' };
        }

        const firstPrefixAsn = responseData.data.prefixes?.[0]?.asn;
        if (firstPrefixAsn) {
            const asn = firstPrefixAsn.asn || 'N/A';
            const name = firstPrefixAsn.name || 'Unknown';
            return { summary: `AS${asn} (${name})`, tlp: 'BLUE', keyMetric: `AS${asn}` };
        }

        const firstAsn = responseData.data.asns?.[0];
        if (firstAsn) {
             const asn = firstAsn.asn || 'N/A';
             const name = firstAsn.name || 'Unknown';
             return { summary: `AS${asn} (${name})`, tlp: 'BLUE', keyMetric: `AS${asn}` };
        }

        return { summary: "ASN 정보 없음", tlp: 'WHITE' };
    },
  },
  checkphish: {
    name: 'CheckPhish',
    icon: 'checkphish_logo_small',
    detailComponent: CheckphishDetails,
    requiredKeys: ['checkphishai'],
    supportedIocTypes: ['IPv4', 'Domain', 'URL'],
    lookupEndpoint: createSingleEndpoint('checkphish'),
    getSummaryAndTlp: (responseData) => {
        if (responseData?.error) return { summary: `오류: ${responseData.message || responseData.error}`, tlp: 'WHITE' };
        if (responseData.status !== 'DONE') return { summary: `스캔 상태: ${responseData?.status || "알 수 없음"}`, tlp: 'WHITE' };
        const { disposition } = responseData;
        let tlp = 'WHITE';
        if (disposition?.toLowerCase() === 'phish') tlp = 'RED';
        else if (disposition?.toLowerCase() === 'clean') tlp = 'GREEN';
        return { summary: `판정: ${disposition || '없음'}`, tlp, keyMetric: disposition || '없음' };
    },
  },
  crowdsec: {
    name: 'CrowdSec',
    icon: 'crowdsec_logo_small',
    detailComponent: CrowdSecDetailsComponent,
    requiredKeys: ['crowdsec'],
    supportedIocTypes: ['IPv4'],
    lookupEndpoint: createSingleEndpoint('crowdsec'),
    getSummaryAndTlp: (responseData) => {
        if (responseData?.error) return { summary: `오류: ${responseData.message || responseData.error}`, tlp: 'WHITE' };
        if (responseData.message?.toLowerCase().includes("not found")) return { summary: "CTI에서 IP를 찾을 수 없음", tlp: 'GREEN' };
        const score = responseData.ip_range_score;
        let tlp = 'GREEN';
        if (score === null || typeof score === 'undefined') return { summary: "점수 없음", tlp: 'WHITE' };
        if (score >= 0.8) tlp = 'RED'; else if (score >= 0.5) tlp = 'AMBER';
        return { summary: `CTI 범위 점수: ${score}`, tlp, keyMetric: score };
    },
  },
  emailrepio: {
    name: 'EmailRep.io',
    icon: 'emailrepio_logo_small',
    detailComponent: EmailrepioDetails,
    requiredKeys: ['emailrepio'],
    supportedIocTypes: ['Email'],
    lookupEndpoint: createSingleEndpoint('emailrepio'),
    getSummaryAndTlp: (responseData) => {
      if (responseData?.error) return { summary: `오류: ${responseData.message || responseData.error}`, tlp: 'WHITE' };
      if (!responseData) return { summary: "데이터 없음", tlp: 'WHITE' };
      let tlp = 'GREEN';
      if (responseData.suspicious) tlp = 'RED';
      else if (responseData.reputation === 'low') tlp = 'AMBER';
      return { summary: `평판: ${responseData.reputation || 'N/A'}${responseData.suspicious ? ' (의심스러움)' : ''}`, tlp, keyMetric: responseData.reputation };
    },
  },
  github: {
    name: 'GitHub Search',
    icon: 'github_logo_small',
    detailComponent: GithubDetails,
    requiredKeys: ['github_pat'],
    supportedIocTypes: ['IPv4', 'IPv6', 'Domain', 'URL', 'Email', 'MD5', 'SHA1', 'SHA256', 'CVE'],
    lookupEndpoint: createSingleEndpoint('github'),
    getSummaryAndTlp: (responseData) => {
        if (responseData?.error) return { summary: `오류: ${responseData.message || responseData.error}`, tlp: 'WHITE' };
        const count = responseData.total_count || 0;
        return { summary: `${count}회 언급됨`, tlp: count > 0 ? 'AMBER' : 'GREEN', keyMetric: count };
    },
  },
  haveibeenpwned: {
    name: 'Have I Been Pwned',
    icon: 'hibp_logo_small',
    detailComponent: HaveibeenpwndDetails,
    requiredKeys: ['hibp_api_key'],
    supportedIocTypes: ['Email'],
    lookupEndpoint: createSingleEndpoint('haveibeenpwned'),
    getSummaryAndTlp: (responseData) => {
        if (responseData?.error === 404) return { summary: "유출 기록 없음", tlp: 'GREEN' };
        if (responseData?.error) return { summary: `오류: ${responseData.message || responseData.error}`, tlp: 'WHITE' };
        const breachCount = responseData.breachedaccount?.length || 0;
        return { summary: `${breachCount}개 유출 사고에서 발견됨`, tlp: breachCount > 0 ? 'RED' : 'GREEN', keyMetric: breachCount };
    },
  },
  hunterio: {
    name: 'Hunter.io',
    icon: 'hunterio_logo_small',
    detailComponent: HunterioDetails,
    requiredKeys: ['hunterio_api_key'],
    supportedIocTypes: ['Email'],
    lookupEndpoint: createSingleEndpoint('hunterio'),
    getSummaryAndTlp: (responseData) => {
        if (responseData?.error) return { summary: `오류: ${responseData.message || responseData.error}`, tlp: 'WHITE' };
        if (!responseData?.data) return { summary: "데이터 없음", tlp: 'WHITE' };
        const { result, disposable } = responseData.data;
        let tlp = 'GREEN';
        if (disposable || result === 'undeliverable') tlp = 'RED';
        else if (result === 'risky') tlp = 'AMBER';
        return { summary: `상태: ${result}${disposable ? ' (일회용)' : ''}`, tlp, keyMetric: result };
    },
  },
  ipqualityscore: {
    name: 'IPQualityScore',
    icon: 'ipqualityscore_logo_small',
    detailComponent: IpQualityscoreDetails,
    requiredKeys: ['ipqualityscore'],
    supportedIocTypes: ['IPv4'],
    lookupEndpoint: createSingleEndpoint('ipqualityscore'),
    getSummaryAndTlp: (responseData) => {
        if (responseData?.error) return { summary: `오류: ${responseData.message || responseData.error}`, tlp: 'WHITE' };
        const score = responseData.fraud_score;
        if (typeof score === 'undefined') return { summary: "점수 없음", tlp: 'WHITE' };
        let tlp = 'GREEN';
        if (score >= 90) tlp = 'RED'; else if (score >= 75) tlp = 'AMBER';
        return { summary: `사기 점수: ${score}`, tlp, keyMetric: score };
    },
  },
  maltiverse: {
    name: 'Maltiverse',
    icon: 'maltiverse_logo_small',
    detailComponent: MaltiverseDetails,
    requiredKeys: ['maltiverse'],
    supportedIocTypes: ['IPv4', 'Domain', 'URL', 'MD5', 'SHA1', 'SHA256'],
    lookupEndpoint: createSingleEndpoint('maltiverse'),
    getSummaryAndTlp: (responseData) => {
        if (responseData?.error) return { summary: `오류: ${responseData.message || responseData.error}`, tlp: 'WHITE' };
        const classification = responseData.classification;
        if (!classification) return { summary: "분류 없음", tlp: 'WHITE' };
        let tlp = 'BLUE';
        if (classification === 'malicious') tlp = 'RED';
        else if (classification === 'suspicious') tlp = 'AMBER';
        else if (classification === 'whitelisted') tlp = 'GREEN';
        return { summary: `분류: ${classification}`, tlp, keyMetric: classification };
    },
  },
  malwarebazaar: {
    name: 'MalwareBazaar',
    icon: 'malwarebazaar_logo_small',
    detailComponent: MalwarebazaarDetails,
    requiredKeys: ['malwarebazaar'],
    supportedIocTypes: ['MD5', 'SHA1', 'SHA256'],
    lookupEndpoint: createSingleEndpoint('malwarebazaar'),
    getSummaryAndTlp: (responseData) => {
        if (responseData?.error) return { summary: `오류: ${responseData.message || responseData.error}`, tlp: 'WHITE' };
        const status = responseData.query_status;
        if (status === 'hash_not_found') return { summary: "해시를 찾을 수 없음", tlp: 'GREEN' };
        if (status === 'ok') return { summary: `발견됨: ${responseData.data[0].signature || '악성코드 샘플'}`, tlp: 'RED', keyMetric: responseData.data[0].signature };
        return { summary: `상태: ${status}`, tlp: 'WHITE' };
    },
  },
  nistnvd: {
    name: 'NIST NVD',
    icon: 'nistnvd_logo_small',
    detailComponent: NistNvdDetailsComponent,
    requiredKeys: ['nist_nvd_api_key'],
    supportedIocTypes: ['CVE'],
    lookupEndpoint: createSingleEndpoint('nistnvd'),
    getSummaryAndTlp: (responseData) => {
        if (responseData?.error) return { summary: `오류: ${responseData.message || responseData.error}`, tlp: 'WHITE' };
        if (!responseData.vulnerabilities?.length) return { summary: "CVE를 찾을 수 없음", tlp: 'GREEN' };
        const cve = responseData.vulnerabilities[0].cve;
        const metrics = cve.metrics?.cvssMetricV31 || cve.metrics?.cvssMetricV30 || [];
        const severity = metrics[0]?.cvssData?.baseSeverity || 'UNKNOWN';
        let tlp = 'WHITE';
        if (severity === 'CRITICAL' || severity === 'HIGH') tlp = 'RED';
        else if (severity === 'MEDIUM') tlp = 'AMBER';
        else if (severity === 'LOW') tlp = 'BLUE';
        return { summary: `심각도: ${severity}`, tlp, keyMetric: severity };
    },
  },
  pulsedive: {
    name: 'Pulsedive',
    icon: 'pulsedive_logo_small',
    detailComponent: PulsediveDetails,
    requiredKeys: ['pulsedive'],
    supportedIocTypes: ['IPv4', 'Domain', 'MD5', 'SHA1', 'SHA256', 'URL'],
    lookupEndpoint: createSingleEndpoint('pulsedive'),
    getSummaryAndTlp: (responseData) => {
        if (responseData?.error === 404) return { summary: "찾을 수 없음", tlp: 'GREEN' };
        if (responseData?.error) return { summary: `오류: ${responseData.error.info}`, tlp: 'WHITE' };
        const risk = responseData.risk?.toLowerCase() || 'unknown';
        let tlp = 'WHITE';
        if (risk === 'critical' || risk === 'high') tlp = 'RED';
        else if (risk === 'medium') tlp = 'AMBER';
        else if (risk === 'low') tlp = 'BLUE';
        else if (risk === 'none') tlp = 'GREEN';
        return { summary: `위험도: ${risk}`, tlp, keyMetric: risk };
    },
  },
  reddit: {
    name: 'Reddit Search',
    icon: 'reddit_logo_small',
    detailComponent: RedditDetails,
    requiredKeys: ['reddit_cid', 'reddit_cs'],
    supportedIocTypes: ['IPv4', 'IPv6', 'Domain', 'URL', 'Email', 'MD5', 'SHA1', 'SHA256', 'CVE'],
    lookupEndpoint: createSingleEndpoint('reddit'),
    getSummaryAndTlp: (responseData) => {
        if (responseData?.error) return { summary: `오류: ${responseData.message || responseData.error}`, tlp: 'WHITE' };
        const count = responseData?.data?.dist || 0;
        return { summary: `${count}회 언급됨`, tlp: count > 0 ? 'AMBER' : 'GREEN', keyMetric: count };
    },
  },
  safeBrowse: {
    name: 'Google Safe Browse',
    icon: 'safeBrowse_logo_small',
    detailComponent: SafeBrowseDetails,
    requiredKeys: ['safeBrowse'],
    supportedIocTypes: ['Domain', 'URL'],
    lookupEndpoint: createSingleEndpoint('safeBrowse'),
    getSummaryAndTlp: (responseData) => {
        if (responseData?.error) return { summary: `오류: ${responseData.message || responseData.error}`, tlp: 'WHITE' };
        if (!responseData.matches?.length) return { summary: "안전함", tlp: 'GREEN' };
        const threats = responseData.matches.map(m => m.threatType).join(', ');
        return { summary: `위협 발견됨: ${threats}`, tlp: 'RED', keyMetric: threats };
    },
  },
  shodan: {
    name: 'Shodan',
    icon: 'shodan_logo_small',
    detailComponent: ShodanDetailsComponent,
    requiredKeys: ['shodan'],
    supportedIocTypes: ['IPv4', 'Domain'],
    lookupEndpoint: createSingleEndpoint('shodan'),
    getSummaryAndTlp: (responseData) => {
        if (responseData?.error) return { summary: `오류: ${responseData.error}`, tlp: 'WHITE' };
        if (!responseData || Object.keys(responseData).length <= 1) return { summary: "정보 없음", tlp: 'WHITE' };
        const portCount = responseData.ports?.length || 0;
        const vuln_count = responseData.vulns?.length || 0;
        let tlp = portCount > 0 ? 'BLUE' : 'GREEN';
        if (vuln_count > 0) tlp = 'RED';
        return { summary: `${portCount}개 오픈 포트, ${vuln_count}개 취약점`, tlp, keyMetric: `${portCount}/${vuln_count}` };
    },
  },
  threatfox: {
    name: 'ThreatFox',
    icon: 'threatfox_logo_small',
    detailComponent: ThreatfoxDetails,
    requiredKeys: ['threatfox'],
    supportedIocTypes: ['IPv4', 'IPv6', 'Domain', 'URL', 'MD5', 'SHA1', 'SHA256'],
    lookupEndpoint: createSingleEndpoint('threatfox'),
    getSummaryAndTlp: (responseData) => {
        if (responseData?.error) return { summary: `오류: ${responseData.message || responseData.error}`, tlp: 'WHITE' };
        if (responseData.query_status === 'no_result') return { summary: "찾을 수 없음", tlp: 'GREEN' };
        if (responseData.query_status === 'ok') return { summary: `위협: ${responseData.data[0].threat_type}`, tlp: 'RED', keyMetric: responseData.data[0].threat_type };
        return { summary: `상태: ${responseData.query_status}`, tlp: 'WHITE' };
    },
  },
  twitter: {
    name: 'Twitter/X Search',
    icon: 'twitter_logo_small',
    detailComponent: TwitterDetails,
    requiredKeys: ['twitter_bearer_token'],
    supportedIocTypes: ['IPv4', 'IPv6', 'Domain', 'URL', 'Email', 'MD5', 'SHA1', 'SHA256', 'CVE'],
    lookupEndpoint: createSingleEndpoint('twitter'),
    getSummaryAndTlp: (responseData) => {
        if (responseData?.error) return { summary: `오류: ${responseData.title || responseData.detail}`, tlp: 'WHITE' };
        const count = responseData.meta?.result_count || 0;
        return { summary: `${count}개 게시물 발견됨`, tlp: count > 0 ? 'AMBER' : 'GREEN', keyMetric: count };
    },
  },
  urlhaus: {
    name: 'URLhaus',
    icon: 'urlhaus_logo_small',
    detailComponent: UrlHausDetails,
    requiredKeys: ['urlhaus'],
    supportedIocTypes: ['URL', 'Domain'],
    lookupEndpoint: createSingleEndpoint('urlhaus'),
    getSummaryAndTlp: (responseData) => {
        if (responseData?.error) return { summary: `오류: ${responseData.message || responseData.error}`, tlp: 'WHITE' };
        if (responseData.query_status === 'no_results') return { summary: "찾을 수 없음", tlp: 'GREEN' };
        if (responseData.query_status === 'ok') {
            const status = responseData.url_status || responseData.urls[0].url_status;
            return { summary: `발견됨, 상태: ${status}`, tlp: status === 'online' ? 'RED' : 'AMBER', keyMetric: status };
        }
        return { summary: `상태: ${responseData.query_status}`, tlp: 'WHITE' };
    },
  },
  urlscanio: {
    name: 'URLScan.io',
    icon: 'urlscanio_logo_small',
    detailComponent: UrlScanDetails,
    requiredKeys: [],
    supportedIocTypes: ['Domain', 'URL', 'IPv4'],
    lookupEndpoint: createSingleEndpoint('urlscanio'),
    getSummaryAndTlp: (responseData) => {
      if (responseData?.error) {
        return { summary: `오류: ${responseData.message || responseData.error}`, tlp: 'WHITE' };
      }

      const results = responseData?.results;
      if (!results || results.length === 0) {
        return { summary: "스캔을 찾을 수 없음", tlp: 'GREEN' };
      }

      const totalScans = results.length;

      const suspiciousTags = ['phishing', 'malware', '@phish_report'];

      const flaggedCount = results.filter(scan => {
        if (scan.verdicts?.overall?.malicious) {
          return true;
        }
        const scanTags = scan.task?.tags || [];
        return scanTags.some(tag => suspiciousTags.includes(tag.toLowerCase()));
      }).length;

      let summary = `${totalScans}개 스캔 발견됨`;
      let tlp = 'AMBER';
      let keyMetric = `${flaggedCount}/${totalScans}`;

      if (flaggedCount > 0) {
        summary = `${totalScans}개 스캔, ${flaggedCount}개 플래그됨`;
        tlp = 'RED';
      }

      return { summary, tlp, keyMetric };
    },
  },
  virustotal: {
    name: 'VirusTotal',
    icon: 'vt_logo_small',
    detailComponent: VirustotalDetailsComponent,
    requiredKeys: ['virustotal'],
    supportedIocTypes: ['IPv4', 'IPv6', 'Domain', 'URL', 'MD5', 'SHA1', 'SHA256'],
    lookupEndpoint: createSingleEndpoint('virustotal'),
    getSummaryAndTlp: (responseData) => {
      if (responseData?.error) return { summary: `오류: ${responseData.message || responseData.error}`, tlp: 'WHITE' };
      if (responseData.error?.code === 'NotFoundError') return { summary: "찾을 수 없음", tlp: 'GREEN' };
      const stats = responseData.data?.attributes?.last_analysis_stats;
      if (!stats) return { summary: "분석 데이터 없음", tlp: 'WHITE' };
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const total = (stats.harmless || 0) + malicious + suspicious + (stats.timeout || 0) + (stats.undetected || 0);
      let tlp = 'GREEN';
      if (malicious > 0) tlp = 'RED';
      else if (suspicious > 0) tlp = 'AMBER';
      return { summary: `${total}개 엔진 중 ${malicious + suspicious}개에서 악성 또는 의심으로 탐지됨`, tlp, keyMetric: `${malicious + suspicious}/${total}` };
    },
  },
};
