import asyncio
import contextlib
import ipaddress
import json
import logging
import time
import uuid
from datetime import UTC
from datetime import datetime
from enum import Enum
from typing import Any
from typing import ClassVar

import aiohttp
import geoip2.database
import redis.asyncio as redis
from fastapi import status
from redis.asyncio.client import Redis

from app.core.config import settings as st

# Configure IP security logger
logger = logging.getLogger("ip_security")
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


class ThreatLevelThreshold(int, Enum):
    """Enum for threat levels and their corresponding thresholds"""

    LOW = 0
    MEDIUM = 30
    HIGH = 50
    CRITICAL = 80


class IPSecurityManager:
    """IP security management system for detecting and blocking malicious IPs"""

    _initialized: ClassVar[bool] = False
    _redis_client: ClassVar[Redis | None] = None
    _tor_exit_nodes: ClassVar[set[str]] = set()
    _last_tor_update: ClassVar[float] = 0
    _ip_reputation_cache: ClassVar[dict[str, dict[str, Any]]] = {}
    _datacenter_asns: ClassVar[set[int]] = {
        16509,  # AWS
        14618,  # Amazon
        15169,  # Google Cloud
        8075,  # Microsoft Azure
        36351,  # Softlayer/IBM
        14061,  # DigitalOcean
        63949,  # Linode
        19551,  # Incapsula
        13335,  # Cloudflare
        16276,  # OVH
        24940,  # Hetzner
        20473,  # Choopa/Vultr
        46606,  # Unified Layer
        34788,  # Neue Medien Muennich
        55293,  # A2 Hosting
    }
    _hosting_keywords: ClassVar[list[str]] = [
        "amazon",
        "google",
        "microsoft",
        "azure",
        "digital ocean",
        "linode",
        "softlayer",
        "rackspace",
        "hosting",
        "datacenter",
        "data center",
        "server",
        "cloud",
        "vps",
        "proxy",
        "ovh",
        "dedicated",
        "host",
        "colocation",
        "telecom",
        "isp",
    ]
    _high_risk_countries: ClassVar[set[str]] = {
        "RU",
        "CN",
        "IR",
        "KP",
        "SY",
        "VE",
        "CU",
        "MM",
        "BY",
        "SD",
    }
    _update_task: ClassVar[asyncio.Task | None] = None
    _blocklist_sources_text: ClassVar[list[str]] = [
        "https://iplists.firehol.org/files/firehol_level1.netset",
        "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        "https://lists.blocklist.de/lists/all.txt",
    ]
    _blocklist_sources_json: ClassVar[list[str]] = [
        "https://www.spamhaus.org/drop/drop_v4.json",  # IPv4
        "https://www.spamhaus.org/drop/drop_v6.json",  # IPv6
    ]
    _blocklist_asn: ClassVar[list[str]] = [
        "https://www.spamhaus.org/drop/asndrop.json",  # ASN
    ]
    _geo_city_db_path: ClassVar[str] = ""
    _geo_asn_db_path: ClassVar[str] = ""
    _api_keys: ClassVar[dict[str, str]] = {}

    @classmethod
    async def initialize(  # noqa: PLR0913
        cls,
        redis_url: str | None = None,
        geo_city_db_path: str | None = None,
        geo_asn_db_path: str | None = None,
        api_keys: dict[str, str] | None = None,
        update_interval: int = 3600,
        blocklist_sources_txt: list[str] | None = None,
        blocklist_sources_json: list[str] | None = None,
        blocklist_asn: list[str] | None = None,
        high_risk_countries: list[str] | None = None,
        datacenter_asns: list[int] | None = None,
    ) -> None:
        """Initialize the IP Security Manager

        Args:
            redis_url: Redis connection URL
            geo_city_db_path: Path to MaxMind GeoIP2 City database
            geo_asn_db_path: Path to MaxMind GeoIP2 ASN database
            api_keys: Dictionary of API keys for external services
            update_interval: Interval for updating blocklists (in seconds)
            blocklist_sources_txt: List of IP blocklist URLs (text format)
            blocklist_sources_json: List of IP blocklist URLs (JSON format)
            blocklist_asn: List of known ASN controlled by spammers or cyber criminals
            high_risk_countries: List of high-risk country codes
            datacenter_asns: List of ASNs for datacenters/hosting providers
        """
        if cls._initialized:
            return

        # Set up redis client
        if redis_url:
            try:
                cls._redis_client = redis.from_url(
                    redis_url,
                    decode_responses=True,
                )
                await cls._redis_client.ping()
                logger.info("IPSecurityManager connected to Redis")
            except Exception as e:
                msg = f"Failed to connect to Redis: {e}"
                logger.exception(msg)
                cls._redis_client = None
        else:
            try:
                redis_host = getattr(st, "REDIS_HOST", "localhost")
                redis_port = getattr(st, "REDIS_PORT", 6379)
                redis_db = getattr(st, "SECURITY_DB", 3)

                cls._redis_client = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    db=redis_db,
                    decode_responses=True,
                )
                await cls._redis_client.ping()
                logger.info("IPSecurityManager connected to Redis")
            except Exception as e:
                msg = f"Failed to connect to Redis: {e}"
                logger.exception(msg)
                cls._redis_client = None

        # Set up GeoIP databases
        cls._geo_city_db_path = geo_city_db_path or getattr(
            st,
            "GEOIP_CITY_DB_PATH",
            "/app/data/GeoLite2-City.mmdb",
        )
        cls._geo_asn_db_path = geo_asn_db_path or getattr(
            st,
            "GEOIP_ASN_DB_PATH",
            "/app/data/GeoLite2-ASN.mmdb",
        )

        # Set up API keys
        cls._api_keys = api_keys or {
            "abuseipdb": getattr(st, "ABUSEIPDB_API_KEY", ""),
            # in a enterprise setting, maybe use ipqualityscore
            # "ipqualityscore": getattr(st, "IPQUALITYSCORE_API_KEY", ""),
        }

        # Set up other configuration
        if blocklist_sources_txt:
            cls._blocklist_sources_text = blocklist_sources_txt
        if blocklist_sources_json:
            cls._blocklist_sources_json = blocklist_sources_json
        if blocklist_asn:
            cls._blocklist_asn = blocklist_asn
        if high_risk_countries:
            cls._high_risk_countries = set(high_risk_countries)
        if datacenter_asns:
            cls._datacenter_asns = set(datacenter_asns)

        # Initialize background tasks
        cls._initialized = True
        cls._update_task = asyncio.create_task(cls._periodic_updates(update_interval))

        background_tasks = set()

        task1 = asyncio.create_task(cls._update_tor_exit_nodes())
        background_tasks.add(task1)
        task1.add_done_callback(background_tasks.discard)

        task2 = asyncio.create_task(cls._update_ip_blocklists())
        background_tasks.add(task2)
        task2.add_done_callback(background_tasks.discard)

        logger.info("IPSecurityManager initialized successfully")

    @classmethod
    async def shutdown(cls) -> None:
        """Shut down the manager and clean up resources"""
        if cls._update_task:
            cls._update_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await cls._update_task
            cls._update_task = None

        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None

        cls._initialized = False
        logger.info("IPSecurityManager shutdown complete")

    @classmethod
    async def _periodic_updates(cls, interval: int) -> None:
        """Run periodic updates for blocklists and other data"""
        try:
            while True:
                await asyncio.sleep(interval)

                background_tasks = set()
                if time.time() - cls._last_tor_update > st.SECURITY_DATA_EXPIRE:
                    task = asyncio.create_task(cls._update_tor_exit_nodes())
                    background_tasks.add(task)
                    task.add_done_callback(background_tasks.discard)
                task = asyncio.create_task(cls._update_ip_blocklists())
                background_tasks.add(task)
                task.add_done_callback(background_tasks.discard)

                cls._clean_reputation_cache()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            msg = f"Error in periodic updates: {e}"
            logger.exception(msg)
            asyncio.create_task(cls._periodic_updates(interval))  # noqa: RUF006

    @classmethod
    async def _update_tor_exit_nodes(cls) -> None:
        """Update the list of TOR exit nodes"""
        try:
            async with (
                aiohttp.ClientSession() as session,
                session.get(
                    "https://check.torproject.org/exit-addresses",
                    timeout=30,  # type: ignore[arg-type]
                ) as response,
            ):
                if response.status == status.HTTP_200_OK:
                    text = await response.text()
                    exit_addresses = [
                        line.split()
                        for line in text.splitlines()
                        if line.startswith("ExitAddress ")
                    ]
                    new_nodes = {ip[1] for ip in exit_addresses if len(ip) >= 2}  # noqa: PLR2004
                    cls._tor_exit_nodes = new_nodes
                    cls._last_tor_update = time.time()

                    if cls._redis_client:
                        pipe = cls._redis_client.pipeline()
                        pipe.delete("tor_exit_nodes")
                        if new_nodes:
                            pipe.sadd("tor_exit_nodes", *new_nodes)
                        pipe.expire(
                            "tor_exit_nodes",
                            st.SECURITY_DATA_EXPIRE * 2,
                        )  # 2 days
                        await pipe.execute()

                    msg = f"Updated TOR exit nodes: {len(new_nodes)} nodes"
                    logger.info(msg)
        except Exception as e:
            msg = f"Failed to update TOR exit nodes: {e}"
            logger.exception(msg)

            if cls._redis_client:
                try:
                    cached_nodes = await cls._redis_client.smembers("tor_exit_nodes")  # type: ignore[call]
                    if cached_nodes:
                        cls._tor_exit_nodes = cached_nodes
                        msg = f"Loaded {len(cached_nodes)} TOR exit nodes from cache"
                        logger.info(msg)
                except Exception as e:
                    msg = f"Failed to load TOR exit nodes from cache: {e}"
                    logger.exception(msg)

    @classmethod
    async def _process_text_blocklist(
        cls,
        source: str,
        session: aiohttp.ClientSession,
    ) -> tuple[set[str], set[str]]:
        """Process a text-based IP blocklist source.

        Args:
            source: URL of the blocklist source
            session: Active aiohttp ClientSession

        Returns:
            Tuple containing (malicious_ips, malicious_networks)
        """
        malicious_ips = set()
        malicious_networks = set()

        try:
            async with session.get(source, timeout=30) as response:  # type: ignore[arg-type]
                if response.status == status.HTTP_200_OK:
                    text = await response.text()
                    lines = [
                        line.strip()
                        for line in text.splitlines()
                        if line.strip() and not line.startswith("#")
                    ]
                    for line in lines:
                        try:
                            if "/" in line:
                                network = ipaddress.ip_network(line)
                                malicious_networks.add(str(network))
                            else:
                                ip = ipaddress.ip_address(line)
                                malicious_ips.add(str(ip))
                        except ValueError:
                            continue
        except Exception as e:  # noqa: BLE001
            msg = f"Failed to process text blocklist from {source}: {e}"
            logger.warning(msg)

        return malicious_ips, malicious_networks

    @classmethod
    async def _process_json_blocklist(
        cls,
        source: str,
        session: aiohttp.ClientSession,
    ) -> tuple[set[str], set[str]]:
        """Process a JSON-based IP blocklist source.
        Actually, this is a implementation for spamhaus.org blocklist

        Args:
            source: URL of the blocklist source
            session: Active aiohttp ClientSession

        Returns:
            Tuple containing (malicious_ips, malicious_networks)
        """
        malicious_ips = set()
        malicious_networks = set()

        try:
            async with session.get(source, timeout=30) as response:  # type: ignore[arg-type]
                if (
                    response.status == status.HTTP_200_OK
                    and response.content_type == "text/json"
                ):
                    text = await response.text()
                    lines = [line.strip() for line in text.splitlines() if line.strip()]
                    for line in lines:
                        try:
                            entry = json.loads(line)
                            if "cidr" in entry:
                                try:
                                    if "/" in entry["cidr"]:
                                        network = ipaddress.ip_network(entry["cidr"])
                                        malicious_networks.add(str(network))
                                    else:
                                        ip = ipaddress.ip_address(entry["cidr"])
                                        malicious_ips.add(str(ip))
                                except ValueError:
                                    continue
                        except json.JSONDecodeError:
                            continue
        except Exception as e:  # noqa: BLE001
            msg = f"Failed to process JSON blocklist from {source}: {e}"
            logger.warning(msg)

        return malicious_ips, malicious_networks

    @classmethod
    async def _process_asn_blocklist(
        cls,
        source: str,
        session: aiohttp.ClientSession,
    ) -> set[str]:
        """Process a JSON-based ASN blocklist source.
        Actually, this is a implementation for spamhaus.org blocklist

        Args:
            source: URL of the blocklist source
            session: Active aiohttp ClientSession

        Returns:
            Set containing malicious ASNs
        """
        malicious_asn = set()

        try:
            async with session.get(source, timeout=30) as response:  # type: ignore[arg-type]
                if (
                    response.status == status.HTTP_200_OK
                    and response.content_type == "text/json"
                ):
                    text = await response.text()
                    lines = [line.strip() for line in text.splitlines() if line.strip()]
                    for line in lines:
                        try:
                            entry = json.loads(line)
                            if "asn" in entry:
                                malicious_asn.add(str(entry["asn"]))
                        except json.JSONDecodeError:
                            continue
        except Exception as e:  # noqa: BLE001
            msg = f"Failed to process JSON blocklist from {source}: {e}"
            logger.warning(msg)

        return malicious_asn

    @classmethod
    async def _update_ip_blocklists(cls) -> None:
        """Update IP blocklists from various sources"""
        try:
            malicious_ips = set()
            malicious_networks = set()

            async with aiohttp.ClientSession() as session:
                for source in cls._blocklist_sources_text:
                    ips, networks = await cls._process_text_blocklist(source, session)
                    malicious_ips.update(ips)
                    malicious_networks.update(networks)

                for source in cls._blocklist_sources_json:
                    ips, networks = await cls._process_json_blocklist(source, session)
                    malicious_ips.update(ips)
                    malicious_networks.update(networks)

                if cls._redis_client and (malicious_ips or malicious_networks):
                    pipe = cls._redis_client.pipeline()

                    if malicious_ips:
                        pipe.delete("malicious_ips")
                        batch_size = 1000
                        for i in range(0, len(malicious_ips), batch_size):
                            batch = list(malicious_ips)[i : i + batch_size]
                            pipe.sadd("malicious_ips", *batch)
                        pipe.expire("malicious_ips", st.SECURITY_DATA_EXPIRE)

                    if malicious_networks:
                        pipe.delete("malicious_networks")
                        pipe.sadd("malicious_networks", *malicious_networks)
                        pipe.expire("malicious_networks", st.SECURITY_DATA_EXPIRE)

                    await pipe.execute()

                    msg = (
                        f"Updated IP blocklists: {len(malicious_ips)} IPs, "
                        f"{len(malicious_networks)} networks"
                    )
                    logger.info(msg)

        except Exception as e:
            msg = f"Failed to update IP blocklists: {e}"
            logger.exception(msg)

    @classmethod
    async def _update_asn_blocklists(cls) -> None:
        """Update ASN blocklists from various sources"""
        try:
            malicious_asn = set()

            async with aiohttp.ClientSession() as session:
                for source in cls._blocklist_asn:
                    asns = await cls._process_asn_blocklist(source, session)
                    malicious_asn.update(asns)

                if cls._redis_client and malicious_asn:
                    pipe = cls._redis_client.pipeline()

                    pipe.delete("malicious_asns")
                    batch_size = 1000
                    for i in range(0, len(malicious_asn), batch_size):
                        batch = list(malicious_asn)[i : i + batch_size]
                        pipe.sadd("malicious_asns", *batch)
                    pipe.expire("malicious_asns", st.SECURITY_DATA_EXPIRE)

                    await pipe.execute()

                    msg = f"Updated ASN blocklists: {len(malicious_asn)} ASNs"
                    logger.info(msg)

        except Exception as e:
            msg = f"Failed to update ASN blocklists: {e}"
            logger.exception(msg)

    @classmethod
    def _clean_reputation_cache(cls) -> None:
        """Clean up expired entries from the reputation cache"""
        now = time.time()
        expired_keys = []

        for ip, data in cls._ip_reputation_cache.items():
            if now - data.get("timestamp", 0) > st.IP_REPUTATION_EXPIRE:
                expired_keys.append(ip)

        for key in expired_keys:
            cls._ip_reputation_cache.pop(key)

        if expired_keys:
            msg = (
                f"Cleaned {len(expired_keys)} expired entries from IP reputation cache"
            )
            logger.debug(msg)

    @classmethod
    def _is_tor_exit_node(cls, ip_address: str) -> bool:
        """Check if an IP is a known TOR exit node"""
        return ip_address in cls._tor_exit_nodes

    @classmethod
    async def _is_known_malicious_ip(cls, ip_address: str) -> tuple[bool, str]:
        """
        Check if IP is in database of known malicious IPs

        Returns:
            Tuple[bool, str]: (is_malicious, reason)
        """
        if not cls._redis_client:
            return False, ""

        try:
            is_malicious = await cls._redis_client.sismember(
                "malicious_ips",
                ip_address,
            )  # type: ignore[call-arg]
            if is_malicious:
                return True, "blocklist_direct_match"
            try:
                ip_obj = ipaddress.ip_address(ip_address)
                all_networks = await cls._redis_client.smembers("malicious_networks")  # type: ignore[call-arg]
                for network_str in all_networks:
                    try:
                        network = ipaddress.ip_network(network_str)
                        if ip_obj in network:
                            return True, f"blocklist_network_match:{network_str}"
                    except ValueError:
                        msg = f"Malicious IP check in network failed: {e}"
                        logger.warning(msg)
                        continue
            except ValueError:
                msg = f"Malicious IP check in network failed: {e}"
                logger.warning(msg)

            is_flagged = await cls._redis_client.sismember(
                "flagged_malicious_ips",
                ip_address,
            )  # type: ignore[call-arg]
            if is_flagged:
                reason = await cls._redis_client.get(f"flagged_ip:{ip_address}:reason")
                return True, reason or "manually_flagged"
        except Exception as e:  # noqa: BLE001
            msg = f"Malicious IP check failed: {e}"
            logger.warning(msg)
            return False, ""
        return False, ""

    @classmethod
    async def _is_known_malicious_asn(cls, asn_number: str) -> bool:
        """
        Check if an ASN is in database of known flagged malicious ASNs

        Returns:
            Bool: True if ASN is known malicious, False otherwise
        """
        if not cls._redis_client:
            return False

        try:
            is_malicious = await cls._redis_client.sismember(
                "malicious_asns",
                asn_number,
            )  # type: ignore[call-arg]
            if is_malicious:
                return True
        except Exception as e:  # noqa: BLE001
            msg = f"Malicious ASN check failed: {e}"
            logger.warning(msg)
            return False
        return False

    @classmethod
    async def _check_ip_reputation(cls, ip_address: str) -> dict[str, Any]:
        """Check IP reputation using a third-party service"""
        cache_key = f"ip_rep:{ip_address}"
        if cache_key in cls._ip_reputation_cache:
            cached_result = cls._ip_reputation_cache[cache_key]
            if time.time() - cached_result["timestamp"] < st.IP_REPUTATION_EXPIRE:
                return cached_result["data"]
        try:
            if cls._redis_client:
                cached_data = await cls._redis_client.get(f"ip_reputation:{ip_address}")
                if cached_data:
                    try:
                        reputation_data = json.loads(cached_data)
                        cls._ip_reputation_cache[cache_key] = {
                            "timestamp": time.time(),
                            "data": reputation_data,
                        }
                    except json.JSONDecodeError:
                        pass
                    return reputation_data

            async with aiohttp.ClientSession() as session:
                if cls._api_keys.get("abuseipdb"):
                    # AbuseIPDB
                    api_key = cls._api_keys["abuseipdb"]
                    async with session.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        params={"ipAddress": ip_address, "maxAgeInDays": 30},
                        headers={"Key": api_key, "Accept": "application/json"},
                        timeout=5,  # type: ignore[call-arg]
                    ) as response:
                        if response.status == status.HTTP_200_OK:
                            result = await response.json()
                            reputation_data = {
                                "score": result.get("data", {}).get(
                                    "abuseConfidenceScore",
                                    0,
                                ),
                                "is_suspicious": result.get("data", {}).get(
                                    "abuseConfidenceScore",
                                    0,
                                )
                                > st.ABUSEIPDB_SUSPICIOUS_THRESHOLD,
                                "is_known_attacker": result.get("data", {}).get(
                                    "abuseConfidenceScore",
                                    0,
                                )
                                > st.ABUSEIPDB_ATTACKER_THRESHOLD,
                                "country": result.get("data", {}).get("countryCode"),
                                "isp": result.get("data", {}).get("isp"),
                                "usage_type": result.get("data", {}).get("usageType"),
                                "reports": result.get("data", {}).get(
                                    "totalReports",
                                    0,
                                ),
                                "source": "abuseipdb",
                            }
                            cls._ip_reputation_cache[cache_key] = {
                                "timestamp": time.time(),
                                "data": reputation_data,
                            }
                            if cls._redis_client:
                                await cls._redis_client.setex(
                                    f"ip_reputation:{ip_address}",
                                    st.IP_REPUTATION_EXPIRE,
                                    json.dumps(reputation_data),
                                )
                            return reputation_data
        except Exception as e:  # noqa: BLE001
            msg = f"IP reputation check failed: {e}"
            logger.warning(msg)

        # Default response if checks fail
        return {
            "score": 0,
            "is_suspicious": False,
            "is_known_attacker": False,
            "country": None,
            "isp": None,
            "source": "default",
        }

    @classmethod
    async def _check_geoip_risk(cls, ip_address: str) -> dict[str, Any]:
        """Check geographic risk factors for an IP address"""
        try:
            # Check if IP is valid
            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                return {"error": "Invalid IP address"}

            # Initialize result
            geo_data = {}

            # Try city database first
            if cls._geo_city_db_path:
                try:
                    with geoip2.database.Reader(cls._geo_city_db_path) as city_reader:
                        city_response = city_reader.city(ip_address)
                        geo_data.update(
                            {
                                "country_code": city_response.country.iso_code,
                                "country_name": city_response.country.name,
                                "city": city_response.city.name,
                                "latitude": city_response.location.latitude,
                                "longitude": city_response.location.longitude,
                            },
                        )
                except Exception:  # noqa: BLE001, S110
                    pass

            # Try ASN database
            if cls._geo_asn_db_path:
                try:
                    with geoip2.database.Reader(cls._geo_asn_db_path) as asn_reader:
                        asn_response = asn_reader.asn(ip_address)
                        geo_data.update(
                            {
                                "asn": asn_response.autonomous_system_number,
                                "asn_org": asn_response.autonomous_system_organization,
                            },
                        )
                except Exception:  # noqa: BLE001, S110
                    pass

            geo_data["is_high_risk_country"] = (
                geo_data.get("country_code", "") in cls._high_risk_countries
            )
            # Check if datacenter/hosting IP
            asn = geo_data.get("asn")
            asn_org = str(geo_data.get("asn_org", "")).lower()

            geo_data["is_datacenter"] = False
            if asn in cls._datacenter_asns or any(
                kw in asn_org for kw in cls._hosting_keywords
            ):
                geo_data["is_datacenter"] = True
            if asn:
                with contextlib.suppress(Exception):
                    is_malicious_asn = await cls._is_known_malicious_asn(str(asn))
                    if is_malicious_asn:
                        geo_data["is_malicious_asn"] = True
        except Exception as e:  # noqa: BLE001
            msg = f"GeoIP check failed: {e}"
            logger.warning(msg)
            return {}
        return geo_data

    @classmethod
    def _assess_threat_score(cls, threat_score: int) -> tuple[bool, str]:
        """
        Assess a threat score based on IP data and gives recommendations
        on access control.

        Args:
            threat_score (int): The threat score to assess.

        Returns:
            tuple (bool, str): A tuple containing a boolean indicating whether
            access should be allowed and a string indicating the recommended
            access control action.
        """
        if threat_score >= ThreatLevelThreshold.CRITICAL:
            return False, "block"
        if threat_score >= ThreatLevelThreshold.HIGH:
            return True, "challenge"
        if threat_score >= ThreatLevelThreshold.MEDIUM:
            return True, "monitor"
        return True, "allow"

    @classmethod
    async def update_security_statistics(
        cls,
        ip_address: str,
        is_suspicious: bool,  # noqa: FBT001
        threat_score: int,
        alerts: dict[str, Any],
    ) -> None:
        """
        Update security statistics in Redis.

        Args:
            ip_address (str): The IP address.
            is_suspicious (bool): Whether the IP address is suspicious.
            threat_score (int): The threat score.
            alerts (dict): The alerts about the IP address.
        """
        if cls._redis_client:
            try:
                pipe = cls._redis_client.pipeline()
                pipe.incr("ip_security:checks_total")
                if is_suspicious:
                    pipe.incr("ip_security:suspicious_total")
                    pipe.sadd("ip_security:recent_suspicious", ip_address)
                    pipe.expire(
                        "ip_security:recent_suspicious",
                        st.RECENT_SUSPICIOUS_EXPIRE,
                    )
                    pipe.hset(
                        f"ip:{ip_address}:threat",
                        mapping={
                            "score": threat_score,
                            "timestamp": time.time(),
                            "alerts": json.dumps(alerts),
                        },
                    )
                    pipe.expire(f"ip:{ip_address}:threat", st.IP_THREAT_EXPIRES)
                await pipe.execute()
            except Exception as e:  # noqa: BLE001
                msg = f"Failed to record IP security statistics: {e}"
                logger.debug(msg)

    @classmethod
    async def check_ip_security(
        cls,
        ip_address: str,
        *,
        user_id: str | None = None,
        request_path: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        IP security check

        Args:
            ip_address: IP address to check
            user_id: Optional user ID for context-aware checks
            request_path: Optional request path for context-aware checks
            context: Optional additional context

        Returns:
            dict: Dictionary with security assessment:
            {
                "is_suspicious": bool,
                "threat_score": int,
                "alerts": dict,
                "allow": bool,
                "recommendation": str,
                "details": dict
            }
        """
        if not cls._initialized:
            await cls.initialize()

        if not ip_address or ip_address in ["127.0.0.1", "::1", "localhost"]:
            return {
                "is_suspicious": False,
                "threat_score": 0,
                "alerts": {},
                "allow": True,
                "recommendation": "allow",
                "details": {"type": "local"},
            }

        alerts = {}
        threat_score = 0
        details = {
            "ip": ip_address,
            "timestamp": datetime.now(UTC).isoformat(),
            "checks_performed": [],
        }
        context = context or {}

        details["checks_performed"].append("tor")
        if cls._is_tor_exit_node(ip_address):
            alerts["tor_exit_node"] = True
            threat_score += 30
            details["tor"] = True
        else:
            details["tor"] = False

        details["checks_performed"].append("blocklist")
        is_malicious, reason = await cls._is_known_malicious_ip(ip_address)
        if is_malicious:
            alerts["known_malicious_ip"] = reason
            threat_score += 60
            details["blocklisted"] = True
            details["blocklist_reason"] = reason
        else:
            details["blocklisted"] = False

        details["checks_performed"].append("reputation")
        ip_reputation = await cls._check_ip_reputation(ip_address)
        details["reputation"] = ip_reputation

        if ip_reputation.get("is_suspicious"):
            alerts["suspicious_ip_reputation"] = {
                "score": ip_reputation.get("score"),
                "reports": ip_reputation.get("reports"),
            }
            rep_score = min(ip_reputation.get("score", 0) // 10, 40)
            threat_score += rep_score

        if ip_reputation.get("is_known_attacker"):
            alerts["known_attacker"] = ip_reputation.get("score", 0)
            threat_score += 20

        details["checks_performed"].append("geolocation")
        geo_data = await cls._check_geoip_risk(ip_address)
        details["geolocation"] = geo_data

        if geo_data.get("is_high_risk_country"):
            alerts["high_risk_country"] = geo_data.get("country_code")
            threat_score += 15

        if geo_data.get("is_malicious_asn"):
            alerts["known_malicious_datacenter_ip"] = {
                "asn": geo_data.get("asn"),
                "provider": geo_data.get("asn_org"),
            }
            threat_score += 50
            details["known_malicious_datacenter_details"] = {
                "asn": geo_data.get("asn"),
                "provider": geo_data.get("asn_org"),
            }

        if geo_data.get("is_datacenter"):
            # Only treat datacenters as suspicious for sensitive endpoints
            is_sensitive_path = False
            if request_path:
                # TODO: Add more sensitive paths here, maybe with a separate config?
                sensitive_patterns = [
                    "/auth",
                    "/login",
                    "/verify",
                    "/token",
                    "/admin",
                    "/reset",
                ]
                is_sensitive_path = any(
                    pattern in request_path for pattern in sensitive_patterns
                )
            if is_sensitive_path:
                alerts["datacenter_ip"] = {
                    "asn": geo_data.get("asn"),
                    "provider": geo_data.get("asn_org"),
                }
                threat_score += 10
                details["datacenter_details"] = {
                    "asn": geo_data.get("asn"),
                    "provider": geo_data.get("asn_org"),
                }

        user_country = geo_data.get("country_code")
        if user_id and user_id != "unknown" and cls._redis_client and user_country:
            details["checks_performed"].append("user_location_history")
            try:
                # Check user's previous countries
                prev_countries_key = f"user:{user_id}:countries"
                prev_countries = await cls._redis_client.smembers(prev_countries_key)  # type: ignore[call-arg]

                if prev_countries:
                    details["previous_countries"] = list(prev_countries)
                    details["unusual_country"] = False
                    if user_country not in prev_countries:
                        alerts["unusual_country"] = {
                            "current": user_country,
                            "previous": list(prev_countries),
                        }
                        threat_score += 25
                        details["unusual_country"] = True
                pipe = cls._redis_client.pipeline()
                pipe.sadd(prev_countries_key, user_country)
                pipe.expire(prev_countries_key, st.COUNTRY_ACCESS_EXPIRE)
                await pipe.execute()
            except Exception as e:  # noqa: BLE001
                details["user_location_error"] = str(e)
                msg = f"User country check failed: {e}"
                logger.warning(msg)

        if cls._redis_client:
            details["checks_performed"].append("recent_activity")
            try:
                auth_failures_key = f"ip:{ip_address}:auth_failures"
                recent_failures = await cls._redis_client.get(auth_failures_key)
                if recent_failures:
                    failures = int(recent_failures)
                    details["recent_auth_failures"] = failures
                    if failures >= st.AUTH_FAILURES_THRESHOLD:
                        alerts["recent_auth_failures"] = failures
                        threat_score += min(failures * 5, 30)

                security_events_key = f"ip:{ip_address}:security_events"
                recent_events = await cls._redis_client.get(security_events_key)
                if recent_events:
                    events = int(recent_events)
                    details["recent_security_events"] = events
                    if events >= st.SECURITY_EVENTS_THRESHOLD:
                        alerts["recent_security_events"] = events
                        threat_score += min(events * 8, 40)
            except Exception as e:  # noqa: BLE001
                details["recent_activity_error"] = str(e)
                msg = f"Recent activity check failed: {e}"
                logger.warning(msg)

        is_suspicious = threat_score >= ThreatLevelThreshold.MEDIUM
        details["threat_score"] = threat_score
        details["alerts"] = alerts

        await cls.update_security_statistics(
            ip_address,
            is_suspicious,
            threat_score,
            alerts,
        )

        allow, recommendation = cls._assess_threat_score(threat_score)
        return {
            "is_suspicious": is_suspicious,
            "threat_score": threat_score,
            "alerts": alerts,
            "allow": allow,
            "recommendation": recommendation,
            "details": details,
        }

    @classmethod
    async def mark_malicious_ip(
        cls,
        ip_address: str,
        reason: str,
        *,
        ttl: int = 86400,
        severity: str = "medium",
    ) -> bool:
        """
        Mark an IP as malicious in the database

        Args:
            ip_address: The IP to mark
            reason: Reason for marking
            ttl: How long to keep the IP marked (in seconds), default 24 hours
            severity: Severity level (low, medium, high)

        Returns:
            bool: Success status
        """
        if not cls._initialized:
            await cls.initialize()

        if not cls._redis_client:
            logger.warning("Cannot mark malicious IP: Redis not available")
            return False

        try:
            # Validate IP
            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                logger.error(f"Invalid IP address: {ip_address}")
                return False

            pipe = cls._redis_client.pipeline()
            pipe.sadd("flagged_malicious_ips", ip_address)
            info_key = f"flagged_ip:{ip_address}"
            current_time = datetime.now(UTC).isoformat()
            existing_data = await cls._redis_client.hgetall(info_key)
            ip_data = {
                "first_detected": existing_data.get("first_detected", current_time),
                "last_detected": current_time,
                "reason": reason,
                "severity": severity,
                "detection_count": str(
                    int(existing_data.get("detection_count", 0)) + 1,
                ),
            }
            pipe.hset(info_key, mapping=ip_data)
            pipe.expire("flagged_malicious_ips", ttl)
            pipe.expire(info_key, ttl)

            event_id = str(uuid.uuid4())
            event_key = f"ip_event:{event_id}"
            event_data = {
                "timestamp": current_time,
                "ip": ip_address,
                "reason": reason,
                "severity": severity,
                "action": "mark_malicious",
            }
            pipe.hset(event_key, mapping=event_data)
            pipe.expire(event_key, 86400 * 7)  # 7 days
            pipe.lpush("ip_security:recent_events", event_id)
            pipe.ltrim("ip_security:recent_events", 0, 999)  # Keep last 1000 events
            await pipe.execute()
            msg = f"IP {ip_address} marked as malicious: {reason}"
            logger.warning(msg)
        except Exception as e:
            msg = f"Failed to mark malicious IP: {e}"
            logger.exception(msg)
            return False
        return True

    @classmethod
    async def record_auth_failure(
        cls,
        ip_address: str,
        user_id: str | None = None,
    ) -> None:
        """
        Record an authentication failure for an IP address

        Args:
            ip_address: The IP address
            user_id: Optional user ID
        """
        if not cls._redis_client:
            return

        try:
            pipe = cls._redis_client.pipeline()
            auth_failures_key = f"ip:{ip_address}:auth_failures"
            pipe.incr(auth_failures_key)
            pipe.expire(auth_failures_key, 3600)  # 1 hour

            timestamp = datetime.now(UTC).isoformat()
            pipe.lpush(f"ip:{ip_address}:auth_failure_times", timestamp)
            pipe.ltrim(f"ip:{ip_address}:auth_failure_times", 0, 19)  # Keep last 20
            pipe.expire(f"ip:{ip_address}:auth_failure_times", 86400)  # 1 day

            if user_id and user_id != "unknown":
                user_failures_key = f"user:{user_id}:auth_failures"
                pipe.incr(user_failures_key)
                pipe.expire(user_failures_key, 3600)  # 1 hour
                pipe.sadd(f"user:{user_id}:failure_ips", ip_address)
                pipe.expire(f"user:{user_id}:failure_ips", 86400)  # 1 day

            await pipe.execute()

            # Check if we should mark IP as suspicious after multiple failures
            failures = int(await cls._redis_client.get(auth_failures_key) or 0)
            # TODO: variable threshold
            if failures >= 10:  # threshold
                times = await cls._redis_client.lrange(
                    f"ip:{ip_address}:auth_failure_times",
                    0,
                    -1,
                )
                if len(times) >= 2:
                    try:
                        first_time = datetime.fromisoformat(times[-1])
                        last_time = datetime.fromisoformat(times[0])
                        time_span = (last_time - first_time).total_seconds()
                        if (
                            time_span < 300 and failures >= 10
                        ):  # 5 minutes, 10+ failures
                            reason = f"Potential brute force: {failures} failures in {time_span:.1f} seconds"
                            await cls.mark_malicious_ip(
                                ip_address,
                                reason,
                                ttl=3600,
                                severity="medium",
                            )
                    except Exception:  # noqa: BLE001, S110
                        pass
        except Exception as e:  # noqa: BLE001
            msg = f"Failed to record auth failure: {e}"
            logger.debug(msg)

    @classmethod
    async def record_security_event(
        cls,
        ip_address: str,
        event_type: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """
        Record a security event for an IP address

        Args:
            ip_address: The IP address
            event_type: Type of security event
            details: Optional event details
        """
        if not cls._redis_client:
            return

        try:
            pipe = cls._redis_client.pipeline()

            security_events_key = f"ip:{ip_address}:security_events"
            pipe.incr(security_events_key)
            pipe.expire(security_events_key, 3600)  # 1 hour

            event_id = str(uuid.uuid4())
            event_key = f"ip_event:{event_id}"
            event_data = {
                "timestamp": datetime.now(UTC).isoformat(),
                "ip": ip_address,
                "event_type": event_type,
                "details": json.dumps(details or {}),
            }
            pipe.hset(event_key, mapping=event_data)
            pipe.expire(event_key, 86400 * 7)  # 7 days

            # Add to recent events list
            pipe.lpush("ip_security:recent_events", event_id)
            pipe.ltrim("ip_security:recent_events", 0, 999)  # Keep last 1000

            # Also add to IP-specific event list
            pipe.lpush(f"ip:{ip_address}:events", event_id)
            pipe.ltrim(f"ip:{ip_address}:events", 0, 19)  # Keep last 20 per IP
            pipe.expire(f"ip:{ip_address}:events", 86400)  # 1 day

            await pipe.execute()

            events = int(await cls._redis_client.get(security_events_key) or 0)
            # TODO: variable threshold
            if events >= 5:  # threshold
                reason = (
                    f"Multiple security events: {events} events of type {event_type}"
                )
                await cls.mark_malicious_ip(
                    ip_address,
                    reason,
                    ttl=7200,  # 2 hours
                    severity="medium",
                )
        except Exception as e:  # noqa: BLE001
            msg = f"Failed to record security event: {e}"
            logger.debug(msg)

    @classmethod
    async def get_ip_security_stats(cls) -> dict[str, Any]:
        """Get statistics about IP security checks"""
        if not cls._redis_client:
            return {"error": "Redis not available"}

        try:
            total_checks = int(
                await cls._redis_client.get("ip_security:checks_total") or 0,
            )
            suspicious_total = int(
                await cls._redis_client.get("ip_security:suspicious_total") or 0,
            )
            recent_suspicious = await cls._redis_client.smembers(
                "ip_security:recent_suspicious",
            )

            recent_event_ids = await cls._redis_client.lrange(
                "ip_security:recent_events",
                0,
                9,
            )
            recent_events = []
            for event_id in recent_event_ids:
                event_data = await cls._redis_client.hgetall(f"ip_event:{event_id}")
                if event_data:
                    try:
                        if "details" in event_data:
                            event_data["details"] = json.loads(event_data["details"])
                    except json.JSONDecodeError:
                        pass
                    recent_events.append(event_data)
        except Exception as e:
            msg = f"Failed to get IP security stats: {e}"
            logger.exception(msg)
            return {"error": str(e)}
        return {
            "total_checks": total_checks,
            "suspicious_total": suspicious_total,
            "suspicious_rate": round(suspicious_total / total_checks * 100, 2)
            if total_checks
            else 0,
            "recent_suspicious_count": len(recent_suspicious),
            "recent_suspicious": list(recent_suspicious),
            "recent_events": recent_events,
            "updated_at": datetime.now(UTC).isoformat(),
        }
