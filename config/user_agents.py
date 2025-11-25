"""
Advanced User Agent Rotation Module
Provides sophisticated user agent management with rotation strategies and filtering capabilities.
"""

import random
import time
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum
import json
import hashlib
from collections import defaultdict, deque
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RotationStrategy(Enum):
    """Strategies for user agent rotation"""
    RANDOM = "random"
    ROUND_ROBIN = "round_robin"
    WEIGHTED = "weighted"
    TIME_BASED = "time_based"

class Platform(Enum):
    """Platform categories"""
    WINDOWS = "windows"
    MAC = "mac"
    LINUX = "linux"
    ANDROID = "android"
    IOS = "ios"
    UNKNOWN = "unknown"

class Browser(Enum):
    """Browser categories"""
    CHROME = "chrome"
    FIREFOX = "firefox"
    SAFARI = "safari"
    EDGE = "edge"
    IE = "ie"
    UNKNOWN = "unknown"

@dataclass
class UserAgentMetadata:
    """Metadata for user agent analysis"""
    platform: Platform
    browser: Browser
    version: str
    is_mobile: bool
    is_tablet: bool
    is_desktop: bool
    raw_ua: str

class AdvancedUserAgentRotator:
    """
    Advanced user agent rotator with multiple rotation strategies,
    usage tracking, and filtering capabilities.
    """
    
    # Comprehensive user agent list
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.198 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
        "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.65 Mobile Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; U; Android 4.4.2; en-US; GT-I9505 Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
        "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/114.0",
        "Mozilla/5.0 (iPad; CPU OS 15_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/111.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15",
        "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
        "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.137 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
        "Mozilla/5.0 (Linux; Android 9; Redmi Note 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.126 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0",
        "Mozilla/5.0 (Linux; U; Android 4.2.2; en-us; GT-P5113 Build/JDQ39) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Safari/534.30",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19577",
        "Mozilla/5.0 (X11) AppleWebKit/62.41 (KHTML, like Gecko) Edge/17.10859 Safari/452.6",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14931",
        "Chrome (AppleWebKit/537.1; Chrome50.0; Windows NT 6.3) AppleWebKit/537.36 (KHTML like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.9200",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
        "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.16) Gecko/20120421 Firefox/11.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:11.0) Gecko Firefox/11.0",
        "Mozilla/5.0 (Windows NT 6.1; U;WOW64; de;rv:11.0) Gecko Firefox/11.0",
        "Mozilla/5.0 (Windows NT 5.1; rv:11.0) Gecko Firefox/11.0",
        "Mozilla/6.0 (Macintosh; I; Intel Mac OS X 11_7_9; de-LI; rv:1.9b4) Gecko/2012010317 Firefox/10.0a4",
        "Mozilla/5.0 (Macintosh; I; Intel Mac OS X 11_7_9; de-LI; rv:1.9b4) Gecko/2012010317 Firefox/10.0a4",
        "Mozilla/5.0 (X11; Mageia; Linux x86_64; rv:10.0.9) Gecko/20100101 Firefox/10.0.9",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:9.0a2) Gecko/20111101 Firefox/9.0a2",
        "Mozilla/5.0 (Windows NT 6.2; rv:9.0.1) Gecko/20100101 Firefox/9.0.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:9.0) Gecko/20100101 Firefox/9.0",
        "Mozilla/5.0 (Windows NT 5.1; rv:8.0; en_us) Gecko/20100101 Firefox/8.0",
        "Mozilla/5.0 (Windows NT 6.1; rv:6.0) Gecko/20100101 Firefox/7.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0a2) Gecko/20110613 Firefox/6.0a2",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0a2) Gecko/20110612 Firefox/6.0a2",
        "Mozilla/5.0 (X11; Linux i686; rv:6.0) Gecko/20100101 Firefox/6.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.90 Safari/537.36",
        "Mozilla/5.0 (X11; NetBSD) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36",
        "Mozilla/5.0 (X11; CrOS i686 3912.101.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.60 Safari/537.17",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1309.0 Safari/537.17",
        "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.15 (KHTML, like Gecko) Chrome/24.0.1295.0 Safari/537.15",
        "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.14 (KHTML, like Gecko) Chrome/24.0.1292.0 Safari/537.14",
        "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.13 (KHTML, like Gecko) Chrome/24.0.1290.1 Safari/537.13",
        "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.13 (KHTML, like Gecko) Chrome/24.0.1290.1 Safari/537.13"
    ]

    def __init__(
        self,
        strategy: RotationStrategy = RotationStrategy.RANDOM,
        custom_user_agents: Optional[List[str]] = None,
        enable_usage_tracking: bool = True,
        max_history_size: int = 1000
    ):
        """
        Initialize the user agent rotator.
        
        Args:
            strategy: Rotation strategy to use
            custom_user_agents: Additional custom user agents
            enable_usage_tracking: Track usage statistics
            max_history_size: Maximum size of usage history
        """
        self.strategy = strategy
        self.user_agents = self.USER_AGENTS.copy()
        
        if custom_user_agents:
            self.user_agents.extend(custom_user_agents)
        
        self.enable_usage_tracking = enable_usage_tracking
        self.max_history_size = max_history_size
        
        # Initialize rotation state
        self.current_index = 0
        self.usage_count = defaultdict(int)
        self.usage_history = deque(maxlen=max_history_size)
        self.last_used = {}
        
        # Pre-analyze all user agents
        self.ua_metadata = {}
        for ua in self.user_agents:
            self.ua_metadata[ua] = self._analyze_user_agent(ua)
        
        logger.info(f"Initialized UserAgentRotator with {len(self.user_agents)} user agents")

    def _analyze_user_agent(self, user_agent: str) -> UserAgentMetadata:
        """Analyze user agent string and extract metadata"""
        ua_lower = user_agent.lower()
        
        # Detect platform
        if "windows" in ua_lower:
            platform = Platform.WINDOWS
        elif "mac" in ua_lower:
            platform = Platform.MAC
        elif "linux" in ua_lower or "ubuntu" in ua_lower or "fedora" in ua_lower:
            platform = Platform.LINUX
        elif "android" in ua_lower:
            platform = Platform.ANDROID
        elif "iphone" in ua_lower or "ipad" in ua_lower or "ios" in ua_lower:
            platform = Platform.IOS
        else:
            platform = Platform.UNKNOWN
        
        # Detect browser
        if "chrome" in ua_lower and "edge" not in ua_lower:
            browser = Browser.CHROME
        elif "firefox" in ua_lower:
            browser = Browser.FIREFOX
        elif "safari" in ua_lower and "chrome" not in ua_lower:
            browser = Browser.SAFARI
        elif "edge" in ua_lower:
            browser = Browser.EDGE
        elif "msie" in ua_lower or "trident" in ua_lower:
            browser = Browser.IE
        else:
            browser = Browser.UNKNOWN
        
        # Detect device type
        is_mobile = any(x in ua_lower for x in ["mobile", "android", "iphone"])
        is_tablet = "ipad" in ua_lower
        is_desktop = not (is_mobile or is_tablet)
        
        # Extract version (simplified)
        version = "unknown"
        if browser == Browser.CHROME and "chrome/" in ua_lower:
            version = ua_lower.split("chrome/")[1].split(" ")[0].split(".")[0]
        elif browser == Browser.FIREFOX and "firefox/" in ua_lower:
            version = ua_lower.split("firefox/")[1].split(" ")[0].split(".")[0]
        
        return UserAgentMetadata(
            platform=platform,
            browser=browser,
            version=version,
            is_mobile=is_mobile,
            is_tablet=is_tablet,
            is_desktop=is_desktop,
            raw_ua=user_agent
        )

    def get_random(self) -> str:
        """Get a random user agent"""
        return random.choice(self.user_agents)

    def get_round_robin(self) -> str:
        """Get user agent in round-robin fashion"""
        ua = self.user_agents[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.user_agents)
        return ua

    def get_weighted(self) -> str:
        """Get user agent with weighted random selection based on usage"""
        if not self.usage_count:
            return self.get_random()
        
        # Prefer less used user agents
        min_usage = min(self.usage_count.values())
        weights = [1 / (self.usage_count.get(ua, min_usage) + 1) for ua in self.user_agents]
        
        return random.choices(self.user_agents, weights=weights)[0]

    def get_time_based(self) -> str:
        """Get user agent based on time of day"""
        current_hour = time.localtime().tm_hour
        
        # Different patterns for different times of day
        if 6 <= current_hour < 12:  # Morning
            preferred_browsers = [Browser.CHROME, Browser.SAFARI]
        elif 12 <= current_hour < 18:  # Afternoon
            preferred_browsers = [Browser.CHROME, Browser.FIREFOX]
        else:  # Evening/Night
            preferred_browsers = [Browser.FIREFOX, Browser.CHROME, Browser.SAFARI]
        
        # Filter user agents by preferred browsers
        filtered_agents = [
            ua for ua in self.user_agents 
            if self.ua_metadata[ua].browser in preferred_browsers
        ]
        
        return random.choice(filtered_agents) if filtered_agents else self.get_random()

    def get_user_agent(self, strategy: Optional[RotationStrategy] = None) -> str:
        """
        Get a user agent based on the specified strategy.
        
        Args:
            strategy: Override the default strategy for this call
            
        Returns:
            User agent string
        """
        actual_strategy = strategy or self.strategy
        
        if actual_strategy == RotationStrategy.RANDOM:
            user_agent = self.get_random()
        elif actual_strategy == RotationStrategy.ROUND_ROBIN:
            user_agent = self.get_round_robin()
        elif actual_strategy == RotationStrategy.WEIGHTED:
            user_agent = self.get_weighted()
        elif actual_strategy == RotationStrategy.TIME_BASED:
            user_agent = self.get_time_based()
        else:
            user_agent = self.get_random()
        
        # Track usage if enabled
        if self.enable_usage_tracking:
            self._track_usage(user_agent)
        
        return user_agent

    def _track_usage(self, user_agent: str):
        """Track usage statistics for a user agent"""
        self.usage_count[user_agent] += 1
        self.last_used[user_agent] = time.time()
        self.usage_history.append({
            'user_agent': user_agent,
            'timestamp': time.time(),
            'metadata': self.ua_metadata[user_agent]
        })

    def filter_user_agents(
        self,
        platform: Optional[Platform] = None,
        browser: Optional[Browser] = None,
        mobile_only: bool = False,
        desktop_only: bool = False,
        min_version: Optional[str] = None
    ) -> List[str]:
        """
        Filter user agents based on criteria.
        
        Args:
            platform: Filter by platform
            browser: Filter by browser
            mobile_only: Only return mobile user agents
            desktop_only: Only return desktop user agents
            min_version: Minimum browser version (simplified)
            
        Returns:
            List of filtered user agents
        """
        filtered = []
        
        for ua in self.user_agents:
            metadata = self.ua_metadata[ua]
            
            # Apply filters
            if platform and metadata.platform != platform:
                continue
            if browser and metadata.browser != browser:
                continue
            if mobile_only and not metadata.is_mobile:
                continue
            if desktop_only and not metadata.is_desktop:
                continue
            if min_version and metadata.version != "unknown":
                try:
                    if int(metadata.version) < int(min_version):
                        continue
                except (ValueError, TypeError):
                    pass
            
            filtered.append(ua)
        
        return filtered

    def get_usage_statistics(self) -> Dict[str, Any]:
        """Get comprehensive usage statistics"""
        total_requests = sum(self.usage_count.values())
        
        # Browser distribution
        browser_dist = defaultdict(int)
        platform_dist = defaultdict(int)
        device_dist = defaultdict(int)
        
        for ua, count in self.usage_count.items():
            metadata = self.ua_metadata[ua]
            browser_dist[metadata.browser.value] += count
            platform_dist[metadata.platform.value] += count
            
            if metadata.is_mobile:
                device_dist['mobile'] += count
            elif metadata.is_tablet:
                device_dist['tablet'] += count
            else:
                device_dist['desktop'] += count
        
        return {
            'total_user_agents': len(self.user_agents),
            'total_requests': total_requests,
            'most_used': max(self.usage_count.items(), key=lambda x: x[1]) if self.usage_count else None,
            'least_used': min(self.usage_count.items(), key=lambda x: x[1]) if self.usage_count else None,
            'browser_distribution': dict(browser_dist),
            'platform_distribution': dict(platform_dist),
            'device_distribution': dict(device_dist),
            'strategy': self.strategy.value
        }

    def add_user_agent(self, user_agent: str):
        """Add a custom user agent"""
        if user_agent not in self.user_agents:
            self.user_agents.append(user_agent)
            self.ua_metadata[user_agent] = self._analyze_user_agent(user_agent)
            logger.info(f"Added new user agent: {user_agent[:50]}...")

    def remove_user_agent(self, user_agent: str):
        """Remove a user agent"""
        if user_agent in self.user_agents:
            self.user_agents.remove(user_agent)
            self.ua_metadata.pop(user_agent, None)
            self.usage_count.pop(user_agent, None)
            logger.info(f"Removed user agent: {user_agent[:50]}...")

    def export_user_agents(self, filename: str):
        """Export user agents to a JSON file"""
        data = {
            'user_agents': self.user_agents,
            'metadata': {ua: vars(meta) for ua, meta in self.ua_metadata.items()},
            'statistics': self.get_usage_statistics()
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"User agents exported to {filename}")

    def import_user_agents(self, filename: str):
        """Import user agents from a JSON file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            self.user_agents = data.get('user_agents', [])
            self.ua_metadata = {}
            
            for ua, meta_dict in data.get('metadata', {}).items():
                self.ua_metadata[ua] = UserAgentMetadata(**meta_dict)
            
            logger.info(f"User agents imported from {filename}")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Failed to import user agents: {e}")

# Convenience functions for quick usage
_default_rotator = None

def get_default_rotator() -> AdvancedUserAgentRotator:
    """Get the default user agent rotator instance"""
    global _default_rotator
    if _default_rotator is None:
        _default_rotator = AdvancedUserAgentRotator()
    return _default_rotator

def get_user_agent(strategy: Optional[RotationStrategy] = None) -> str:
    """Quick function to get a user agent using default rotator"""
    return get_default_rotator().get_user_agent(strategy)

def get_random_user_agent() -> str:
    """Quick function to get a random user agent"""
    return get_default_rotator().get_random()
