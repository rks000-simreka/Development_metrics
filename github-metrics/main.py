#!/usr/bin/env python3
"""
Enhanced GitHub Organization Metrics Scanner
Collects development metrics with improved performance, security, and reliability
FIXED: Accurate line counting for additions/deletions
"""

import os
import re
import json
import csv
import pickle
import hashlib
import getpass
import asyncio
import aiohttp
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Pattern, Set, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict, Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import time
import itertools
from functools import wraps
import logging
from enum import Enum

import numpy as np
import requests
from dotenv import load_dotenv
try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False
    print("Warning: keyring not available. Using environment variables for token.")

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('github_metrics.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ============================================================================
# EXCEPTIONS
# ============================================================================

class GitHubAPIError(Exception):
    """Base exception for GitHub API errors"""
    pass

class RateLimitError(GitHubAPIError):
    """Raised when rate limit is exceeded"""
    pass

class TokenValidationError(GitHubAPIError):
    """Raised when token validation fails"""
    pass

class ConfigurationError(Exception):
    """Raised when configuration is invalid"""
    pass


# ============================================================================
# DECORATORS
# ============================================================================

def with_retry(max_attempts=3, backoff_factor=2, exceptions=(Exception,)):
    """Decorator for retrying failed operations with exponential backoff"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        wait_time = backoff_factor ** attempt
                        logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {wait_time}s...")
                        time.sleep(wait_time)
                    else:
                        logger.error(f"All {max_attempts} attempts failed")
            raise last_exception
        return wrapper
    return decorator


# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class DeveloperMetrics:
    """Stores metrics for individual developers with optimized data structures"""
    username: str
    commits_per_week: Counter = field(default_factory=Counter)
    lines_stats: np.ndarray = field(default_factory=lambda: np.zeros(2, dtype=np.int64))  # [added, deleted]
    prs_created: int = 0
    prs_merged: int = 0
    pr_turnarounds: List[float] = field(default_factory=list)
    review_comments: int = 0
    prs_reviewed: int = 0
    active_repos: Set[str] = field(default_factory=set)
    last_updated: datetime = field(default_factory=datetime.now)
    
    @property
    def lines_added(self) -> int:
        return int(self.lines_stats[0])
    
    @property
    def lines_deleted(self) -> int:
        return int(self.lines_stats[1])
    
    @property
    def net_lines(self) -> int:
        return int(self.lines_stats[0] - self.lines_stats[1])
    
    @property
    def avg_pr_turnaround_hours(self) -> float:
        return float(np.mean(self.pr_turnarounds)) if self.pr_turnarounds else 0.0
    
    @property
    def total_commits(self) -> int:
        return sum(self.commits_per_week.values())
    
    def add_lines(self, added: int, deleted: int):
        """Thread-safe line addition"""
        self.lines_stats[0] += added
        self.lines_stats[1] += deleted
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for export"""
        return {
            'username': self.username,
            'total_commits': self.total_commits,
            'commits_per_week': dict(self.commits_per_week),
            'lines_added': self.lines_added,
            'lines_deleted': self.lines_deleted,
            'net_lines': self.net_lines,
            'prs_created': self.prs_created,
            'prs_merged': self.prs_merged,
            'avg_pr_turnaround_hours': self.avg_pr_turnaround_hours,
            'review_comments': self.review_comments,
            'prs_reviewed': self.prs_reviewed,
            'active_repos': list(self.active_repos),
            'last_updated': self.last_updated.isoformat()
        }


# ============================================================================
# SECURITY & VALIDATION
# ============================================================================

class InputValidator:
    """Input validation for security"""
    ORG_NAME_PATTERN: Pattern = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$')
    REPO_NAME_PATTERN: Pattern = re.compile(r'^[a-zA-Z0-9._-]+$')
    
    @classmethod
    def validate_org_name(cls, org_name: str) -> str:
        if not org_name or not cls.ORG_NAME_PATTERN.match(org_name):
            raise ValueError(f"Invalid organization name: {org_name}")
        return org_name
    
    @classmethod
    def validate_repo_name(cls, repo_name: str) -> str:
        if not repo_name or not cls.REPO_NAME_PATTERN.match(repo_name):
            raise ValueError(f"Invalid repository name: {repo_name}")
        return repo_name
    
    @classmethod
    def sanitize_filename(cls, filename: str) -> str:
        """Remove potentially dangerous characters from filenames"""
        return re.sub(r'[^a-zA-Z0-9._-]', '_', filename)


class SecureConfig:
    """Secure configuration management"""
    def __init__(self):
        self.service_name = "github_metrics_scanner"
        self._token_cache = None
    
    def get_token(self) -> str:
        """Get token from secure storage or environment"""
        if self._token_cache:
            return self._token_cache
        
        # Try keyring first if available
        if KEYRING_AVAILABLE:
            try:
                token = keyring.get_password(self.service_name, "github_token")
                if token:
                    self._token_cache = token
                    return token
            except Exception as e:
                logger.warning(f"Keyring access failed: {e}")
        
        # Fall back to environment variable
        token = os.getenv('GITHUB_TOKEN')
        if token:
            self._token_cache = token
            return token
        
        # Prompt for token
        token = getpass.getpass("Enter GitHub token: ")
        if KEYRING_AVAILABLE:
            try:
                keyring.set_password(self.service_name, "github_token", token)
            except Exception as e:
                logger.warning(f"Failed to save token to keyring: {e}")
        
        self._token_cache = token
        return token
    
    def validate_token(self, token: str) -> bool:
        """Validate GitHub token format"""
        if not token:
            return False
        
        valid_prefixes = ('ghp_', 'github_pat_', 'gho_', 'ghs_', 'ghr_')
        return any(token.startswith(prefix) for prefix in valid_prefixes)


# ============================================================================
# RATE LIMITING
# ============================================================================

class RateLimiter:
    """Advanced rate limiting with exponential backoff"""
    def __init__(self, max_requests_per_second: int = 10):
        self.max_requests_per_second = max_requests_per_second
        self.request_times = deque(maxlen=max_requests_per_second)
        self.lock = Lock()
        self.graphql_remaining = 5000
        self.graphql_reset = None
    
    def wait_if_needed(self):
        """Implement rate limiting with exponential backoff"""
        with self.lock:
            now = time.time()
            if len(self.request_times) == self.max_requests_per_second:
                time_passed = now - self.request_times[0]
                if time_passed < 1:
                    sleep_time = (1 - time_passed) * 1.1  # Add 10% buffer
                    time.sleep(sleep_time)
            self.request_times.append(time.time())
    
    def update_graphql_limits(self, remaining: int, reset_at: str):
        """Update GraphQL rate limit info"""
        self.graphql_remaining = remaining
        self.graphql_reset = reset_at
    
    def wait_for_graphql_reset(self):
        """Wait for GraphQL rate limit to reset"""
        if self.graphql_reset:
            reset_time_str = self.graphql_reset.replace('Z', '+00:00')
            reset_time = datetime.fromisoformat(reset_time_str)
            current_time = datetime.now(timezone.utc)
            wait_time = (reset_time - current_time).total_seconds() + 10
            if wait_time > 0:
                logger.info(f"Rate limit reached. Waiting {wait_time:.0f} seconds...")
                time.sleep(wait_time)


# ============================================================================
# CACHE MANAGER
# ============================================================================

class CacheManager:
    """Manages caching of API responses"""
    def __init__(self, cache_dir: str = ".github_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.lock = Lock()
    
    def _get_cache_key(self, key: str) -> str:
        """Generate cache key hash"""
        return hashlib.md5(key.encode()).hexdigest()
    
    def get_or_fetch(self, key: str, fetch_func, ttl_hours: float = 24) -> Any:
        """Get from cache or fetch if expired"""
        with self.lock:
            cache_key = self._get_cache_key(key)
            cache_file = self.cache_dir / f"{cache_key}.pkl"
            
            # Check if cache exists and is valid
            if cache_file.exists():
                mod_time = datetime.fromtimestamp(cache_file.stat().st_mtime)
                if datetime.now() - mod_time < timedelta(hours=ttl_hours):
                    try:
                        with open(cache_file, 'rb') as f:
                            logger.debug(f"Cache hit for {key}")
                            return pickle.load(f)
                    except Exception as e:
                        logger.warning(f"Cache read failed for {key}: {e}")
            
            # Fetch new data
            logger.debug(f"Cache miss for {key}, fetching...")
            data = fetch_func()
            
            # Save to cache
            try:
                with open(cache_file, 'wb') as f:
                    pickle.dump(data, f)
            except Exception as e:
                logger.warning(f"Cache write failed for {key}: {e}")
            
            return data
    
    def clear_cache(self):
        """Clear all cache files"""
        for cache_file in self.cache_dir.glob("*.pkl"):
            cache_file.unlink()
        logger.info("Cache cleared")


# ============================================================================
# CSV MANAGER
# ============================================================================

class CSVManager:
    """Manages CSV output with append mode support"""
    def __init__(self, append_mode: bool = False, base_filename: str = "github_metrics", include_all_users: bool = True):
        self.append_mode = append_mode
        self.base_filename = base_filename
        self.include_all_users = include_all_users  # New flag to include all users
        self.fieldnames = [
            'timestamp',
            'username',
            'total_commits',
            'avg_commits_per_week',
            'lines_added',
            'lines_deleted',
            'net_lines',
            'prs_created',
            'prs_merged',
            'avg_pr_turnaround_hours',
            'review_comments',
            'prs_reviewed',
            'active_repos_count',
            'active_repos',
            'analysis_period_weeks',
            'start_date',
            'end_date'
        ]
    
    def get_filename(self) -> str:
        """Get appropriate filename based on mode"""
        if self.append_mode:
            return f"{self.base_filename}_continuous.csv"
        else:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            return f"{self.base_filename}_{timestamp}.csv"
    
    def export_metrics(self, metrics: Dict[str, DeveloperMetrics], 
                      weeks_analyzed: int, start_date: datetime, end_date: datetime):
        """Export metrics to CSV with append support"""
        filename = self.get_filename()
        file_exists = Path(filename).exists()
        
        mode = 'a' if self.append_mode and file_exists else 'w'
        
        with open(filename, mode, newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames)
            
            # Write header if new file or not in append mode
            if not (self.append_mode and file_exists):
                writer.writeheader()
            
            timestamp = datetime.now(timezone.utc).isoformat()
            
            # Sort by total commits for consistent ordering
            sorted_metrics = sorted(
                metrics.items(),
                key=lambda x: x[1].total_commits,
                reverse=True
            )
            
            rows_written = 0
            for username, metric in sorted_metrics:
                # Include all users if flag is set, or only users with activity
                if not self.include_all_users:
                    if metric.total_commits == 0 and metric.prs_created == 0 and metric.prs_reviewed == 0:
                        continue
                
                avg_commits = metric.total_commits / weeks_analyzed if weeks_analyzed > 0 else 0
                
                row = {
                    'timestamp': timestamp,
                    'username': username,
                    'total_commits': metric.total_commits,
                    'avg_commits_per_week': f"{avg_commits:.2f}",
                    'lines_added': metric.lines_added,
                    'lines_deleted': metric.lines_deleted,
                    'net_lines': metric.net_lines,
                    'prs_created': metric.prs_created,
                    'prs_merged': metric.prs_merged,
                    'avg_pr_turnaround_hours': f"{metric.avg_pr_turnaround_hours:.2f}",
                    'review_comments': metric.review_comments,
                    'prs_reviewed': metric.prs_reviewed,
                    'active_repos_count': len(metric.active_repos),
                    'active_repos': ', '.join(sorted(list(metric.active_repos)[:10])),  # Limit to 10 repos
                    'analysis_period_weeks': weeks_analyzed,
                    'start_date': start_date.date().isoformat(),
                    'end_date': end_date.date().isoformat()
                }
                writer.writerow(row)
                rows_written += 1
        
        action = "Appended to" if (self.append_mode and file_exists) else "Created"
        logger.info(f"✅ {action} {filename} - {rows_written} total users (including inactive)")
        return filename


# ============================================================================
# MAIN COLLECTOR
# ============================================================================

class GitHubMetricsCollector:
    """Enhanced GitHub metrics collector with parallel processing"""
    
    def __init__(self):
        # Configuration
        self.config = SecureConfig()
        self.token = self.config.get_token()
        
        if not self.config.validate_token(self.token):
            raise TokenValidationError("Invalid GitHub token format")
        
        self.org_name = os.getenv('GITHUB_ORG')
        if not self.org_name:
            raise ConfigurationError("GITHUB_ORG not set in environment")
        
        self.org_name = InputValidator.validate_org_name(self.org_name)
        
        # API setup
        self.api_url = 'https://api.github.com/graphql'
        self.headers = {
            'Authorization': f'bearer {self.token}',
            'Content-Type': 'application/json'
        }
        
        # Components
        self.rate_limiter = RateLimiter()
        self.cache_manager = CacheManager()
        
        # Include all users in CSV (even with 0 metrics)
        include_all = os.getenv('INCLUDE_ALL_USERS', 'true').lower() == 'true'
        
        self.csv_manager = CSVManager(
            append_mode=os.getenv('APPEND_MODE', 'false').lower() == 'true',
            base_filename=os.getenv('CSV_FILENAME', 'github_metrics'),
            include_all_users=include_all
        )
        
        # Thread safety
        self.metrics: Dict[str, DeveloperMetrics] = {}
        self.metrics_lock = Lock()
        
        # Time range configuration
        self.weeks_to_analyze = int(os.getenv('WEEKS_TO_ANALYZE', '12'))
        self.end_date = datetime.now(timezone.utc)
        self.start_date = self.end_date - timedelta(weeks=self.weeks_to_analyze)
        
        # Performance settings
        self.max_workers = int(os.getenv('MAX_WORKERS', '5'))
        self.batch_size = int(os.getenv('BATCH_SIZE', '10'))
        
        # Validate token permissions
        self._validate_token_permissions()
        
        logger.info(f"Initialized collector for org: {self.org_name}")
        logger.info(f"Append mode: {self.csv_manager.append_mode}")
        logger.info(f"Include all users: {self.csv_manager.include_all_users}")
        logger.info(f"Period: {self.start_date.date()} to {self.end_date.date()}")
    
    @with_retry(max_attempts=3, exceptions=(requests.RequestException, RateLimitError))
    def execute_query(self, query: str, variables: Dict = None) -> Dict:
        """Execute GraphQL query with rate limiting and retry logic"""
        self.rate_limiter.wait_if_needed()
        
        # Check GraphQL rate limit
        if self.rate_limiter.graphql_remaining < 100:
            self.rate_limiter.wait_for_graphql_reset()
        
        payload = {'query': query}
        if variables:
            payload['variables'] = variables
        
        response = requests.post(
            self.api_url,
            headers=self.headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # Update rate limit info
            self._update_rate_limits(data)
            
            # Check for errors
            if 'errors' in data:
                for error in data['errors']:
                    if 'rate limit' in str(error).lower():
                        raise RateLimitError(f"Rate limit error: {error}")
                    logger.warning(f"GraphQL error: {error}")
            
            return data
        elif response.status_code == 403:
            raise RateLimitError(f"Rate limit exceeded: {response.text}")
        else:
            raise GitHubAPIError(f"Query failed with status {response.status_code}: {response.text}")
    
    def _update_rate_limits(self, data: Dict):
        """Update rate limit information from response"""
        if 'data' in data and data['data']:
            # Check for rateLimit field in the response
            if 'rateLimit' in data['data']:
                rate_limit = data['data']['rateLimit']
                self.rate_limiter.update_graphql_limits(
                    rate_limit['remaining'],
                    rate_limit.get('resetAt')
                )
            # Also check nested structures
            for key, value in data['data'].items():
                if isinstance(value, dict) and 'rateLimit' in value:
                    rate_limit = value['rateLimit']
                    self.rate_limiter.update_graphql_limits(
                        rate_limit['remaining'],
                        rate_limit.get('resetAt')
                    )
                    break
    
    def _validate_token_permissions(self):
        """Validate that token has required permissions"""
        query = """
        query {
            viewer {
                login
            }
            organization(login: "%s") {
                name
                membersWithRole(first: 1) {
                    totalCount
                }
                repositories(first: 1) {
                    totalCount
                }
            }
            rateLimit {
                remaining
                resetAt
            }
        }
        """ % self.org_name
        
        try:
            result = self.execute_query(query)
            if 'data' not in result or not result['data'].get('organization'):
                raise TokenValidationError(f"Token doesn't have access to organization {self.org_name}")
            
            logger.info(f"Token validated. User: {result['data']['viewer']['login']}")
        except Exception as e:
            raise TokenValidationError(f"Token validation failed: {e}")
    
    def get_organization_members(self) -> List[str]:
        """Fetch all members of the organization with caching"""
        cache_key = f"members_{self.org_name}"
        
        def fetch_members():
            query = """
            query($org: String!, $cursor: String) {
                organization(login: $org) {
                    membersWithRole(first: 100, after: $cursor) {
                        edges {
                            node {
                                login
                            }
                        }
                        pageInfo {
                            endCursor
                            hasNextPage
                        }
                    }
                }
                rateLimit {
                    remaining
                    resetAt
                }
            }
            """
            
            members = []
            cursor = None
            
            while True:
                variables = {'org': self.org_name, 'cursor': cursor}
                result = self.execute_query(query, variables)
                
                if 'data' not in result or not result['data'].get('organization'):
                    break
                
                edges = result['data']['organization']['membersWithRole'].get('edges', [])
                members.extend([edge['node']['login'] for edge in edges])
                
                page_info = result['data']['organization']['membersWithRole']['pageInfo']
                if not page_info['hasNextPage']:
                    break
                cursor = page_info['endCursor']
            
            return members
        
        members = self.cache_manager.get_or_fetch(cache_key, fetch_members, ttl_hours=24)
        logger.info(f"Found {len(members)} organization members")
        return members
    
    def get_organization_repos(self) -> List[Dict]:
        """Fetch all repositories in the organization with caching"""
        cache_key = f"repos_{self.org_name}_{self.start_date.date()}"
        
        def fetch_repos():
            query = """
            query($org: String!, $cursor: String) {
                organization(login: $org) {
                    repositories(first: 100, after: $cursor, orderBy: {field: PUSHED_AT, direction: DESC}) {
                        edges {
                            node {
                                id
                                name
                                nameWithOwner
                                isArchived
                                isEmpty
                                pushedAt
                                defaultBranchRef {
                                    name
                                }
                            }
                        }
                        pageInfo {
                            endCursor
                            hasNextPage
                        }
                    }
                }
                rateLimit {
                    remaining
                    resetAt
                }
            }
            """
            
            repos = []
            cursor = None
            
            while True:
                variables = {'org': self.org_name, 'cursor': cursor}
                result = self.execute_query(query, variables)
                
                if 'data' not in result or not result['data'].get('organization'):
                    break
                
                edges = result['data']['organization']['repositories'].get('edges', [])
                for edge in edges:
                    repo = edge['node']
                    
                    # Skip archived or empty repos
                    if repo['isArchived'] or repo['isEmpty']:
                        continue
                    
                    repos.append({
                        'id': repo['id'],
                        'name': repo['name'],
                        'nameWithOwner': repo['nameWithOwner'],
                        'defaultBranch': repo['defaultBranchRef']['name'] if repo['defaultBranchRef'] else 'main'
                    })
                
                page_info = result['data']['organization']['repositories']['pageInfo']
                if not page_info['hasNextPage']:
                    break
                cursor = page_info['endCursor']
            
            return repos
        
        repos = self.cache_manager.get_or_fetch(cache_key, fetch_repos, ttl_hours=6)
        logger.info(f"Found {len(repos)} repositories")
        return repos
    
    def collect_repo_commits_rest_api(self, repo: Dict, members: List[str]) -> Dict[str, DeveloperMetrics]:
        """Collect commits using REST API with detailed statistics"""
        owner, name = repo['nameWithOwner'].split('/')
        members_set = set(members)
        all_metrics = defaultdict(lambda: DeveloperMetrics(username=""))
        
        # REST API endpoint
        rest_url = f"https://api.github.com/repos/{owner}/{name}/commits"
        
        # Headers for REST API
        rest_headers = {
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        params = {
            'since': self.start_date.isoformat(),
            'until': self.end_date.isoformat(),
            'per_page': 100
        }
        
        page = 1
        while page <= 10:  # Limit pages to avoid excessive API calls
            params['page'] = page
            
            try:
                response = requests.get(rest_url, headers=rest_headers, params=params, timeout=30)
                
                if response.status_code != 200:
                    break
                
                commits = response.json()
                if not commits:
                    break
                
                # Process each commit to get detailed stats
                for commit_data in commits:
                    # Extract author info
                    author = None
                    
                    if commit_data.get('author') and commit_data['author'].get('login'):
                        author = commit_data['author']['login']
                    elif commit_data.get('commit', {}).get('author', {}).get('email'):
                        email = commit_data['commit']['author']['email'].lower()
                        # Try to match by email
                        for member in members:
                            if member.lower() in email or email.startswith(f"{member.lower()}@"):
                                author = member
                                break
                    
                    if not author or author not in members_set:
                        continue
                    
                    if author not in all_metrics:
                        all_metrics[author] = DeveloperMetrics(username=author)
                    
                    # Get commit date
                    commit_date_str = commit_data['commit']['author']['date']
                    commit_date = datetime.fromisoformat(commit_date_str.replace('Z', '+00:00'))
                    week_key = commit_date.strftime('%Y-%W')
                    
                    # Update metrics
                    all_metrics[author].commits_per_week[week_key] += 1
                    all_metrics[author].active_repos.add(repo['name'])
                    
                    # Get detailed commit info with stats
                    commit_detail_url = f"https://api.github.com/repos/{owner}/{name}/commits/{commit_data['sha']}"
                    try:
                        detail_response = requests.get(commit_detail_url, headers=rest_headers, timeout=30)
                        if detail_response.status_code == 200:
                            detail_data = detail_response.json()
                            if detail_data.get('stats'):
                                all_metrics[author].add_lines(
                                    detail_data['stats'].get('additions', 0),
                                    detail_data['stats'].get('deletions', 0)
                                )
                    except Exception as e:
                        logger.debug(f"Failed to get commit details: {e}")
                
                page += 1
                
            except Exception as e:
                logger.warning(f"REST API failed for {repo['name']}: {e}")
                break
        
        return dict(all_metrics)
    
    def collect_repo_commits(self, repo: Dict, members: List[str]) -> Dict[str, DeveloperMetrics]:
        """Collect commits for a repository - always use REST API for accurate line counts"""
        # Use REST API directly for accurate line counts
        return self.collect_repo_commits_rest_api(repo, members)
    
    def collect_repo_prs(self, repo: Dict, members: List[str]) -> Dict[str, DeveloperMetrics]:
        """Collect pull request metrics for a repository"""
        query = """
        query($owner: String!, $name: String!, $cursor: String) {
            repository(owner: $owner, name: $name) {
                pullRequests(first: 50, states: [MERGED, OPEN, CLOSED], orderBy: {field: CREATED_AT, direction: DESC}, after: $cursor) {
                    edges {
                        node {
                            author {
                                login
                            }
                            createdAt
                            mergedAt
                            state
                            reviews(first: 20) {
                                edges {
                                    node {
                                        author {
                                            login
                                        }
                                        comments {
                                            totalCount
                                        }
                                    }
                                }
                            }
                        }
                    }
                    pageInfo {
                        endCursor
                        hasNextPage
                    }
                }
            }
            rateLimit {
                remaining
                resetAt
            }
        }
        """
        
        owner, name = repo['nameWithOwner'].split('/')
        members_set = set(members)
        cursor = None
        all_metrics = defaultdict(lambda: DeveloperMetrics(username=""))
        
        pages_fetched = 0
        max_pages = 10  # Limit pages
        
        while pages_fetched < max_pages:
            variables = {
                'owner': owner,
                'name': name,
                'cursor': cursor
            }
            
            try:
                result = self.execute_query(query, variables)
            except Exception as e:
                logger.error(f"Failed to fetch PRs for {repo['name']}: {e}")
                break
            
            if 'data' not in result or not result.get('data'):
                break
            
            repo_data = result['data'].get('repository')
            if not repo_data:
                break
            
            prs = repo_data.get('pullRequests', {})
            edges = prs.get('edges', [])
            
            found_old_pr = False
            for edge in edges:
                pr = edge['node']
                
                # Check if PR is within our time range
                created_at = datetime.fromisoformat(pr['createdAt'].replace('Z', '+00:00'))
                if created_at < self.start_date:
                    found_old_pr = True
                    continue
                
                pr_author = pr.get('author', {}).get('login') if pr.get('author') else None
                
                if pr_author and pr_author in members_set:
                    if pr_author not in all_metrics:
                        all_metrics[pr_author] = DeveloperMetrics(username=pr_author)
                    
                    all_metrics[pr_author].prs_created += 1
                    
                    # Count merged PRs
                    if pr.get('state') == 'MERGED' and pr.get('mergedAt'):
                        all_metrics[pr_author].prs_merged += 1
                        merged_at = datetime.fromisoformat(pr['mergedAt'].replace('Z', '+00:00'))
                        turnaround = (merged_at - created_at).total_seconds() / 3600  # hours
                        all_metrics[pr_author].pr_turnarounds.append(turnaround)
                
                # Count reviews
                for review_edge in pr.get('reviews', {}).get('edges', []):
                    review = review_edge['node']
                    reviewer = review.get('author', {}).get('login') if review.get('author') else None
                    
                    if reviewer and reviewer in members_set and reviewer != pr_author:
                        if reviewer not in all_metrics:
                            all_metrics[reviewer] = DeveloperMetrics(username=reviewer)
                        
                        all_metrics[reviewer].prs_reviewed += 1
                        all_metrics[reviewer].review_comments += review.get('comments', {}).get('totalCount', 0)
            
            # Stop if we've found PRs older than our date range
            if found_old_pr and len(edges) < 50:
                break
            
            page_info = prs.get('pageInfo', {})
            if not page_info.get('hasNextPage', False):
                break
            cursor = page_info.get('endCursor')
            pages_fetched += 1
        
        return dict(all_metrics)
    
    def process_repository(self, repo: Dict, members: List[str]) -> Tuple[str, Dict[str, DeveloperMetrics]]:
        """Process a single repository and return combined metrics"""
        logger.info(f"Processing repository: {repo['name']}")
        
        try:
            # Collect commits (with line stats from REST API)
            commit_metrics = self.collect_repo_commits(repo, members)
            
            # Collect PRs
            pr_metrics = self.collect_repo_prs(repo, members)
            
            # Merge metrics
            combined_metrics = defaultdict(lambda: DeveloperMetrics(username=""))
            
            # Add commit metrics
            for author, metrics in commit_metrics.items():
                combined_metrics[author] = metrics
            
            # Add PR metrics
            for author, metrics in pr_metrics.items():
                if author in combined_metrics:
                    combined_metrics[author].prs_created = metrics.prs_created
                    combined_metrics[author].prs_merged = metrics.prs_merged
                    combined_metrics[author].pr_turnarounds = metrics.pr_turnarounds
                    combined_metrics[author].prs_reviewed = metrics.prs_reviewed
                    combined_metrics[author].review_comments = metrics.review_comments
                else:
                    combined_metrics[author] = metrics
            
            return repo['name'], dict(combined_metrics)
            
        except Exception as e:
            logger.error(f"Error processing {repo['name']}: {e}")
            return repo['name'], {}
    
    def merge_metrics_threadsafe(self, repo_metrics: Dict[str, DeveloperMetrics]):
        """Thread-safe merging of repository metrics into global metrics"""
        with self.metrics_lock:
            for username, new_metrics in repo_metrics.items():
                if username not in self.metrics:
                    self.metrics[username] = new_metrics
                else:
                    existing = self.metrics[username]
                    
                    # Merge commits
                    existing.commits_per_week.update(new_metrics.commits_per_week)
                    
                    # Add lines
                    existing.add_lines(new_metrics.lines_added, new_metrics.lines_deleted)
                    
                    # Add PRs
                    existing.prs_created += new_metrics.prs_created
                    existing.prs_merged += new_metrics.prs_merged
                    existing.pr_turnarounds.extend(new_metrics.pr_turnarounds)
                    
                    # Add reviews
                    existing.prs_reviewed += new_metrics.prs_reviewed
                    existing.review_comments += new_metrics.review_comments
                    
                    # Merge repos
                    existing.active_repos.update(new_metrics.active_repos)
                    
                    # Update timestamp
                    existing.last_updated = datetime.now(timezone.utc)
    
    def collect_all_metrics(self):
        """Main method to collect all metrics with parallel processing"""
        logger.info(f"Starting metrics collection from {self.start_date.date()} to {self.end_date.date()}")
        logger.info("=" * 60)
        
        # Get organization members
        members = self.get_organization_members()
        if not members:
            logger.error("No organization members found")
            return
        
        # Initialize metrics for all members (ensures all users appear in output)
        for member in members:
            if member not in self.metrics:
                self.metrics[member] = DeveloperMetrics(username=member)
        
        # Get all repositories
        repos = self.get_organization_repos()
        if not repos:
            logger.error("No repositories found")
            return
        
        # Process repositories in parallel
        logger.info(f"Processing {len(repos)} repositories with {self.max_workers} workers")
        logger.info("Note: Using REST API for accurate line counts (this may take a while)")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for repo in repos:
                future = executor.submit(self.process_repository, repo, members)
                futures[future] = repo
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                repo = futures[future]
                
                try:
                    repo_name, repo_metrics = future.result(timeout=300)
                    if repo_metrics:
                        self.merge_metrics_threadsafe(repo_metrics)
                    logger.info(f"[{completed}/{len(repos)}] Completed: {repo_name}")
                except Exception as e:
                    logger.error(f"Failed to process {repo['name']}: {e}")
        
        logger.info("=" * 60)
        logger.info("Metrics collection complete!")
    
    def export_to_csv(self):
        """Export metrics to CSV file"""
        return self.csv_manager.export_metrics(
            self.metrics,
            self.weeks_to_analyze,
            self.start_date,
            self.end_date
        )
    
    def export_to_json(self, filename: str = None):
        """Export metrics to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'github_metrics_{timestamp}.json'
        
        export_data = {
            'metadata': {
                'organization': self.org_name,
                'start_date': self.start_date.isoformat(),
                'end_date': self.end_date.isoformat(),
                'weeks_analyzed': self.weeks_to_analyze,
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'append_mode': self.csv_manager.append_mode,
                'include_all_users': self.csv_manager.include_all_users
            },
            'metrics': {}
        }
        
        for username, metrics in self.metrics.items():
            export_data['metrics'][username] = metrics.to_dict()
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        logger.info(f"✅ Metrics exported to {filename}")
        return filename
    
    def print_summary(self):
        """Print a summary of collected metrics"""
        print("\n" + "=" * 60)
        print("METRICS SUMMARY")
        print("=" * 60)
        
        # Sort developers by total commits
        sorted_devs = sorted(
            self.metrics.items(),
            key=lambda x: x[1].total_commits,
            reverse=True
        )
        
        # Count active and inactive users
        active_users = 0
        inactive_users = 0
        
        for username, metrics in sorted_devs:
            if metrics.total_commits > 0 or metrics.prs_created > 0 or metrics.prs_reviewed > 0:
                active_users += 1
            else:
                inactive_users += 1
        
        print(f"\nTotal Organization Members: {len(sorted_devs)}")
        print(f"Active Contributors: {active_users}")
        print(f"Inactive in Period: {inactive_users}")
        print("\n" + "-" * 60)
        
        # Show top contributors
        contributors_shown = 0
        for username, metrics in sorted_devs:
            if metrics.total_commits == 0 and metrics.prs_created == 0 and metrics.prs_reviewed == 0:
                continue
            
            contributors_shown += 1
            if contributors_shown > 10:  # Show top 10 contributors
                remaining = len([m for m in sorted_devs[10:] if m[1].total_commits > 0])
                if remaining > 0:
                    print(f"\n... and {remaining} more active contributors")
                break
            
            print(f"\n[{contributors_shown}. {username}]")
            print(f"  Commits: {metrics.total_commits} total ({metrics.total_commits/self.weeks_to_analyze:.1f}/week avg)")
            if metrics.lines_added or metrics.lines_deleted:
                print(f"  Lines: +{metrics.lines_added:,} / -{metrics.lines_deleted:,} (net: {metrics.net_lines:+,})")
            if metrics.prs_merged:
                print(f"  PRs: {metrics.prs_merged} merged")
                if metrics.avg_pr_turnaround_hours > 0:
                    print(f"  PR Turnaround: {metrics.avg_pr_turnaround_hours:.1f} hours avg")
            if metrics.prs_reviewed or metrics.review_comments:
                print(f"  Reviews: {metrics.prs_reviewed} PRs reviewed, {metrics.review_comments} comments")
            if metrics.active_repos:
                print(f"  Active in: {len(metrics.active_repos)} repos")
    
    def cleanup(self):
        """Cleanup resources"""
        if os.getenv('CLEAR_CACHE', 'false').lower() == 'true':
            self.cache_manager.clear_cache()
            logger.info("Cache cleared")


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main execution function"""
    try:
        print("\n🚀 Enhanced GitHub Organization Metrics Scanner")
        print("=" * 50)
        
        # Create collector instance
        collector = GitHubMetricsCollector()
        
        print(f"Organization: {collector.org_name}")
        print(f"Period: Last {collector.weeks_to_analyze} weeks")
        print(f"Append Mode: {collector.csv_manager.append_mode}")
        print(f"Include All Users: {collector.csv_manager.include_all_users}")
        print(f"Workers: {collector.max_workers}")
        print()
        
        # Collect all metrics
        collector.collect_all_metrics()
        
        # Print summary
        collector.print_summary()
        
        # Export results
        print("\n" + "=" * 60)
        print("EXPORTING RESULTS")
        print("=" * 60)
        
        csv_file = collector.export_to_csv()
        json_file = collector.export_to_json()
        
        print(f"\n✨ All done!")
        print(f"   CSV: {csv_file}")
        print(f"   JSON: {json_file}")
        
        if collector.csv_manager.append_mode:
            print(f"\n📝 Note: Running in APPEND mode - data was added to existing CSV")
            print("   This is suitable for scheduled/continuous monitoring")
        else:
            print(f"\n📝 Note: Running in SINGLE-RUN mode - new CSV file created")
        
        if collector.csv_manager.include_all_users:
            print("   Including ALL organization members (even with 0 activity)")
        else:
            print("   Including only members with activity in the period")
        
        # Cleanup if needed
        collector.cleanup()
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Process interrupted by user")
        logger.info("Process interrupted by user")
    except ConfigurationError as e:
        print(f"\n❌ Configuration Error: {e}")
        print("\nPlease ensure your .env file contains:")
        print("  GITHUB_TOKEN=your_github_token")
        print("  GITHUB_ORG=your_organization_name")
        print("  APPEND_MODE=true/false (default: false)")
        print("  INCLUDE_ALL_USERS=true/false (default: true)")
        print("  WEEKS_TO_ANALYZE=12")
        logger.error(f"Configuration error: {e}")
    except TokenValidationError as e:
        print(f"\n❌ Token Error: {e}")
        print("\nPlease check that your GitHub token:")
        print("  - Is valid and not expired")
        print("  - Has 'repo' and 'read:org' scopes")
        print("  - Has access to the specified organization")
        logger.error(f"Token validation error: {e}")
    except Exception as e:
        print(f"\n❌ Unexpected Error: {e}")
        logger.error(f"Unexpected error: {e}", exc_info=True)
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()