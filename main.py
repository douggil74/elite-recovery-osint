"""
Elite Recovery OSINT Backend
FastAPI service integrating Python OSINT tools:
- Sherlock: Username search across 400+ sites
- Maigret: Comprehensive username intelligence
- holehe: Email account discovery
- phoneinfoga: Phone number intelligence
- socialscan: Username/email availability
"""

import asyncio
import json
import os
import subprocess
import tempfile
from datetime import datetime
from typing import Optional, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import aiohttp
import httpx

# Initialize FastAPI
app = FastAPI(
    title="Elite Recovery OSINT API",
    description="Advanced OSINT intelligence gathering for fugitive recovery",
    version="1.0.0"
)

# CORS - allow all origins for the recovery app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Thread pool for running CLI tools
executor = ThreadPoolExecutor(max_workers=10)


# ============================================================================
# MODELS
# ============================================================================

class UsernameSearchRequest(BaseModel):
    username: str
    timeout: int = 60


class UsernameSearchResult(BaseModel):
    username: str
    searched_at: str
    tool: str
    total_sites: int
    found: List[Dict[str, str]]
    not_found: List[str]
    errors: List[str]
    execution_time: float


class EmailSearchRequest(BaseModel):
    email: EmailStr
    timeout: int = 60


class EmailSearchResult(BaseModel):
    email: str
    searched_at: str
    tool: str
    registered_on: List[Dict[str, Any]]
    not_registered: List[str]
    execution_time: float


class PhoneSearchRequest(BaseModel):
    phone: str
    country_code: str = "US"


class PhoneSearchResult(BaseModel):
    phone: str
    searched_at: str
    carrier: Optional[str]
    line_type: Optional[str]
    location: Optional[Dict[str, str]]
    reputation: Optional[Dict[str, Any]]
    social_media: List[Dict[str, str]]
    execution_time: float


class FullSweepRequest(BaseModel):
    name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    username: Optional[str] = None
    state: Optional[str] = None


class FullSweepResult(BaseModel):
    target: Dict[str, Any]
    searched_at: str
    username_results: Optional[UsernameSearchResult] = None
    email_results: Optional[EmailSearchResult] = None
    phone_results: Optional[PhoneSearchResult] = None
    summary: str
    total_profiles_found: int
    execution_time: float


# ============================================================================
# SHERLOCK - Username Search
# ============================================================================

def run_sherlock(username: str, timeout: int = 60) -> Dict[str, Any]:
    """Run Sherlock CLI tool for username search"""
    start_time = datetime.now()
    found = []
    not_found = []
    errors = []

    try:
        # Create temp directory for output
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, f"{username}.json")

            # Run sherlock
            cmd = [
                "sherlock", username,
                "--json", output_file,
                "--timeout", str(timeout),
                "--print-found"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 10
            )

            # Parse JSON output
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    data = json.load(f)

                for site, info in data.items():
                    if info.get('status') == 'Claimed':
                        found.append({
                            'platform': site,
                            'url': info.get('url_user', ''),
                            'response_time': info.get('response_time_s', 0)
                        })
                    elif info.get('status') == 'Available':
                        not_found.append(site)
                    else:
                        errors.append(f"{site}: {info.get('status', 'Unknown')}")

            # Also parse stdout for any additional findings
            if result.stdout:
                for line in result.stdout.split('\n'):
                    if '[+]' in line and 'http' in line:
                        # Extract URL from line
                        parts = line.split()
                        for part in parts:
                            if part.startswith('http'):
                                # Check if already in found
                                if not any(f['url'] == part for f in found):
                                    found.append({
                                        'platform': 'Unknown',
                                        'url': part,
                                        'response_time': 0
                                    })

    except subprocess.TimeoutExpired:
        errors.append("Search timed out")
    except FileNotFoundError:
        errors.append("Sherlock not installed. Run: pip install sherlock-project")
    except Exception as e:
        errors.append(f"Error: {str(e)}")

    execution_time = (datetime.now() - start_time).total_seconds()

    return {
        'username': username,
        'searched_at': datetime.now().isoformat(),
        'tool': 'sherlock',
        'total_sites': len(found) + len(not_found),
        'found': found,
        'not_found': not_found,
        'errors': errors,
        'execution_time': execution_time
    }


@app.post("/api/sherlock", response_model=UsernameSearchResult)
async def sherlock_search(request: UsernameSearchRequest):
    """Search username across 400+ sites using Sherlock"""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        executor,
        run_sherlock,
        request.username,
        request.timeout
    )
    return result


# ============================================================================
# MAIGRET - Comprehensive Username Search
# ============================================================================

def run_maigret(username: str, timeout: int = 120) -> Dict[str, Any]:
    """Run Maigret CLI tool for comprehensive username search"""
    start_time = datetime.now()
    found = []
    not_found = []
    errors = []

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, f"{username}.json")

            cmd = [
                "maigret", username,
                "--json", "simple",
                "-o", output_file,
                "--timeout", str(timeout),
                "--no-progressbar"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30
            )

            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    data = json.load(f)

                # Maigret output structure
                if isinstance(data, dict):
                    for site, info in data.items():
                        if isinstance(info, dict):
                            if info.get('status') == 'Claimed' or info.get('exists'):
                                found.append({
                                    'platform': site,
                                    'url': info.get('url', info.get('url_user', '')),
                                    'tags': info.get('tags', []),
                                    'ids': info.get('ids', {})
                                })
                            else:
                                not_found.append(site)

    except subprocess.TimeoutExpired:
        errors.append("Search timed out")
    except FileNotFoundError:
        errors.append("Maigret not installed. Run: pip install maigret")
    except Exception as e:
        errors.append(f"Error: {str(e)}")

    execution_time = (datetime.now() - start_time).total_seconds()

    return {
        'username': username,
        'searched_at': datetime.now().isoformat(),
        'tool': 'maigret',
        'total_sites': len(found) + len(not_found),
        'found': found,
        'not_found': not_found[:50],  # Limit not_found to reduce payload
        'errors': errors,
        'execution_time': execution_time
    }


@app.post("/api/maigret", response_model=UsernameSearchResult)
async def maigret_search(request: UsernameSearchRequest):
    """Comprehensive username search using Maigret"""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        executor,
        run_maigret,
        request.username,
        request.timeout
    )
    return result


# ============================================================================
# HOLEHE - Email Account Discovery
# ============================================================================

def run_holehe(email: str, timeout: int = 60) -> Dict[str, Any]:
    """Run holehe to check email registration across services"""
    start_time = datetime.now()
    registered = []
    not_registered = []
    errors = []

    try:
        cmd = ["holehe", email, "--only-used", "-NP"]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Parse holehe output
        current_service = None
        for line in result.stdout.split('\n'):
            line = line.strip()
            if not line:
                continue

            # holehe outputs: [+] service: registered/rate-limited/etc
            if '[+]' in line:
                # Registered
                parts = line.replace('[+]', '').strip().split(':')
                if parts:
                    service = parts[0].strip()
                    registered.append({
                        'service': service,
                        'status': 'registered',
                        'details': ':'.join(parts[1:]).strip() if len(parts) > 1 else ''
                    })
            elif '[-]' in line:
                # Not registered
                parts = line.replace('[-]', '').strip().split(':')
                if parts:
                    not_registered.append(parts[0].strip())
            elif '[x]' in line:
                # Error/rate-limited
                parts = line.replace('[x]', '').strip().split(':')
                if parts:
                    errors.append(parts[0].strip())

    except subprocess.TimeoutExpired:
        errors.append("Search timed out")
    except FileNotFoundError:
        errors.append("holehe not installed. Run: pip install holehe")
    except Exception as e:
        errors.append(f"Error: {str(e)}")

    execution_time = (datetime.now() - start_time).total_seconds()

    return {
        'email': email,
        'searched_at': datetime.now().isoformat(),
        'tool': 'holehe',
        'registered_on': registered,
        'not_registered': not_registered[:20],
        'errors': errors,
        'execution_time': execution_time
    }


@app.post("/api/holehe", response_model=EmailSearchResult)
async def holehe_search(request: EmailSearchRequest):
    """Check email registration across services using holehe"""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        executor,
        run_holehe,
        request.email,
        request.timeout
    )
    return result


# ============================================================================
# SOCIALSCAN - Quick Username/Email Check
# ============================================================================

async def run_socialscan(query: str, query_type: str = "username") -> Dict[str, Any]:
    """Run socialscan for quick availability check"""
    start_time = datetime.now()
    results = []
    errors = []

    try:
        cmd = ["socialscan", query]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=30
        )

        output = stdout.decode()
        for line in output.split('\n'):
            if query in line:
                # Parse socialscan output format
                # Platform: Available/Taken
                parts = line.split(':')
                if len(parts) >= 2:
                    platform = parts[0].strip()
                    status = parts[1].strip().lower()
                    results.append({
                        'platform': platform,
                        'available': 'available' in status,
                        'taken': 'taken' in status or 'claimed' in status
                    })

    except asyncio.TimeoutError:
        errors.append("Search timed out")
    except FileNotFoundError:
        errors.append("socialscan not installed. Run: pip install socialscan")
    except Exception as e:
        errors.append(f"Error: {str(e)}")

    execution_time = (datetime.now() - start_time).total_seconds()

    return {
        'query': query,
        'type': query_type,
        'searched_at': datetime.now().isoformat(),
        'tool': 'socialscan',
        'results': results,
        'errors': errors,
        'execution_time': execution_time
    }


@app.get("/api/socialscan")
async def socialscan_check(
    query: str = Query(..., description="Username or email to check"),
    type: str = Query("username", description="Type: username or email")
):
    """Quick username/email availability check using socialscan"""
    return await run_socialscan(query, type)


# ============================================================================
# COMBINED USERNAME SEARCH
# ============================================================================

@app.post("/api/username/full")
async def full_username_search(request: UsernameSearchRequest):
    """Run both Sherlock and Maigret for comprehensive results"""
    loop = asyncio.get_event_loop()

    # Run both tools in parallel
    sherlock_task = loop.run_in_executor(
        executor, run_sherlock, request.username, request.timeout
    )
    maigret_task = loop.run_in_executor(
        executor, run_maigret, request.username, request.timeout
    )

    sherlock_result, maigret_result = await asyncio.gather(
        sherlock_task, maigret_task
    )

    # Merge results, deduplicate by URL
    all_found = {}
    for item in sherlock_result['found']:
        url = item.get('url', '')
        if url:
            all_found[url] = item

    for item in maigret_result['found']:
        url = item.get('url', '')
        if url and url not in all_found:
            all_found[url] = item

    return {
        'username': request.username,
        'searched_at': datetime.now().isoformat(),
        'sherlock': sherlock_result,
        'maigret': maigret_result,
        'combined': {
            'total_unique_profiles': len(all_found),
            'profiles': list(all_found.values())
        }
    }


# ============================================================================
# PHONE INTELLIGENCE (Basic - phoneinfoga integration placeholder)
# ============================================================================

@app.post("/api/phone", response_model=PhoneSearchResult)
async def phone_search(request: PhoneSearchRequest):
    """Phone number intelligence gathering"""
    start_time = datetime.now()

    # Basic phone analysis (phoneinfoga integration would go here)
    phone = request.phone.replace("-", "").replace(" ", "").replace("(", "").replace(")", "")

    # US area code database (subset)
    area_codes = {
        "212": {"city": "New York", "state": "NY"},
        "213": {"city": "Los Angeles", "state": "CA"},
        "312": {"city": "Chicago", "state": "IL"},
        "404": {"city": "Atlanta", "state": "GA"},
        "504": {"city": "New Orleans", "state": "LA"},
        "713": {"city": "Houston", "state": "TX"},
        "305": {"city": "Miami", "state": "FL"},
        "702": {"city": "Las Vegas", "state": "NV"},
        "206": {"city": "Seattle", "state": "WA"},
        "415": {"city": "San Francisco", "state": "CA"},
    }

    # Extract area code
    area_code = None
    location = None
    if phone.startswith("+1"):
        phone = phone[2:]
    if phone.startswith("1") and len(phone) == 11:
        phone = phone[1:]
    if len(phone) >= 10:
        area_code = phone[:3]
        location = area_codes.get(area_code, {"city": "Unknown", "state": "Unknown"})

    # Generate social media search links
    social_media = [
        {"platform": "Facebook", "url": f"https://www.facebook.com/search/top?q={phone}"},
        {"platform": "TrueCaller", "url": f"https://www.truecaller.com/search/us/{phone}"},
        {"platform": "Whitepages", "url": f"https://www.whitepages.com/phone/{phone}"},
        {"platform": "NumLookup", "url": f"https://www.numlookup.com/us/{phone}"},
    ]

    execution_time = (datetime.now() - start_time).total_seconds()

    return {
        'phone': request.phone,
        'searched_at': datetime.now().isoformat(),
        'carrier': None,  # Would come from phoneinfoga
        'line_type': None,
        'location': location,
        'reputation': None,
        'social_media': social_media,
        'execution_time': execution_time
    }


# ============================================================================
# FULL OSINT SWEEP
# ============================================================================

@app.post("/api/sweep", response_model=FullSweepResult)
async def full_osint_sweep(request: FullSweepRequest):
    """Complete OSINT sweep on a target"""
    start_time = datetime.now()

    # Generate username from name if not provided
    username = request.username
    if not username and request.name:
        username = request.name.lower().replace(" ", "")

    tasks = []
    results = {
        'username_results': None,
        'email_results': None,
        'phone_results': None
    }

    loop = asyncio.get_event_loop()

    # Username search
    if username:
        async def search_username():
            result = await loop.run_in_executor(
                executor, run_sherlock, username, 60
            )
            results['username_results'] = result
        tasks.append(search_username())

    # Email search
    if request.email:
        async def search_email():
            result = await loop.run_in_executor(
                executor, run_holehe, request.email, 60
            )
            results['email_results'] = result
        tasks.append(search_email())

    # Phone search
    if request.phone:
        async def search_phone():
            result = await phone_search(PhoneSearchRequest(phone=request.phone))
            results['phone_results'] = result
        tasks.append(search_phone())

    # Run all tasks
    if tasks:
        await asyncio.gather(*tasks)

    # Calculate totals
    total_profiles = 0
    if results['username_results']:
        total_profiles += len(results['username_results'].get('found', []))
    if results['email_results']:
        total_profiles += len(results['email_results'].get('registered_on', []))

    # Generate summary
    summary_parts = []
    if results['username_results']:
        found = len(results['username_results'].get('found', []))
        summary_parts.append(f"Found {found} social profiles for @{username}")
    if results['email_results']:
        registered = len(results['email_results'].get('registered_on', []))
        summary_parts.append(f"Email registered on {registered} services")
    if results['phone_results'] and results['phone_results'].get('location'):
        loc = results['phone_results']['location']
        summary_parts.append(f"Phone from {loc.get('city', 'Unknown')}, {loc.get('state', 'Unknown')}")

    execution_time = (datetime.now() - start_time).total_seconds()

    return {
        'target': {
            'name': request.name,
            'email': request.email,
            'phone': request.phone,
            'username': username,
            'state': request.state
        },
        'searched_at': datetime.now().isoformat(),
        'username_results': results['username_results'],
        'email_results': results['email_results'],
        'phone_results': results['phone_results'],
        'summary': ' | '.join(summary_parts) if summary_parts else 'No results found',
        'total_profiles_found': total_profiles,
        'execution_time': execution_time
    }


# ============================================================================
# HEALTH CHECK
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    # Check which tools are available
    tools = {}

    for tool in ['sherlock', 'maigret', 'holehe', 'socialscan']:
        try:
            result = subprocess.run(
                [tool, '--version'],
                capture_output=True,
                timeout=5
            )
            tools[tool] = 'installed'
        except FileNotFoundError:
            tools[tool] = 'not installed'
        except Exception as e:
            tools[tool] = f'error: {str(e)}'

    return {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'tools': tools
    }


@app.get("/")
async def root():
    """Root endpoint with API info"""
    return {
        'name': 'Elite Recovery OSINT API',
        'version': '1.0.0',
        'endpoints': {
            '/api/sherlock': 'Username search (400+ sites)',
            '/api/maigret': 'Comprehensive username search',
            '/api/holehe': 'Email account discovery',
            '/api/socialscan': 'Quick username/email check',
            '/api/username/full': 'Combined username search',
            '/api/phone': 'Phone intelligence',
            '/api/sweep': 'Full OSINT sweep',
            '/health': 'Health check'
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
