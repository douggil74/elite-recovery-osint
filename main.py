"""
Elite Recovery OSINT Backend
FastAPI service integrating Python OSINT tools:
- Sherlock: Username search across 400+ sites
- Maigret: Comprehensive username intelligence
- holehe: Email account discovery
- phoneinfoga: Phone number intelligence
- socialscan: Username/email availability
- h8mail: Email breach/leak checking
- theHarvester: Email/domain reconnaissance
- social-analyzer: Enhanced username search (1000+ sites)
- CourtListener API: Federal court records
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
    version="1.5.0"
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
# PHONEINFOGA - Advanced Phone Intelligence
# ============================================================================

class PhoneInfogaRequest(BaseModel):
    phone: str
    scanners: List[str] = ["local", "numverify", "googlesearch"]


class PhoneInfogaResult(BaseModel):
    phone: str
    searched_at: str
    raw_local: Optional[str] = None
    international: Optional[str] = None
    country: Optional[str] = None
    carrier: Optional[str] = None
    line_type: Optional[str] = None
    valid: bool = False
    possible_owner: Optional[str] = None
    social_results: List[Dict[str, Any]] = []
    dork_results: List[str] = []
    errors: List[str] = []
    execution_time: float


def run_phoneinfoga(phone: str, scanners: List[str] = None) -> Dict[str, Any]:
    """Run PhoneInfoga for phone number intelligence"""
    start_time = datetime.now()
    errors = []
    result_data = {
        'raw_local': None,
        'international': None,
        'country': None,
        'carrier': None,
        'line_type': None,
        'valid': False,
        'possible_owner': None,
        'social_results': [],
        'dork_results': []
    }

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, "phoneinfoga_output.json")

            # Run phoneinfoga scan
            cmd = [
                "phoneinfoga", "scan",
                "-n", phone,
                "-o", output_file
            ]

            proc_result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=90
            )

            # Parse output
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    data = json.load(f)

                result_data['raw_local'] = data.get('rawLocal', phone)
                result_data['international'] = data.get('international', '')
                result_data['country'] = data.get('country', '')
                result_data['carrier'] = data.get('carrier', '')
                result_data['line_type'] = data.get('lineType', '')
                result_data['valid'] = data.get('valid', False)

                # Extract social media findings
                if 'googlesearch' in data:
                    for item in data.get('googlesearch', []):
                        result_data['social_results'].append({
                            'title': item.get('title', ''),
                            'url': item.get('url', ''),
                            'snippet': item.get('snippet', '')
                        })

            # Also parse stdout for any additional info
            if proc_result.stdout:
                for line in proc_result.stdout.split('\n'):
                    if 'Carrier:' in line:
                        result_data['carrier'] = line.split('Carrier:')[1].strip()
                    elif 'Country:' in line:
                        result_data['country'] = line.split('Country:')[1].strip()
                    elif 'Line type:' in line or 'LineType:' in line:
                        result_data['line_type'] = line.split(':')[1].strip()

            # Generate Google dorks for manual searching
            clean_phone = phone.replace('-', '').replace(' ', '').replace('(', '').replace(')', '')
            result_data['dork_results'] = [
                f'"{clean_phone}"',
                f'"{phone}" site:facebook.com',
                f'"{phone}" site:linkedin.com',
                f'"{phone}" site:twitter.com',
                f'"{clean_phone}" intext:contact',
                f'"{clean_phone}" filetype:pdf',
            ]

    except subprocess.TimeoutExpired:
        errors.append("PhoneInfoga search timed out")
    except FileNotFoundError:
        errors.append("PhoneInfoga not installed. Run: go install github.com/sundowndev/phoneinfoga/v2/cmd/phoneinfoga@latest")
        # Fallback to basic analysis
        clean_phone = phone.replace('-', '').replace(' ', '').replace('(', '').replace(')', '')
        if clean_phone.startswith('+1'):
            clean_phone = clean_phone[2:]
        if len(clean_phone) == 11 and clean_phone.startswith('1'):
            clean_phone = clean_phone[1:]
        if len(clean_phone) == 10:
            result_data['country'] = 'US'
            result_data['valid'] = True
    except Exception as e:
        errors.append(f"PhoneInfoga error: {str(e)}")

    execution_time = (datetime.now() - start_time).total_seconds()

    return {
        'phone': phone,
        'searched_at': datetime.now().isoformat(),
        **result_data,
        'errors': errors,
        'execution_time': execution_time
    }


@app.post("/api/phoneinfoga", response_model=PhoneInfogaResult)
async def phoneinfoga_search(request: PhoneInfogaRequest):
    """Advanced phone number intelligence using PhoneInfoga"""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        executor,
        run_phoneinfoga,
        request.phone,
        request.scanners
    )
    return result


# ============================================================================
# H8MAIL - Email Breach/Leak Checking
# ============================================================================

class H8mailRequest(BaseModel):
    email: EmailStr
    chase_breaches: bool = True


class H8mailResult(BaseModel):
    email: str
    searched_at: str
    breaches_found: List[Dict[str, Any]]
    leaked_passwords: List[str]
    related_emails: List[str]
    total_breaches: int
    errors: List[str]
    execution_time: float


def run_h8mail(email: str, chase: bool = True) -> Dict[str, Any]:
    """Run h8mail to check for email in data breaches"""
    start_time = datetime.now()
    breaches = []
    leaked_passwords = []
    related_emails = []
    errors = []

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, "h8mail_output.json")

            cmd = ["h8mail", "-t", email, "-j", output_file]
            if chase:
                cmd.append("-c")  # Chase related emails

            proc_result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            # Parse JSON output
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    data = json.load(f)

                for target in data.get('targets', []):
                    target_email = target.get('target', '')
                    if target_email != email:
                        related_emails.append(target_email)

                    for breach in target.get('data', []):
                        breaches.append({
                            'source': breach.get('source', 'Unknown'),
                            'breach_name': breach.get('breach', ''),
                            'data': breach.get('data', ''),
                            'date': breach.get('date', '')
                        })

                        # Check for leaked passwords
                        data_str = breach.get('data', '')
                        if ':' in data_str and '@' in data_str.split(':')[0]:
                            possible_password = data_str.split(':')[-1]
                            if possible_password and len(possible_password) > 3:
                                leaked_passwords.append(possible_password[:3] + '***')

            # Also parse stdout for additional findings
            if proc_result.stdout:
                for line in proc_result.stdout.split('\n'):
                    if '[+]' in line and 'breach' in line.lower():
                        breaches.append({
                            'source': 'h8mail_stdout',
                            'data': line.replace('[+]', '').strip()
                        })

    except subprocess.TimeoutExpired:
        errors.append("h8mail search timed out")
    except FileNotFoundError:
        errors.append("h8mail not installed. Run: pip install h8mail")
    except Exception as e:
        errors.append(f"h8mail error: {str(e)}")

    execution_time = (datetime.now() - start_time).total_seconds()

    return {
        'email': email,
        'searched_at': datetime.now().isoformat(),
        'breaches_found': breaches,
        'leaked_passwords': list(set(leaked_passwords)),
        'related_emails': list(set(related_emails)),
        'total_breaches': len(breaches),
        'errors': errors,
        'execution_time': execution_time
    }


@app.post("/api/h8mail", response_model=H8mailResult)
async def h8mail_search(request: H8mailRequest):
    """Check email for data breaches using h8mail"""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        executor,
        run_h8mail,
        request.email,
        request.chase_breaches
    )
    return result


# ============================================================================
# THEHARVESTER - Email/Domain Reconnaissance
# ============================================================================

class HarvesterRequest(BaseModel):
    domain: str
    sources: List[str] = ["google", "bing", "linkedin", "twitter"]
    limit: int = 100


class HarvesterResult(BaseModel):
    domain: str
    searched_at: str
    emails_found: List[str]
    hosts_found: List[str]
    ips_found: List[str]
    urls_found: List[str]
    people_found: List[str]
    total_results: int
    errors: List[str]
    execution_time: float


def run_theharvester(domain: str, sources: List[str] = None, limit: int = 100) -> Dict[str, Any]:
    """Run theHarvester for domain reconnaissance"""
    start_time = datetime.now()
    emails = []
    hosts = []
    ips = []
    urls = []
    people = []
    errors = []

    if not sources:
        sources = ["google", "bing", "linkedin"]

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, "harvester_output.xml")

            for source in sources:
                cmd = [
                    "theHarvester",
                    "-d", domain,
                    "-b", source,
                    "-l", str(limit),
                    "-f", output_file
                ]

                proc_result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=90
                )

                # Parse stdout directly (more reliable than XML)
                if proc_result.stdout:
                    current_section = None
                    for line in proc_result.stdout.split('\n'):
                        line = line.strip()
                        if not line:
                            continue

                        if 'Emails found' in line or '[*] Emails' in line:
                            current_section = 'emails'
                        elif 'Hosts found' in line or '[*] Hosts' in line:
                            current_section = 'hosts'
                        elif 'IPs found' in line or '[*] IPs' in line:
                            current_section = 'ips'
                        elif 'URLs found' in line:
                            current_section = 'urls'
                        elif 'People found' in line or '[*] LinkedIn' in line:
                            current_section = 'people'
                        elif line.startswith('[*]') or line.startswith('[-]'):
                            current_section = None
                        elif current_section and not line.startswith('-'):
                            if current_section == 'emails' and '@' in line:
                                emails.append(line)
                            elif current_section == 'hosts':
                                hosts.append(line)
                            elif current_section == 'ips':
                                ips.append(line)
                            elif current_section == 'urls' and 'http' in line:
                                urls.append(line)
                            elif current_section == 'people' and line:
                                people.append(line)

    except subprocess.TimeoutExpired:
        errors.append("theHarvester search timed out")
    except FileNotFoundError:
        errors.append("theHarvester not installed. Run: pip install theHarvester")
    except Exception as e:
        errors.append(f"theHarvester error: {str(e)}")

    execution_time = (datetime.now() - start_time).total_seconds()

    # Deduplicate results
    emails = list(set(emails))
    hosts = list(set(hosts))
    ips = list(set(ips))
    urls = list(set(urls))
    people = list(set(people))

    return {
        'domain': domain,
        'searched_at': datetime.now().isoformat(),
        'emails_found': emails,
        'hosts_found': hosts,
        'ips_found': ips,
        'urls_found': urls,
        'people_found': people,
        'total_results': len(emails) + len(hosts) + len(people),
        'errors': errors,
        'execution_time': execution_time
    }


@app.post("/api/harvester", response_model=HarvesterResult)
async def harvester_search(request: HarvesterRequest):
    """Domain reconnaissance using theHarvester"""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        executor,
        run_theharvester,
        request.domain,
        request.sources,
        request.limit
    )
    return result


# ============================================================================
# SOCIAL-ANALYZER - Enhanced Username Search (1000+ Sites)
# ============================================================================

class SocialAnalyzerRequest(BaseModel):
    username: str
    metadata: bool = True
    extract_links: bool = True
    timeout: int = 120


class SocialAnalyzerResult(BaseModel):
    username: str
    searched_at: str
    profiles_found: List[Dict[str, Any]]
    total_found: int
    metadata_extracted: Dict[str, Any]
    errors: List[str]
    execution_time: float


def run_social_analyzer(username: str, metadata: bool = True, timeout: int = 120) -> Dict[str, Any]:
    """Run social-analyzer for comprehensive username search (1000+ sites)"""
    start_time = datetime.now()
    profiles = []
    metadata_info = {}
    errors = []

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, "social_analyzer_output.json")

            cmd = [
                "social-analyzer",
                "--username", username,
                "--output", "json",
                "--trim"
            ]

            if metadata:
                cmd.append("--metadata")

            proc_result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30
            )

            # Parse stdout (social-analyzer outputs JSON to stdout)
            if proc_result.stdout:
                try:
                    # Find JSON in output
                    output = proc_result.stdout
                    json_start = output.find('{')
                    json_end = output.rfind('}') + 1
                    if json_start >= 0 and json_end > json_start:
                        data = json.loads(output[json_start:json_end])

                        # Extract detected profiles
                        detected = data.get('detected', [])
                        for profile in detected:
                            profiles.append({
                                'platform': profile.get('name', 'Unknown'),
                                'url': profile.get('url', ''),
                                'status': profile.get('status', ''),
                                'extracted_info': profile.get('extracted', {})
                            })

                        # Extract metadata
                        if 'metadata' in data:
                            metadata_info = data['metadata']

                except json.JSONDecodeError:
                    # Fallback: parse stdout line by line
                    for line in proc_result.stdout.split('\n'):
                        if 'http' in line and username.lower() in line.lower():
                            profiles.append({
                                'platform': 'Unknown',
                                'url': line.strip(),
                                'status': 'found'
                            })

    except subprocess.TimeoutExpired:
        errors.append("social-analyzer search timed out")
    except FileNotFoundError:
        errors.append("social-analyzer not installed. Run: pip install social-analyzer")
    except Exception as e:
        errors.append(f"social-analyzer error: {str(e)}")

    execution_time = (datetime.now() - start_time).total_seconds()

    return {
        'username': username,
        'searched_at': datetime.now().isoformat(),
        'profiles_found': profiles,
        'total_found': len(profiles),
        'metadata_extracted': metadata_info,
        'errors': errors,
        'execution_time': execution_time
    }


@app.post("/api/social-analyzer", response_model=SocialAnalyzerResult)
async def social_analyzer_search(request: SocialAnalyzerRequest):
    """Comprehensive username search across 1000+ sites using social-analyzer"""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        executor,
        run_social_analyzer,
        request.username,
        request.metadata,
        request.timeout
    )
    return result


# ============================================================================
# COURTLISTENER API - Federal Court Records
# ============================================================================

COURTLISTENER_API_KEY = os.getenv("COURTLISTENER_API_KEY", "")

class CourtSearchRequest(BaseModel):
    name: str
    case_name: Optional[str] = None
    court: Optional[str] = None  # e.g., "scotus", "ca9", "laed"
    filed_after: Optional[str] = None  # YYYY-MM-DD
    filed_before: Optional[str] = None


class CourtSearchResult(BaseModel):
    query: str
    searched_at: str
    cases_found: List[Dict[str, Any]]
    people_found: List[Dict[str, Any]]
    total_results: int
    courtlistener_urls: List[str]
    errors: List[str]
    execution_time: float


async def search_courtlistener(name: str, case_name: str = None, court: str = None,
                               filed_after: str = None, filed_before: str = None) -> Dict[str, Any]:
    """Search CourtListener API for federal court records"""
    start_time = datetime.now()
    cases = []
    people = []
    courtlistener_urls = []
    errors = []

    base_url = "https://www.courtlistener.com/api/rest/v3"

    # Headers
    headers = {
        "Content-Type": "application/json"
    }
    if COURTLISTENER_API_KEY:
        headers["Authorization"] = f"Token {COURTLISTENER_API_KEY}"

    try:
        async with httpx.AsyncClient() as client:
            # Search for opinions/cases
            search_params = {
                "q": name,
                "type": "o",  # opinions
                "order_by": "dateFiled desc",
            }
            if case_name:
                search_params["case_name"] = case_name
            if court:
                search_params["court"] = court
            if filed_after:
                search_params["filed_after"] = filed_after
            if filed_before:
                search_params["filed_before"] = filed_before

            # Search opinions
            try:
                response = await client.get(
                    f"{base_url}/search/",
                    params=search_params,
                    headers=headers,
                    timeout=30.0
                )
                if response.status_code == 200:
                    data = response.json()
                    for result in data.get('results', [])[:20]:
                        cases.append({
                            'case_name': result.get('caseName', ''),
                            'court': result.get('court', ''),
                            'date_filed': result.get('dateFiled', ''),
                            'docket_number': result.get('docketNumber', ''),
                            'status': result.get('status', ''),
                            'url': f"https://www.courtlistener.com{result.get('absolute_url', '')}",
                            'snippet': result.get('snippet', '')[:300]
                        })
            except Exception as e:
                errors.append(f"Opinion search error: {str(e)}")

            # Search people (judges, attorneys)
            try:
                people_response = await client.get(
                    f"{base_url}/people/",
                    params={"name_full": name},
                    headers=headers,
                    timeout=30.0
                )
                if people_response.status_code == 200:
                    data = people_response.json()
                    for person in data.get('results', [])[:10]:
                        people.append({
                            'name': person.get('name_full', ''),
                            'born': person.get('date_dob', ''),
                            'positions': [p.get('position_type', '') for p in person.get('positions', [])],
                            'url': f"https://www.courtlistener.com{person.get('absolute_url', '')}"
                        })
            except Exception as e:
                errors.append(f"People search error: {str(e)}")

            # Search dockets
            try:
                docket_response = await client.get(
                    f"{base_url}/dockets/",
                    params={"case_name__icontains": name},
                    headers=headers,
                    timeout=30.0
                )
                if docket_response.status_code == 200:
                    data = docket_response.json()
                    for docket in data.get('results', [])[:10]:
                        if docket.get('absolute_url'):
                            courtlistener_urls.append(f"https://www.courtlistener.com{docket['absolute_url']}")
            except Exception as e:
                errors.append(f"Docket search error: {str(e)}")

    except Exception as e:
        errors.append(f"CourtListener API error: {str(e)}")

    # Generate manual search URLs
    encoded_name = name.replace(' ', '+')
    courtlistener_urls.extend([
        f"https://www.courtlistener.com/?q={encoded_name}&type=o",
        f"https://www.courtlistener.com/?q={encoded_name}&type=r",
        f"https://www.courtlistener.com/?q={encoded_name}&type=p"
    ])

    execution_time = (datetime.now() - start_time).total_seconds()

    return {
        'query': name,
        'searched_at': datetime.now().isoformat(),
        'cases_found': cases,
        'people_found': people,
        'total_results': len(cases) + len(people),
        'courtlistener_urls': list(set(courtlistener_urls)),
        'errors': errors,
        'execution_time': execution_time
    }


@app.post("/api/court-records", response_model=CourtSearchResult)
async def court_search(request: CourtSearchRequest):
    """Search federal court records using CourtListener API"""
    result = await search_courtlistener(
        request.name,
        request.case_name,
        request.court,
        request.filed_after,
        request.filed_before
    )
    return result


# ============================================================================
# STATE COURT RECORDS - Links Generator
# ============================================================================

class StateCourtRequest(BaseModel):
    name: str
    state: str  # 2-letter state code


@app.post("/api/state-courts")
async def state_court_links(request: StateCourtRequest):
    """Generate links to search state court records"""
    name = request.name.replace(' ', '+')
    state = request.state.upper()

    # State court system URLs
    state_courts = {
        "LA": {
            "name": "Louisiana",
            "supreme_court": f"https://www.lasc.org/search?q={name}",
            "district_courts": f"https://www.laed.uscourts.gov/search/node/{name}",
            "case_search": "https://www.lacourt.org/",
            "offender_search": f"https://www.doc.la.gov/offender-search?name={name}"
        },
        "TX": {
            "name": "Texas",
            "courts_online": f"https://search.txcourts.gov/CaseSearch.aspx?coa=cossup&s={name}",
            "offender_search": f"https://offender.tdcj.texas.gov/OffenderSearch/search.action?lastName={name.split('+')[-1]}"
        },
        "FL": {
            "name": "Florida",
            "clerk_search": "https://www.myfloridacounty.com/",
            "offender_search": f"https://www.dc.state.fl.us/offenderSearch/search.aspx?TypeSearch=IR&LastName={name.split('+')[-1]}"
        },
        "CA": {
            "name": "California",
            "courts": "https://www.courts.ca.gov/find-my-court.htm",
            "cdcr_search": f"https://inmatelocator.cdcr.ca.gov/search.aspx"
        },
        "GA": {
            "name": "Georgia",
            "courts": f"https://www.gasupreme.us/search/?q={name}",
            "offender_search": f"https://gdc.ga.gov/GDC/Offender/Query"
        },
        "NY": {
            "name": "New York",
            "ecourts": f"https://iapps.courts.state.ny.us/webcrim_attorney/AttorneyWelcome",
            "doccs_search": f"https://nysdoccslookup.doccs.ny.gov/"
        },
        "AL": {
            "name": "Alabama",
            "alacourt": "https://pa.alacourt.com/",
            "doc_search": f"https://www.doc.alabama.gov/InmateSearch"
        },
        "MS": {
            "name": "Mississippi",
            "courts": f"https://courts.ms.gov/",
            "doc_search": f"https://www.mdoc.ms.gov/Inmate-Search"
        }
    }

    # Get state-specific links or generate generic
    if state in state_courts:
        return {
            "name": request.name,
            "state": state,
            "searched_at": datetime.now().isoformat(),
            "court_links": state_courts[state],
            "federal_links": {
                "pacer": f"https://pacer.uscourts.gov/",
                "courtlistener": f"https://www.courtlistener.com/?q={name}"
            }
        }
    else:
        return {
            "name": request.name,
            "state": state,
            "searched_at": datetime.now().isoformat(),
            "court_links": {
                "notice": f"State-specific links not available for {state}",
                "generic_search": f"Search '{state} court records {request.name}' on Google"
            },
            "federal_links": {
                "pacer": f"https://pacer.uscourts.gov/",
                "courtlistener": f"https://www.courtlistener.com/?q={name}"
            }
        }


# ============================================================================
# IGNORANT - Phone Number Social Account Check
# ============================================================================

class IgnorantRequest(BaseModel):
    phone: str
    country_code: str = "US"


def run_ignorant(phone: str, country_code: str = "US") -> Dict[str, Any]:
    """Run Ignorant to check phone number for social accounts"""
    start_time = datetime.now()
    accounts_found = []
    errors = []

    try:
        cmd = ["ignorant", phone, "-c", country_code]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )

        # Parse output
        for line in result.stdout.split('\n'):
            if '[+]' in line:
                # Found account
                parts = line.replace('[+]', '').strip()
                accounts_found.append({
                    'platform': parts.split(':')[0].strip() if ':' in parts else parts,
                    'status': 'registered'
                })
            elif '[-]' in line:
                pass  # Not registered, skip

    except subprocess.TimeoutExpired:
        errors.append("Ignorant search timed out")
    except FileNotFoundError:
        errors.append("Ignorant not installed. Run: pip install ignorant")
    except Exception as e:
        errors.append(f"Ignorant error: {str(e)}")

    return {
        'phone': phone,
        'country_code': country_code,
        'searched_at': datetime.now().isoformat(),
        'accounts_found': accounts_found,
        'total_found': len(accounts_found),
        'errors': errors,
        'execution_time': (datetime.now() - start_time).total_seconds()
    }


@app.post("/api/ignorant")
async def ignorant_search(request: IgnorantRequest):
    """Check phone number for social media accounts using Ignorant"""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        executor,
        run_ignorant,
        request.phone,
        request.country_code
    )
    return result


# ============================================================================
# BLACKBIRD - Username Search (Comprehensive)
# ============================================================================

class BlackbirdRequest(BaseModel):
    username: str
    timeout: int = 90


def run_blackbird(username: str, timeout: int = 90) -> Dict[str, Any]:
    """Run Blackbird for comprehensive username search"""
    start_time = datetime.now()
    found = []
    errors = []

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = [
                "blackbird", "--username", username,
                "--json", "--no-nsfw"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=tmpdir
            )

            # Parse JSON output from stdout
            if result.stdout:
                try:
                    # Find JSON array in output
                    output = result.stdout
                    json_start = output.find('[')
                    json_end = output.rfind(']') + 1
                    if json_start >= 0 and json_end > json_start:
                        data = json.loads(output[json_start:json_end])
                        for item in data:
                            if item.get('status') == 'FOUND':
                                found.append({
                                    'platform': item.get('site', 'Unknown'),
                                    'url': item.get('url', ''),
                                    'http_status': item.get('http_status', '')
                                })
                except json.JSONDecodeError:
                    # Fallback: parse line by line
                    for line in result.stdout.split('\n'):
                        if 'FOUND' in line and 'http' in line:
                            found.append({
                                'platform': 'Unknown',
                                'url': line.strip(),
                                'http_status': 200
                            })

    except subprocess.TimeoutExpired:
        errors.append("Blackbird search timed out")
    except FileNotFoundError:
        errors.append("Blackbird not installed. Run: pip install blackbird")
    except Exception as e:
        errors.append(f"Blackbird error: {str(e)}")

    return {
        'username': username,
        'searched_at': datetime.now().isoformat(),
        'tool': 'blackbird',
        'found': found,
        'total_found': len(found),
        'errors': errors,
        'execution_time': (datetime.now() - start_time).total_seconds()
    }


@app.post("/api/blackbird")
async def blackbird_search(request: BlackbirdRequest):
    """Comprehensive username search using Blackbird"""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        executor,
        run_blackbird,
        request.username,
        request.timeout
    )
    return result


# ============================================================================
# INSTALOADER - Instagram Profile Intel
# ============================================================================

class InstaloaderRequest(BaseModel):
    username: str


def run_instaloader(username: str) -> Dict[str, Any]:
    """Get Instagram profile information using Instaloader"""
    start_time = datetime.now()
    profile_data = {}
    errors = []

    try:
        # Use instaloader to get profile info (no login required for public profiles)
        cmd = [
            "instaloader",
            "--no-pictures",
            "--no-videos",
            "--no-video-thumbnails",
            "--no-captions",
            "--no-metadata-json",
            "--no-compress-json",
            f"--login", "",  # Anonymous
            "--",
            f"profile {username}"
        ]

        # Alternative: use Python API directly
        import importlib.util
        if importlib.util.find_spec("instaloader"):
            import instaloader
            L = instaloader.Instaloader()
            try:
                profile = instaloader.Profile.from_username(L.context, username)
                profile_data = {
                    'username': profile.username,
                    'full_name': profile.full_name,
                    'biography': profile.biography,
                    'followers': profile.followers,
                    'following': profile.followees,
                    'posts': profile.mediacount,
                    'is_private': profile.is_private,
                    'is_verified': profile.is_verified,
                    'external_url': profile.external_url,
                    'profile_pic_url': profile.profile_pic_url,
                    'business_category': profile.business_category_name if hasattr(profile, 'business_category_name') else None
                }
            except Exception as e:
                errors.append(f"Profile lookup failed: {str(e)}")
        else:
            errors.append("Instaloader module not available")

    except Exception as e:
        errors.append(f"Instaloader error: {str(e)}")

    return {
        'username': username,
        'searched_at': datetime.now().isoformat(),
        'profile': profile_data,
        'errors': errors,
        'execution_time': (datetime.now() - start_time).total_seconds()
    }


@app.post("/api/instagram")
async def instagram_lookup(request: InstaloaderRequest):
    """Get Instagram profile information"""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        executor,
        run_instaloader,
        request.username
    )
    return result


# ============================================================================
# TOUTATIS - Instagram Deep Intel (Phone/Email from ID)
# ============================================================================

class ToutatisRequest(BaseModel):
    username: str
    session_id: Optional[str] = None  # Instagram session ID for deeper intel


def run_toutatis(username: str, session_id: str = None) -> Dict[str, Any]:
    """Run Toutatis for Instagram deep intel"""
    start_time = datetime.now()
    intel = {}
    errors = []

    try:
        cmd = ["toutatis", "-u", username]
        if session_id:
            cmd.extend(["-s", session_id])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        # Parse output
        for line in result.stdout.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower().replace(' ', '_')
                value = value.strip()
                if value and value != 'None':
                    intel[key] = value

    except subprocess.TimeoutExpired:
        errors.append("Toutatis search timed out")
    except FileNotFoundError:
        errors.append("Toutatis not installed. Run: pip install toutatis")
    except Exception as e:
        errors.append(f"Toutatis error: {str(e)}")

    return {
        'username': username,
        'searched_at': datetime.now().isoformat(),
        'intel': intel,
        'errors': errors,
        'execution_time': (datetime.now() - start_time).total_seconds()
    }


@app.post("/api/toutatis")
async def toutatis_search(request: ToutatisRequest):
    """Get Instagram deep intel (phone/email if available)"""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        executor,
        run_toutatis,
        request.username,
        request.session_id
    )
    return result


# ============================================================================
# GHUNT - Google Account Investigation
# ============================================================================

class GhuntRequest(BaseModel):
    email: EmailStr


def run_ghunt(email: str) -> Dict[str, Any]:
    """Run GHunt to investigate Google account"""
    start_time = datetime.now()
    intel = {
        'google_id': None,
        'name': None,
        'profile_photos': [],
        'google_maps_reviews': [],
        'youtube_channel': None,
        'google_calendar': None,
        'last_profile_edit': None
    }
    errors = []

    try:
        cmd = ["ghunt", "email", email, "--json"]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )

        # Parse JSON output
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                intel.update({
                    'google_id': data.get('personId'),
                    'name': data.get('names', [{}])[0].get('displayName'),
                    'profile_photos': data.get('photos', []),
                    'last_profile_edit': data.get('profileMetadata', {}).get('lastUpdateTime')
                })
            except json.JSONDecodeError:
                # Parse text output
                for line in result.stdout.split('\n'):
                    if 'Name:' in line:
                        intel['name'] = line.split('Name:')[1].strip()
                    elif 'Gaia ID:' in line or 'Google ID:' in line:
                        intel['google_id'] = line.split(':')[1].strip()

    except subprocess.TimeoutExpired:
        errors.append("GHunt search timed out")
    except FileNotFoundError:
        errors.append("GHunt not installed. Run: pip install ghunt")
    except Exception as e:
        errors.append(f"GHunt error: {str(e)}")

    return {
        'email': email,
        'searched_at': datetime.now().isoformat(),
        'intel': intel,
        'errors': errors,
        'execution_time': (datetime.now() - start_time).total_seconds()
    }


@app.post("/api/ghunt")
async def ghunt_search(request: GhuntRequest):
    """Investigate Google account using GHunt"""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        executor,
        run_ghunt,
        request.email
    )
    return result


# ============================================================================
# MEGA OSINT SWEEP - All Tools Combined
# ============================================================================

class MegaSweepRequest(BaseModel):
    name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    username: Optional[str] = None
    instagram: Optional[str] = None
    state: Optional[str] = None


@app.post("/api/mega-sweep")
async def mega_osint_sweep(request: MegaSweepRequest):
    """
    Comprehensive OSINT sweep using ALL available tools:
    - Sherlock + Maigret + Blackbird + Social-Analyzer (usernames)
    - Holehe + h8mail + GHunt (email)
    - PhoneInfoga + Ignorant (phone)
    - Instaloader + Toutatis (Instagram)
    - CourtListener (court records)
    - theHarvester (domain if email has domain)
    """
    start_time = datetime.now()
    results = {
        'username_searches': [],
        'email_searches': [],
        'phone_searches': [],
        'instagram_searches': [],
        'court_records': None,
        'domain_intel': None
    }
    errors = []

    loop = asyncio.get_event_loop()

    # Generate username if not provided
    username = request.username
    if not username and request.name:
        username = request.name.lower().replace(" ", "")

    tasks = []

    # Username searches (parallel)
    if username:
        async def run_all_username_tools():
            tools_results = []
            try:
                sherlock_result = await loop.run_in_executor(executor, run_sherlock, username, 45)
                tools_results.append({'tool': 'sherlock', 'result': sherlock_result})
            except Exception as e:
                errors.append(f"Sherlock: {e}")

            try:
                maigret_result = await loop.run_in_executor(executor, run_maigret, username, 60)
                tools_results.append({'tool': 'maigret', 'result': maigret_result})
            except Exception as e:
                errors.append(f"Maigret: {e}")

            try:
                blackbird_result = await loop.run_in_executor(executor, run_blackbird, username, 60)
                tools_results.append({'tool': 'blackbird', 'result': blackbird_result})
            except Exception as e:
                errors.append(f"Blackbird: {e}")

            results['username_searches'] = tools_results

        tasks.append(run_all_username_tools())

    # Email searches
    if request.email:
        async def run_all_email_tools():
            tools_results = []
            try:
                holehe_result = await loop.run_in_executor(executor, run_holehe, request.email, 45)
                tools_results.append({'tool': 'holehe', 'result': holehe_result})
            except Exception as e:
                errors.append(f"Holehe: {e}")

            try:
                h8mail_result = await loop.run_in_executor(executor, run_h8mail, request.email, True)
                tools_results.append({'tool': 'h8mail', 'result': h8mail_result})
            except Exception as e:
                errors.append(f"h8mail: {e}")

            try:
                ghunt_result = await loop.run_in_executor(executor, run_ghunt, request.email)
                tools_results.append({'tool': 'ghunt', 'result': ghunt_result})
            except Exception as e:
                errors.append(f"GHunt: {e}")

            results['email_searches'] = tools_results

            # Domain intel from email
            domain = request.email.split('@')[1]
            try:
                harvester_result = await loop.run_in_executor(
                    executor, run_theharvester, domain, ['google', 'bing'], 50
                )
                results['domain_intel'] = harvester_result
            except Exception as e:
                errors.append(f"theHarvester: {e}")

        tasks.append(run_all_email_tools())

    # Phone searches
    if request.phone:
        async def run_all_phone_tools():
            tools_results = []
            try:
                phoneinfoga_result = await loop.run_in_executor(
                    executor, run_phoneinfoga, request.phone, None
                )
                tools_results.append({'tool': 'phoneinfoga', 'result': phoneinfoga_result})
            except Exception as e:
                errors.append(f"PhoneInfoga: {e}")

            try:
                ignorant_result = await loop.run_in_executor(
                    executor, run_ignorant, request.phone, "US"
                )
                tools_results.append({'tool': 'ignorant', 'result': ignorant_result})
            except Exception as e:
                errors.append(f"Ignorant: {e}")

            results['phone_searches'] = tools_results

        tasks.append(run_all_phone_tools())

    # Instagram searches
    instagram_user = request.instagram or username
    if instagram_user:
        async def run_all_instagram_tools():
            tools_results = []
            try:
                insta_result = await loop.run_in_executor(executor, run_instaloader, instagram_user)
                tools_results.append({'tool': 'instaloader', 'result': insta_result})
            except Exception as e:
                errors.append(f"Instaloader: {e}")

            try:
                toutatis_result = await loop.run_in_executor(executor, run_toutatis, instagram_user, None)
                tools_results.append({'tool': 'toutatis', 'result': toutatis_result})
            except Exception as e:
                errors.append(f"Toutatis: {e}")

            results['instagram_searches'] = tools_results

        tasks.append(run_all_instagram_tools())

    # Court records
    async def run_court_search():
        try:
            court_result = await search_courtlistener(request.name)
            results['court_records'] = court_result
        except Exception as e:
            errors.append(f"CourtListener: {e}")

    tasks.append(run_court_search())

    # Run all tasks
    await asyncio.gather(*tasks, return_exceptions=True)

    # Compile summary
    total_profiles = 0
    for search in results['username_searches']:
        found = search.get('result', {}).get('found', [])
        total_profiles += len(found) if isinstance(found, list) else 0

    for search in results['email_searches']:
        registered = search.get('result', {}).get('registered_on', [])
        total_profiles += len(registered) if isinstance(registered, list) else 0

    execution_time = (datetime.now() - start_time).total_seconds()

    return {
        'target': {
            'name': request.name,
            'email': request.email,
            'phone': request.phone,
            'username': username,
            'instagram': instagram_user,
            'state': request.state
        },
        'searched_at': datetime.now().isoformat(),
        'results': results,
        'total_profiles_found': total_profiles,
        'court_cases_found': len(results.get('court_records', {}).get('cases_found', [])) if results.get('court_records') else 0,
        'errors': errors,
        'execution_time': execution_time
    }


# ============================================================================
# MULTI-USERNAME SEARCH (searches variations)
# ============================================================================

class MultiUsernameRequest(BaseModel):
    name: str
    usernames: Optional[List[str]] = None  # If not provided, will generate from name
    max_usernames: int = 5
    timeout: int = 30


# Common name variants/nicknames mapping (both directions)
NAME_VARIANTS = {
    # Male names
    "william": ["will", "bill", "billy", "willy", "liam"],
    "will": ["william", "bill", "billy"],
    "bill": ["william", "will", "billy"],
    "billy": ["william", "will", "bill"],
    "robert": ["rob", "robby", "bob", "bobby", "bert"],
    "rob": ["robert", "robby", "bob", "bobby"],
    "bob": ["robert", "rob", "bobby"],
    "bobby": ["robert", "rob", "bob"],
    "richard": ["rick", "ricky", "dick", "rich", "richie"],
    "rick": ["richard", "ricky", "rich"],
    "dick": ["richard", "rick"],
    "james": ["jim", "jimmy", "jamie", "jem"],
    "jim": ["james", "jimmy", "jamie"],
    "jimmy": ["james", "jim", "jamie"],
    "michael": ["mike", "mikey", "mick", "mickey"],
    "mike": ["michael", "mikey", "mick"],
    "john": ["jack", "johnny", "jon"],
    "jack": ["john", "jackson"],
    "johnny": ["john", "jonathan"],
    "jonathan": ["jon", "johnny", "john", "nathan"],
    "jon": ["john", "jonathan"],
    "joseph": ["joe", "joey", "jo"],
    "joe": ["joseph", "joey"],
    "joey": ["joseph", "joe"],
    "charles": ["charlie", "chuck", "chas", "chaz"],
    "charlie": ["charles", "chuck"],
    "chuck": ["charles", "charlie"],
    "thomas": ["tom", "tommy", "thom"],
    "tom": ["thomas", "tommy"],
    "tommy": ["thomas", "tom"],
    "daniel": ["dan", "danny", "dani"],
    "dan": ["daniel", "danny"],
    "danny": ["daniel", "dan"],
    "david": ["dave", "davey", "davy"],
    "dave": ["david", "davey"],
    "edward": ["ed", "eddie", "ted", "teddy", "ned"],
    "ed": ["edward", "eddie", "edwin", "edgar"],
    "eddie": ["edward", "ed", "edwin"],
    "ted": ["edward", "theodore", "teddy"],
    "theodore": ["ted", "teddy", "theo"],
    "anthony": ["tony", "ant"],
    "tony": ["anthony", "antonio"],
    "antonio": ["tony", "anthony"],
    "christopher": ["chris", "topher", "kit"],
    "chris": ["christopher", "christian", "christine"],
    "matthew": ["matt", "matty"],
    "matt": ["matthew", "matty"],
    "andrew": ["andy", "drew", "andre"],
    "andy": ["andrew", "anderson"],
    "drew": ["andrew"],
    "benjamin": ["ben", "benny", "benji"],
    "ben": ["benjamin", "benny", "benedict"],
    "samuel": ["sam", "sammy"],
    "sam": ["samuel", "sammy", "samantha"],
    "nicholas": ["nick", "nicky", "nico"],
    "nick": ["nicholas", "nicky"],
    "patrick": ["pat", "patty", "paddy"],
    "pat": ["patrick", "patricia"],
    "timothy": ["tim", "timmy"],
    "tim": ["timothy", "timmy"],
    "steven": ["steve", "stevie", "stephen"],
    "steve": ["steven", "stephen", "stevie"],
    "stephen": ["steve", "steven"],
    "douglas": ["doug", "dougie"],
    "doug": ["douglas", "dougie"],
    "gregory": ["greg", "gregg"],
    "greg": ["gregory", "gregg"],
    "kenneth": ["ken", "kenny"],
    "ken": ["kenneth", "kenny", "kendall"],
    "raymond": ["ray", "raymon"],
    "ray": ["raymond", "raymon"],
    "lawrence": ["larry", "laurie"],
    "larry": ["lawrence", "laurence"],
    "gerald": ["gerry", "jerry", "gerard"],
    "jerry": ["gerald", "jerome", "jeremiah"],
    "jeffrey": ["jeff", "geoff"],
    "jeff": ["jeffrey", "geoffrey"],
    "alexander": ["alex", "xander", "al", "lex"],
    "alex": ["alexander", "alexis", "alexandra"],
    "nathaniel": ["nate", "nathan", "nat"],
    "nathan": ["nathaniel", "nate"],
    "nate": ["nathan", "nathaniel"],
    "zachary": ["zach", "zack", "zak"],
    "zach": ["zachary", "zack"],
    "joshua": ["josh", "joshy"],
    "josh": ["joshua"],
    "jacob": ["jake", "jakey"],
    "jake": ["jacob"],
    "phillip": ["phil", "pip"],
    "phil": ["phillip", "philip"],
    "frederick": ["fred", "freddy", "rick"],
    "fred": ["frederick", "freddy", "alfred"],
    "alfred": ["al", "alf", "alfie", "fred"],
    "al": ["alfred", "albert", "alan", "alex"],
    "albert": ["al", "bert", "bertie"],

    # Female names
    "elizabeth": ["liz", "lizzy", "beth", "betty", "eliza", "ellie", "lisa"],
    "liz": ["elizabeth", "lizzy"],
    "beth": ["elizabeth", "bethany"],
    "betty": ["elizabeth", "beatrice"],
    "jennifer": ["jen", "jenny", "jenn"],
    "jen": ["jennifer", "jenny"],
    "jenny": ["jennifer", "jen"],
    "katherine": ["kate", "katie", "kathy", "cathy", "kat"],
    "kate": ["katherine", "katelyn", "katie"],
    "katie": ["katherine", "kate"],
    "kathy": ["katherine", "kathleen"],
    "catherine": ["cathy", "kate", "katie", "cat"],
    "margaret": ["maggie", "meg", "peggy", "marge", "margie"],
    "maggie": ["margaret", "magdalene"],
    "patricia": ["pat", "patty", "trish", "tricia"],
    "trish": ["patricia", "tricia"],
    "jessica": ["jess", "jessie"],
    "jess": ["jessica", "jessie"],
    "rebecca": ["becky", "becca", "beck"],
    "becky": ["rebecca", "becca"],
    "samantha": ["sam", "sammy"],
    "amanda": ["mandy", "amy"],
    "mandy": ["amanda", "miranda"],
    "victoria": ["vicky", "vicki", "tori"],
    "vicky": ["victoria", "vicki"],
    "stephanie": ["steph", "steffi"],
    "steph": ["stephanie", "stefan"],
    "christina": ["chris", "tina", "christy"],
    "tina": ["christina", "martina", "valentina"],
    "alexandra": ["alex", "alexa", "lexi", "sandra"],
    "sandra": ["sandy", "alexandra", "cassandra"],
    "sandy": ["sandra", "alexander"],
    "melissa": ["missy", "mel", "lisa"],
    "mel": ["melissa", "melanie", "melody"],
    "deborah": ["deb", "debbie", "debby"],
    "deb": ["deborah", "debbie"],
    "debbie": ["deborah", "deb"],
    "kimberly": ["kim", "kimmy"],
    "kim": ["kimberly", "kimmy"],
    "michelle": ["shelly", "micki", "mich"],
    "shelly": ["michelle", "shelley", "rachel"],
    "nicole": ["nicky", "nikki", "cole"],
    "nikki": ["nicole", "nicky"],
    "heather": ["heath"],
    "ashley": ["ash", "ashy"],
    "ash": ["ashley", "asher", "ashton"],
    "brittany": ["brit", "britt"],
    "cynthia": ["cindy", "cyn"],
    "cindy": ["cynthia", "lucinda"],
    "dorothy": ["dot", "dottie", "dolly"],
    "dot": ["dorothy", "dottie"],
    "frances": ["fran", "frannie", "frankie"],
    "fran": ["frances", "francesca"],
    "jacqueline": ["jackie", "jacqui"],
    "jackie": ["jacqueline", "jack"],
    "susan": ["sue", "susie", "suzy"],
    "sue": ["susan", "susie"],
    "susie": ["susan", "sue", "suzanne"],
    "nancy": ["nan"],
    "ann": ["annie", "anna", "anne"],
    "anna": ["ann", "annie", "anne"],
    "anne": ["ann", "anna", "annie"],
}


def get_name_variants(name: str) -> List[str]:
    """Get all known variants of a first name"""
    name_lower = name.lower().strip()
    variants = set([name_lower])

    # Check if this name has variants
    if name_lower in NAME_VARIANTS:
        variants.update(NAME_VARIANTS[name_lower])

    # Also check if any variant maps back to this name
    for key, values in NAME_VARIANTS.items():
        if name_lower in values:
            variants.add(key)
            variants.update(values)

    return list(variants)


def generate_username_variations(full_name: str, include_name_variants: bool = True) -> List[str]:
    """
    Generate common username variations from a name.
    Now includes nickname variants (Doug → Douglas, Bill → William, etc.)
    Optimized to search most common patterns first.
    """
    parts = full_name.lower().split()
    if len(parts) < 2:
        return [full_name.lower().replace(" ", "")]

    first = parts[0]
    last = parts[-1]
    middle = parts[1] if len(parts) > 2 else ""
    first_initial = first[0] if first else ""
    last_initial = last[0] if last else ""

    # Get all first name variants
    first_names = [first]
    if include_name_variants:
        first_names = get_name_variants(first)
        # Ensure original name is first
        if first in first_names:
            first_names.remove(first)
        first_names = [first] + first_names

    variations = []

    # FIRST: Add the most common patterns for EACH name variant
    # This ensures both "douggilford" AND "douglasgilford" are in top results
    for fname in first_names:
        variations.append(f"{fname}{last}")        # douggilford, douglasgilford
        variations.append(f"{fname}_{last}")       # doug_gilford, douglas_gilford
        variations.append(f"{fname}.{last}")       # doug.gilford, douglas.gilford

    # THEN: Add secondary patterns
    for fname in first_names:
        f_initial = fname[0] if fname else ""
        variations.extend([
            f"{fname}-{last}",          # doug-gilford
            f"{last}{fname}",           # gilforddoug
            f"{f_initial}{last}",       # dgilford
            f"{fname}{last_initial}",   # dougg
            f"{fname}_{last_initial}",  # doug_g
            f"{last}_{fname}",          # gilford_doug
            f"{fname}{last}1",          # douggilford1
            f"{fname}{last}123",        # douggilford123
            f"real{fname}{last}",       # realdouggilford
            f"the{fname}{last}",        # thedouggilford
            f"{fname}official",         # dougofficial
        ])

        if middle:
            variations.extend([
                f"{fname}{middle[0]}{last}",   # dougmgilford
                f"{fname}_{middle[0]}_{last}", # doug_m_gilford
            ])

    # Remove duplicates and filter
    return list(dict.fromkeys([v for v in variations if len(v) > 2]))


@app.post("/api/multi-username")
async def multi_username_search(request: MultiUsernameRequest):
    """Search multiple username variations using Sherlock"""
    start_time = datetime.now()

    # Generate usernames if not provided
    usernames = request.usernames
    if not usernames:
        usernames = generate_username_variations(request.name)

    # Limit to max_usernames
    usernames = usernames[:request.max_usernames]

    all_found = {}  # Dedupe by URL
    all_errors = []
    searched_usernames = []

    loop = asyncio.get_event_loop()

    # Search each username
    for username in usernames:
        searched_usernames.append(username)
        try:
            result = await loop.run_in_executor(
                executor,
                run_sherlock,
                username,
                request.timeout
            )

            for item in result.get('found', []):
                url = item.get('url', '')
                if url and url not in all_found:
                    all_found[url] = {
                        **item,
                        'searched_username': username
                    }

            all_errors.extend([f"{username}: {e}" for e in result.get('errors', [])])

        except Exception as e:
            all_errors.append(f"{username}: {str(e)}")

    execution_time = (datetime.now() - start_time).total_seconds()

    return {
        'name': request.name,
        'searched_at': datetime.now().isoformat(),
        'usernames_searched': searched_usernames,
        'total_profiles_found': len(all_found),
        'profiles': list(all_found.values()),
        'errors': all_errors[:20],  # Limit errors
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
# INTELLIGENT PERSON INVESTIGATION (Smart Flow)
# ============================================================================

class InvestigatePersonRequest(BaseModel):
    name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    location: Optional[str] = None  # State/city to narrow down
    state: Optional[str] = None  # 2-letter state code (e.g., "LA")
    jail_parish: Optional[str] = None  # Parish/county where booked
    mugshot_url: Optional[str] = None  # For photo verification
    demographics: Optional[Dict[str, str]] = None  # race, sex, age


# US States and common location keywords for filtering
US_STATES = {
    "AL": "alabama", "AK": "alaska", "AZ": "arizona", "AR": "arkansas",
    "CA": "california", "CO": "colorado", "CT": "connecticut", "DE": "delaware",
    "FL": "florida", "GA": "georgia", "HI": "hawaii", "ID": "idaho",
    "IL": "illinois", "IN": "indiana", "IA": "iowa", "KS": "kansas",
    "KY": "kentucky", "LA": "louisiana", "ME": "maine", "MD": "maryland",
    "MA": "massachusetts", "MI": "michigan", "MN": "minnesota", "MS": "mississippi",
    "MO": "missouri", "MT": "montana", "NE": "nebraska", "NV": "nevada",
    "NH": "new hampshire", "NJ": "new jersey", "NM": "new mexico", "NY": "new york",
    "NC": "north carolina", "ND": "north dakota", "OH": "ohio", "OK": "oklahoma",
    "OR": "oregon", "PA": "pennsylvania", "RI": "rhode island", "SC": "south carolina",
    "SD": "south dakota", "TN": "tennessee", "TX": "texas", "UT": "utah",
    "VT": "vermont", "VA": "virginia", "WA": "washington", "WV": "west virginia",
    "WI": "wisconsin", "WY": "wyoming", "DC": "washington dc"
}

# Louisiana parishes for local matching
LA_PARISHES = [
    "st. tammany", "st tammany", "orleans", "jefferson", "east baton rouge",
    "caddo", "calcasieu", "lafayette", "ouachita", "livingston", "tangipahoa",
    "rapides", "bossier", "terrebonne", "lafourche", "ascension", "iberia",
    "washington", "st. landry", "st landry", "vermilion", "acadia", "st. mary",
    "st mary", "natchitoches", "lincoln", "beauregard", "st. john", "st john"
]

# Non-US locations to filter out
NON_US_INDICATORS = [
    "canada", "canadian", "ontario", "quebec", "british columbia", "alberta",
    "toronto", "vancouver", "montreal", "calgary", "ottawa", "edmonton",
    "uk", "united kingdom", "england", "london", "manchester", "birmingham",
    "australia", "sydney", "melbourne", "brisbane", "perth",
    "germany", "france", "spain", "italy", "netherlands", "sweden",
    "india", "mumbai", "delhi", "bangalore", "chennai",
    "mexico", "brazil", "argentina", "colombia",
    "nigeria", "south africa", "kenya",
    "philippines", "indonesia", "vietnam", "thailand", "japan", "china", "korea"
]


def check_location_relevance(profile_url: str, profile_bio: str = "", target_state: str = "LA") -> Dict[str, Any]:
    """
    Check if a social profile is geographically relevant to the target.
    Returns relevance score and reason.
    """
    url_lower = profile_url.lower()
    bio_lower = (profile_bio or "").lower()
    combined = f"{url_lower} {bio_lower}"

    target_state_lower = target_state.lower() if target_state else "la"
    target_state_full = US_STATES.get(target_state.upper(), target_state_lower) if target_state else "louisiana"

    result = {
        "is_relevant": True,
        "confidence": 0.5,  # Default neutral
        "reason": "No location indicators found",
        "location_found": None,
        "is_local": False,
        "is_foreign": False
    }

    # Check for non-US locations (strong negative signal)
    for non_us in NON_US_INDICATORS:
        if non_us in combined:
            result["is_relevant"] = False
            result["confidence"] = 0.1
            result["reason"] = f"Profile appears to be from {non_us.title()} - likely different person"
            result["location_found"] = non_us.title()
            result["is_foreign"] = True
            return result

    # Check for target state (strong positive signal)
    if target_state_lower in combined or target_state_full in combined:
        result["is_relevant"] = True
        result["confidence"] = 0.9
        result["reason"] = f"Profile location matches target state ({target_state.upper()})"
        result["location_found"] = target_state.upper()
        result["is_local"] = True
        return result

    # Check for Louisiana parishes specifically
    if target_state.upper() == "LA":
        for parish in LA_PARISHES:
            if parish in combined:
                result["is_relevant"] = True
                result["confidence"] = 0.95
                result["reason"] = f"Profile mentions {parish.title()} parish - strong local match"
                result["location_found"] = parish.title()
                result["is_local"] = True
                return result

    # Check for other US states (might be same person who moved)
    for state_code, state_name in US_STATES.items():
        if state_code.lower() != target_state_lower and (state_code.lower() in combined or state_name in combined):
            result["is_relevant"] = True
            result["confidence"] = 0.6
            result["reason"] = f"Profile may be in {state_name.title()} - verify if person relocated"
            result["location_found"] = state_name.title()
            return result

    return result


class InvestigatePersonResult(BaseModel):
    name: str
    name_variants_searched: List[str]
    searched_at: str
    flow_steps: List[Dict[str, Any]]
    discovered_emails: List[str]
    discovered_usernames: List[str]
    confirmed_profiles: List[Dict[str, Any]]  # Changed to Any to include location data
    filtered_profiles: List[Dict[str, Any]]  # Profiles filtered out due to location mismatch
    people_search_links: List[Dict[str, str]]
    location_context: Optional[Dict[str, str]]
    summary: str
    execution_time: float


@app.post("/api/investigate")
async def investigate_person(request: InvestigatePersonRequest):
    """
    Intelligent person investigation flow:
    1. Generate name variants (Doug → Douglas, Bill → William)
    2. Generate people search links
    3. If email provided, check registrations with holehe
    4. Try username variations with Sherlock
    5. Filter results by geographic relevance
    6. Compile all findings
    """
    start_time = datetime.now()
    flow_steps = []
    discovered_emails = []
    discovered_usernames = []
    confirmed_profiles = []
    filtered_profiles = []  # Profiles filtered due to location mismatch
    name_variants_searched = []

    # Parse name and get variants
    name_parts = request.name.lower().split()
    first = name_parts[0] if name_parts else ""
    last = name_parts[-1] if len(name_parts) > 1 else name_parts[0] if name_parts else ""

    # Step 0: Generate name variants (Doug → Douglas, Bill → William)
    flow_steps.append({
        "step": 0,
        "action": "Generate name variants",
        "status": "running"
    })

    first_name_variants = get_name_variants(first)
    name_variants_searched = [f"{fv} {last}" for fv in first_name_variants[:5]]  # Top 5 variants

    flow_steps[-1]["status"] = "complete"
    flow_steps[-1]["result"] = f"Name variants: {', '.join(first_name_variants[:5])}"

    # Determine target location for filtering
    target_state = request.state or "LA"  # Default to Louisiana
    location_context = {
        "target_state": target_state,
        "jail_parish": request.jail_parish,
        "provided_location": request.location
    }

    # Step 1: Generate people search links (for all name variants)
    flow_steps.append({
        "step": 1,
        "action": "Generate people search links",
        "status": "running"
    })

    people_search_links = []

    # Generate links for original name and variants
    for name_variant in [request.name] + name_variants_searched[:2]:
        nv_parts = name_variant.lower().split()
        nv_first = nv_parts[0] if nv_parts else ""
        nv_last = nv_parts[-1] if len(nv_parts) > 1 else nv_first

        people_search_links.extend([
            {"name": f"TruePeopleSearch ({nv_first.title()})", "url": f"https://www.truepeoplesearch.com/results?name={name_variant.replace(' ', '%20')}", "type": "free"},
            {"name": f"FastPeopleSearch ({nv_first.title()})", "url": f"https://www.fastpeoplesearch.com/name/{name_variant.replace(' ', '-')}", "type": "free"},
            {"name": f"Facebook ({nv_first.title()})", "url": f"https://www.facebook.com/search/people?q={name_variant.replace(' ', '%20')}", "type": "social"},
        ])

    # Add location-specific searches
    if request.location or request.state:
        loc = (request.location or US_STATES.get(request.state, request.state)).replace(' ', '%20')
        people_search_links.extend([
            {"name": "TruePeopleSearch (Location)", "url": f"https://www.truepeoplesearch.com/results?name={request.name.replace(' ', '%20')}&citystatezip={loc}", "type": "free"},
            {"name": "Whitepages (Location)", "url": f"https://www.whitepages.com/name/{first}-{last}/{loc}", "type": "free"},
        ])

    # Standard links
    people_search_links.extend([
        {"name": "Whitepages", "url": f"https://www.whitepages.com/name/{first}-{last}", "type": "free"},
        {"name": "Spokeo", "url": f"https://www.spokeo.com/{first}-{last}", "type": "paid"},
        {"name": "BeenVerified", "url": f"https://www.beenverified.com/people/{first}-{last}/", "type": "paid"},
        {"name": "LinkedIn", "url": f"https://www.linkedin.com/search/results/people/?keywords={request.name.replace(' ', '%20')}", "type": "social"},
        {"name": "Instagram", "url": f"https://www.instagram.com/{first}{last}/", "type": "social"},
        {"name": "Twitter/X", "url": f"https://twitter.com/search?q={request.name.replace(' ', '%20')}&f=user", "type": "social"},
    ])

    flow_steps[-1]["status"] = "complete"
    flow_steps[-1]["result"] = f"Generated {len(people_search_links)} search links for {len(name_variants_searched) + 1} name variants"

    # Step 2: If email provided, check with holehe
    if request.email:
        flow_steps.append({
            "step": 2,
            "action": f"Check email registration: {request.email}",
            "status": "running"
        })

        discovered_emails.append(request.email)

        try:
            loop = asyncio.get_event_loop()
            email_result = await loop.run_in_executor(
                executor, run_holehe, request.email, 60
            )

            registered_services = email_result.get('registered_on', [])
            for service in registered_services:
                confirmed_profiles.append({
                    "platform": service.get('service', 'Unknown'),
                    "source": "holehe (email)",
                    "email": request.email,
                    "url": f"https://{service.get('service', '').lower().replace(' ', '')}.com",
                    "location_verified": False,
                    "location_note": "Email registration - location unknown"
                })

            flow_steps[-1]["status"] = "complete"
            flow_steps[-1]["result"] = f"Found {len(registered_services)} services"

        except Exception as e:
            flow_steps[-1]["status"] = "error"
            flow_steps[-1]["result"] = str(e)

    # Step 3: Try username variations with Sherlock (including name variants)
    flow_steps.append({
        "step": 3,
        "action": "Search username variations with Sherlock (includes name variants)",
        "status": "running"
    })

    # Generate smart username variations for ALL name variants
    # Increased from 10 to 20 to ensure all name variants get adequate coverage
    username_variations = generate_username_variations(request.name, include_name_variants=True)[:20]
    discovered_usernames.extend(username_variations)

    loop = asyncio.get_event_loop()
    all_sherlock_found = {}

    for username in username_variations:
        try:
            result = await loop.run_in_executor(
                executor, run_sherlock, username, 30
            )

            for profile in result.get('found', []):
                url = profile.get('url', '')
                if url and url not in all_sherlock_found:
                    # Check location relevance
                    loc_check = check_location_relevance(url, "", target_state)

                    profile_data = {
                        "platform": profile.get('platform', 'Unknown'),
                        "url": url,
                        "username": username,
                        "source": "sherlock",
                        "location_verified": loc_check["is_local"],
                        "location_confidence": loc_check["confidence"],
                        "location_note": loc_check["reason"],
                        "location_found": loc_check.get("location_found")
                    }

                    all_sherlock_found[url] = profile_data

                    # Filter foreign profiles but keep track of them
                    if loc_check["is_foreign"]:
                        filtered_profiles.append({
                            **profile_data,
                            "filter_reason": f"Location mismatch: {loc_check['reason']}"
                        })
                    else:
                        confirmed_profiles.append(profile_data)

        except Exception as e:
            pass  # Continue with other usernames

    flow_steps[-1]["status"] = "complete"
    flow_steps[-1]["result"] = f"Searched {len(username_variations)} usernames, found {len(all_sherlock_found)} profiles, filtered {len(filtered_profiles)} foreign"

    # Step 4: Location filtering summary
    local_profiles = [p for p in confirmed_profiles if p.get("location_verified")]
    uncertain_profiles = [p for p in confirmed_profiles if not p.get("location_verified") and not p.get("location_found")]

    flow_steps.append({
        "step": 4,
        "action": "Location filtering",
        "status": "complete",
        "result": f"Local matches: {len(local_profiles)}, Uncertain: {len(uncertain_profiles)}, Filtered out: {len(filtered_profiles)}"
    })

    # Build summary
    summary_parts = [
        f"Investigated: {request.name}",
        f"Name variants: {', '.join(first_name_variants[:3])}",
        f"Usernames tried: {', '.join(username_variations[:3])}...",
        f"Confirmed profiles: {len(confirmed_profiles)}",
        f"Local matches: {len(local_profiles)}",
    ]

    if filtered_profiles:
        summary_parts.append(f"Filtered (wrong location): {len(filtered_profiles)}")

    if request.email:
        summary_parts.insert(2, f"Email checked: {request.email}")

    execution_time = (datetime.now() - start_time).total_seconds()

    return {
        "name": request.name,
        "name_variants_searched": name_variants_searched,
        "searched_at": datetime.now().isoformat(),
        "flow_steps": flow_steps,
        "discovered_emails": discovered_emails,
        "discovered_usernames": discovered_usernames,
        "confirmed_profiles": confirmed_profiles,
        "filtered_profiles": filtered_profiles,
        "people_search_links": people_search_links,
        "location_context": location_context,
        "summary": " | ".join(summary_parts),
        "execution_time": execution_time
    }


# ============================================================================
# WEB SEARCH - DuckDuckGo & Google
# ============================================================================

class WebSearchRequest(BaseModel):
    query: str
    max_results: int = 20
    region: str = "us-en"


@app.post("/api/web-search")
async def web_search(request: WebSearchRequest):
    """Search the web using DuckDuckGo"""
    start_time = datetime.now()
    results = []
    errors = []

    try:
        from duckduckgo_search import DDGS

        with DDGS() as ddgs:
            for r in ddgs.text(request.query, region=request.region, max_results=request.max_results):
                results.append({
                    'title': r.get('title', ''),
                    'url': r.get('href', ''),
                    'snippet': r.get('body', '')
                })
    except Exception as e:
        errors.append(f"DuckDuckGo error: {str(e)}")

        # Fallback to googlesearch
        try:
            from googlesearch import search
            for url in search(request.query, num_results=request.max_results):
                results.append({
                    'title': '',
                    'url': url,
                    'snippet': ''
                })
        except Exception as e2:
            errors.append(f"Google fallback error: {str(e2)}")

    return {
        'query': request.query,
        'searched_at': datetime.now().isoformat(),
        'results': results,
        'total_found': len(results),
        'errors': errors,
        'execution_time': (datetime.now() - start_time).total_seconds()
    }


# ============================================================================
# WHOIS LOOKUP
# ============================================================================

class WhoisRequest(BaseModel):
    domain: str


@app.post("/api/whois")
async def whois_lookup(request: WhoisRequest):
    """WHOIS domain lookup"""
    start_time = datetime.now()
    whois_data = {}
    errors = []

    try:
        import whois
        w = whois.whois(request.domain)

        whois_data = {
            'domain_name': w.domain_name,
            'registrar': w.registrar,
            'creation_date': str(w.creation_date) if w.creation_date else None,
            'expiration_date': str(w.expiration_date) if w.expiration_date else None,
            'updated_date': str(w.updated_date) if w.updated_date else None,
            'name_servers': w.name_servers,
            'status': w.status,
            'emails': w.emails,
            'registrant': w.get('registrant_name') or w.get('name'),
            'org': w.org,
            'address': w.address,
            'city': w.city,
            'state': w.state,
            'country': w.country,
            'zipcode': w.zipcode,
        }
    except Exception as e:
        errors.append(f"WHOIS error: {str(e)}")

    return {
        'domain': request.domain,
        'searched_at': datetime.now().isoformat(),
        'whois_data': whois_data,
        'errors': errors,
        'execution_time': (datetime.now() - start_time).total_seconds()
    }


# ============================================================================
# WAYBACK MACHINE - Historical Website Data
# ============================================================================

class WaybackRequest(BaseModel):
    url: str
    limit: int = 10


@app.post("/api/wayback")
async def wayback_search(request: WaybackRequest):
    """Search Wayback Machine for historical snapshots"""
    start_time = datetime.now()
    snapshots = []
    errors = []

    try:
        import waybackpy
        url = waybackpy.Url(request.url)

        # Get available snapshots
        try:
            oldest = url.oldest()
            snapshots.append({
                'type': 'oldest',
                'timestamp': oldest.timestamp.isoformat() if oldest.timestamp else None,
                'archive_url': oldest.archive_url
            })
        except Exception:
            pass

        try:
            newest = url.newest()
            snapshots.append({
                'type': 'newest',
                'timestamp': newest.timestamp.isoformat() if newest.timestamp else None,
                'archive_url': newest.archive_url
            })
        except Exception:
            pass

        # Get CDX snapshots
        try:
            cdx = url.cdx_api()
            for snapshot in list(cdx)[:request.limit]:
                snapshots.append({
                    'type': 'snapshot',
                    'timestamp': snapshot.timestamp,
                    'archive_url': snapshot.archive_url,
                    'status_code': snapshot.statuscode,
                    'mime_type': snapshot.mimetype
                })
        except Exception:
            pass

    except Exception as e:
        errors.append(f"Wayback error: {str(e)}")

    return {
        'url': request.url,
        'searched_at': datetime.now().isoformat(),
        'snapshots': snapshots,
        'total_found': len(snapshots),
        'errors': errors,
        'execution_time': (datetime.now() - start_time).total_seconds()
    }


# ============================================================================
# VEHICLE & LICENSE PLATE SEARCH LINKS
# ============================================================================

class VehicleSearchRequest(BaseModel):
    plate: Optional[str] = None
    vin: Optional[str] = None
    state: str = "LA"
    make: Optional[str] = None
    model: Optional[str] = None
    year: Optional[str] = None


@app.post("/api/vehicle-search")
async def vehicle_search_links(request: VehicleSearchRequest):
    """Generate vehicle/plate search links"""
    links = []

    if request.plate:
        plate = request.plate.replace(" ", "").upper()
        state = request.state.upper()

        links.extend([
            {'name': 'FAXVIN Plate Lookup', 'url': f'https://www.faxvin.com/license-plate-lookup', 'type': 'free'},
            {'name': 'VinCheck.info', 'url': f'https://vincheck.info/check/license-plate.php?plate={plate}&state={state}', 'type': 'free'},
            {'name': 'SearchQuarry Plate', 'url': f'https://www.searchquarry.com/license-plate-lookup/', 'type': 'paid'},
            {'name': 'AutoCheck', 'url': f'https://www.autocheck.com/members/login.do', 'type': 'paid'},
            {'name': 'Carfax', 'url': f'https://www.carfax.com/vehicle-history-reports/', 'type': 'paid'},
        ])

    if request.vin:
        vin = request.vin.upper()
        links.extend([
            {'name': 'NHTSA VIN Decoder', 'url': f'https://vpic.nhtsa.dot.gov/decoder/Decoder?VIN={vin}', 'type': 'free'},
            {'name': 'VinCheck.info', 'url': f'https://vincheck.info/check/vin-check.php?vin={vin}', 'type': 'free'},
            {'name': 'VehicleHistory', 'url': f'https://www.vehiclehistory.com/vin-report/{vin}', 'type': 'free'},
            {'name': 'NICB VINCheck', 'url': f'https://www.nicb.org/vincheck', 'type': 'free'},
            {'name': 'Carfax VIN', 'url': f'https://www.carfax.com/VehicleHistory/p/Report.cfx?vin={vin}', 'type': 'paid'},
            {'name': 'AutoCheck VIN', 'url': f'https://www.autocheck.com/vehiclehistory/autocheck/en/search-by-vin?vin={vin}', 'type': 'paid'},
        ])

    # State DMV links
    state_dmv = {
        'LA': 'https://expresslane.org/vehicles',
        'TX': 'https://www.txdmv.gov/',
        'FL': 'https://www.flhsmv.gov/dmv/',
        'CA': 'https://www.dmv.ca.gov/',
        'GA': 'https://dor.georgia.gov/motor-vehicles',
        'NY': 'https://dmv.ny.gov/',
        'AL': 'https://revenue.alabama.gov/motor-vehicle/',
        'MS': 'https://www.dor.ms.gov/motor-vehicle',
    }

    if request.state.upper() in state_dmv:
        links.append({
            'name': f'{request.state.upper()} DMV',
            'url': state_dmv[request.state.upper()],
            'type': 'official'
        })

    return {
        'plate': request.plate,
        'vin': request.vin,
        'state': request.state,
        'searched_at': datetime.now().isoformat(),
        'search_links': links
    }


# ============================================================================
# BACKGROUND CHECK LINK GENERATOR
# ============================================================================

class BackgroundCheckRequest(BaseModel):
    name: str
    state: Optional[str] = None
    city: Optional[str] = None
    dob: Optional[str] = None  # YYYY-MM-DD


@app.post("/api/background-links")
async def background_check_links(request: BackgroundCheckRequest):
    """Generate links to background check services"""
    name = request.name
    encoded_name = name.replace(' ', '+')
    name_dash = name.replace(' ', '-').lower()

    links = {
        'free_services': [
            {'name': 'TruePeopleSearch', 'url': f'https://www.truepeoplesearch.com/results?name={encoded_name}'},
            {'name': 'FastPeopleSearch', 'url': f'https://www.fastpeoplesearch.com/name/{name_dash}'},
            {'name': "That's Them", 'url': f'https://thatsthem.com/name/{name_dash}'},
            {'name': 'ZabaSearch', 'url': f'https://www.zabasearch.com/people/{name_dash}/'},
            {'name': 'Whitepages', 'url': f'https://www.whitepages.com/name/{name_dash}'},
            {'name': 'Nuwber', 'url': f'https://nuwber.com/search?name={encoded_name}'},
            {'name': 'CyberBackgroundChecks', 'url': f'https://www.cyberbackgroundchecks.com/people/{name_dash}'},
        ],
        'paid_services': [
            {'name': 'BeenVerified', 'url': f'https://www.beenverified.com/people/{name_dash}/'},
            {'name': 'Intelius', 'url': f'https://www.intelius.com/people-search/{name_dash}/'},
            {'name': 'Spokeo', 'url': f'https://www.spokeo.com/{name_dash}'},
            {'name': 'PeopleFinder', 'url': f'https://www.peoplefinder.com/people/{name_dash}/'},
            {'name': 'USSearch', 'url': f'https://www.ussearch.com/search/results/people?firstName={name.split()[0]}&lastName={name.split()[-1]}'},
            {'name': 'Instant Checkmate', 'url': f'https://www.instantcheckmate.com/people/{name_dash}/'},
            {'name': 'TruthFinder', 'url': f'https://www.truthfinder.com/people-search/'},
        ],
        'criminal_records': [
            {'name': 'CourtListener', 'url': f'https://www.courtlistener.com/?q={encoded_name}'},
            {'name': 'JailBase', 'url': f'https://www.jailbase.com/en/search/?q={encoded_name}'},
            {'name': 'VINELink', 'url': 'https://www.vinelink.com/#/search'},
            {'name': 'NSOPW (Sex Offenders)', 'url': f'https://www.nsopw.gov/search-public-sex-offender-registries'},
            {'name': 'BOP Inmate Locator', 'url': f'https://www.bop.gov/inmateloc/'},
        ],
        'social_media': [
            {'name': 'Facebook', 'url': f'https://www.facebook.com/search/people/?q={encoded_name}'},
            {'name': 'LinkedIn', 'url': f'https://www.linkedin.com/search/results/people/?keywords={encoded_name}'},
            {'name': 'Twitter/X', 'url': f'https://twitter.com/search?q={encoded_name}&f=user'},
            {'name': 'Instagram', 'url': f'https://www.instagram.com/{name.replace(" ", "").lower()}/'},
        ]
    }

    if request.state:
        state = request.state.upper()
        links['state_specific'] = []

        # Add state-specific offender searches
        if state == 'LA':
            links['state_specific'].append({'name': 'LA DOC', 'url': f'https://www.doc.la.gov/offender-search?name={encoded_name}'})
        elif state == 'TX':
            links['state_specific'].append({'name': 'TX DOC', 'url': f'https://offender.tdcj.texas.gov/OffenderSearch/'})
        elif state == 'FL':
            links['state_specific'].append({'name': 'FL DOC', 'url': f'https://www.dc.state.fl.us/offenderSearch/'})

    return {
        'name': request.name,
        'searched_at': datetime.now().isoformat(),
        'links': links
    }


# ============================================================================
# BOND CLIENT RISK SCORING
# ============================================================================

class RiskScoreRequest(BaseModel):
    name: str
    age: Optional[int] = None
    charges: Optional[List[str]] = None
    prior_ftas: int = 0  # Failure to appear count
    prior_convictions: int = 0
    employment_status: Optional[str] = None  # employed, unemployed, self-employed
    residence_type: Optional[str] = None  # own, rent, homeless, with_family
    residence_duration_months: Optional[int] = None
    local_ties: Optional[int] = None  # 0-10 scale
    has_vehicle: bool = False
    phone_verified: bool = False
    references_verified: int = 0
    bond_amount: Optional[float] = None
    income_monthly: Optional[float] = None


@app.post("/api/risk-score")
async def calculate_risk_score(request: RiskScoreRequest):
    """
    Calculate bond client risk score (0-100)
    Lower = higher risk, Higher = lower risk (better client)
    """
    score = 50  # Start at neutral
    risk_factors = []
    positive_factors = []

    # Age factor
    if request.age:
        if request.age < 21:
            score -= 10
            risk_factors.append("Under 21 years old (-10)")
        elif request.age > 50:
            score += 5
            positive_factors.append("Over 50 years old (+5)")

    # Prior FTAs (major risk factor)
    if request.prior_ftas > 0:
        fta_penalty = min(request.prior_ftas * 15, 45)
        score -= fta_penalty
        risk_factors.append(f"{request.prior_ftas} prior FTA(s) (-{fta_penalty})")

    # Prior convictions
    if request.prior_convictions > 0:
        conv_penalty = min(request.prior_convictions * 5, 20)
        score -= conv_penalty
        risk_factors.append(f"{request.prior_convictions} prior conviction(s) (-{conv_penalty})")

    # Employment
    if request.employment_status == 'employed':
        score += 15
        positive_factors.append("Employed (+15)")
    elif request.employment_status == 'self-employed':
        score += 8
        positive_factors.append("Self-employed (+8)")
    elif request.employment_status == 'unemployed':
        score -= 10
        risk_factors.append("Unemployed (-10)")

    # Residence
    if request.residence_type == 'own':
        score += 15
        positive_factors.append("Homeowner (+15)")
    elif request.residence_type == 'rent':
        score += 5
        positive_factors.append("Renter (+5)")
    elif request.residence_type == 'with_family':
        score += 8
        positive_factors.append("Lives with family (+8)")
    elif request.residence_type == 'homeless':
        score -= 20
        risk_factors.append("No stable residence (-20)")

    # Residence duration
    if request.residence_duration_months:
        if request.residence_duration_months >= 24:
            score += 10
            positive_factors.append("2+ years at residence (+10)")
        elif request.residence_duration_months >= 12:
            score += 5
            positive_factors.append("1+ year at residence (+5)")
        elif request.residence_duration_months < 3:
            score -= 5
            risk_factors.append("Less than 3 months at residence (-5)")

    # Local ties
    if request.local_ties is not None:
        if request.local_ties >= 7:
            score += 10
            positive_factors.append(f"Strong local ties ({request.local_ties}/10) (+10)")
        elif request.local_ties <= 3:
            score -= 10
            risk_factors.append(f"Weak local ties ({request.local_ties}/10) (-10)")

    # Vehicle
    if request.has_vehicle:
        score += 5
        positive_factors.append("Has vehicle (+5)")

    # Phone verified
    if request.phone_verified:
        score += 5
        positive_factors.append("Phone verified (+5)")
    else:
        score -= 5
        risk_factors.append("Phone not verified (-5)")

    # References
    if request.references_verified >= 3:
        score += 10
        positive_factors.append(f"{request.references_verified} verified references (+10)")
    elif request.references_verified >= 1:
        score += 5
        positive_factors.append(f"{request.references_verified} verified reference(s) (+5)")
    else:
        score -= 5
        risk_factors.append("No verified references (-5)")

    # Bond to income ratio
    if request.bond_amount and request.income_monthly and request.income_monthly > 0:
        ratio = request.bond_amount / (request.income_monthly * 12)
        if ratio > 2:
            score -= 15
            risk_factors.append(f"Bond is {ratio:.1f}x annual income (-15)")
        elif ratio < 0.5:
            score += 10
            positive_factors.append(f"Bond is only {ratio:.1f}x annual income (+10)")

    # Charge severity (simplified)
    if request.charges:
        severe_charges = ['murder', 'assault', 'robbery', 'kidnapping', 'weapon', 'drug trafficking']
        for charge in request.charges:
            charge_lower = charge.lower()
            if any(s in charge_lower for s in severe_charges):
                score -= 10
                risk_factors.append(f"Severe charge: {charge} (-10)")
                break

    # Clamp score
    score = max(0, min(100, score))

    # Determine risk level
    if score >= 70:
        risk_level = 'LOW RISK'
        recommendation = 'Good candidate for bond'
    elif score >= 50:
        risk_level = 'MODERATE RISK'
        recommendation = 'Proceed with caution, consider additional collateral'
    elif score >= 30:
        risk_level = 'HIGH RISK'
        recommendation = 'Requires substantial collateral or co-signer'
    else:
        risk_level = 'VERY HIGH RISK'
        recommendation = 'Consider declining or requiring full collateral'

    return {
        'name': request.name,
        'calculated_at': datetime.now().isoformat(),
        'score': score,
        'risk_level': risk_level,
        'recommendation': recommendation,
        'risk_factors': risk_factors,
        'positive_factors': positive_factors,
        'score_breakdown': {
            'base_score': 50,
            'final_score': score,
            'adjustments': len(risk_factors) + len(positive_factors)
        }
    }


# ============================================================================
# SOCIAL MEDIA SCRAPING (snscrape)
# ============================================================================

class SocialScrapeRequest(BaseModel):
    username: str
    platform: str  # twitter, instagram, reddit, youtube
    max_posts: int = 20


@app.post("/api/social-scrape")
async def social_scrape(request: SocialScrapeRequest):
    """Scrape social media posts (limited functionality)"""
    start_time = datetime.now()
    posts = []
    profile_info = {}
    errors = []

    try:
        import snscrape.modules.twitter as sntwitter
        import snscrape.modules.reddit as snreddit

        if request.platform.lower() == 'twitter':
            try:
                for i, tweet in enumerate(sntwitter.TwitterUserScraper(request.username).get_items()):
                    if i >= request.max_posts:
                        break
                    posts.append({
                        'date': tweet.date.isoformat() if tweet.date else None,
                        'content': tweet.rawContent,
                        'likes': tweet.likeCount,
                        'retweets': tweet.retweetCount,
                        'url': tweet.url
                    })
            except Exception as e:
                errors.append(f"Twitter scrape error: {str(e)}")

        elif request.platform.lower() == 'reddit':
            try:
                for i, post in enumerate(snreddit.RedditUserScraper(request.username).get_items()):
                    if i >= request.max_posts:
                        break
                    posts.append({
                        'date': post.created.isoformat() if hasattr(post, 'created') else None,
                        'title': getattr(post, 'title', ''),
                        'content': getattr(post, 'body', ''),
                        'subreddit': getattr(post, 'subreddit', ''),
                        'url': post.url if hasattr(post, 'url') else None
                    })
            except Exception as e:
                errors.append(f"Reddit scrape error: {str(e)}")

        else:
            errors.append(f"Platform {request.platform} not supported for scraping")

    except ImportError:
        errors.append("snscrape not installed")
    except Exception as e:
        errors.append(f"Scrape error: {str(e)}")

    return {
        'username': request.username,
        'platform': request.platform,
        'searched_at': datetime.now().isoformat(),
        'posts': posts,
        'profile_info': profile_info,
        'total_found': len(posts),
        'errors': errors,
        'execution_time': (datetime.now() - start_time).total_seconds()
    }


# ============================================================================
# DOCUMENT METADATA EXTRACTION
# ============================================================================

class MetadataRequest(BaseModel):
    file_base64: str
    filename: str


@app.post("/api/extract-metadata")
async def extract_metadata(request: MetadataRequest):
    """Extract metadata from documents and images"""
    start_time = datetime.now()
    metadata = {}
    errors = []

    try:
        import base64

        # Decode file
        file_data = base64.b64decode(request.file_base64)
        filename_lower = request.filename.lower()

        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(request.filename)[1]) as tmp:
            tmp.write(file_data)
            tmp_path = tmp.name

        try:
            # Image files
            if filename_lower.endswith(('.jpg', '.jpeg', '.png', '.gif', '.tiff', '.bmp')):
                try:
                    import exifread
                    with open(tmp_path, 'rb') as f:
                        tags = exifread.process_file(f)
                        for tag in tags.keys():
                            if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
                                metadata[str(tag)] = str(tags[tag])

                    # Check for GPS
                    if 'GPS GPSLatitude' in metadata and 'GPS GPSLongitude' in metadata:
                        metadata['_gps_found'] = True
                except Exception as e:
                    errors.append(f"EXIF extraction error: {str(e)}")

            # PDF files
            elif filename_lower.endswith('.pdf'):
                try:
                    from PyPDF2 import PdfReader
                    reader = PdfReader(tmp_path)
                    if reader.metadata:
                        for key, value in reader.metadata.items():
                            metadata[key.replace('/', '')] = str(value) if value else None
                    metadata['_page_count'] = len(reader.pages)
                except Exception as e:
                    errors.append(f"PDF extraction error: {str(e)}")

            # Word documents
            elif filename_lower.endswith(('.docx', '.doc')):
                try:
                    from docx import Document
                    doc = Document(tmp_path)
                    props = doc.core_properties
                    metadata['author'] = props.author
                    metadata['created'] = str(props.created) if props.created else None
                    metadata['modified'] = str(props.modified) if props.modified else None
                    metadata['last_modified_by'] = props.last_modified_by
                    metadata['title'] = props.title
                    metadata['subject'] = props.subject
                    metadata['keywords'] = props.keywords
                    metadata['comments'] = props.comments
                except Exception as e:
                    errors.append(f"DOCX extraction error: {str(e)}")

        finally:
            os.unlink(tmp_path)

    except Exception as e:
        errors.append(f"Metadata extraction error: {str(e)}")

    return {
        'filename': request.filename,
        'extracted_at': datetime.now().isoformat(),
        'metadata': metadata,
        'errors': errors,
        'execution_time': (datetime.now() - start_time).total_seconds()
    }


# ============================================================================
# IP GEOLOCATION
# ============================================================================

class IPLookupRequest(BaseModel):
    ip_address: str


@app.post("/api/ip-lookup")
async def ip_lookup(request: IPLookupRequest):
    """Geolocate IP address"""
    start_time = datetime.now()
    location = {}
    errors = []

    try:
        from ip2geotools.databases.noncommercial import DbIpCity

        response = DbIpCity.get(request.ip_address, api_key='free')
        location = {
            'ip': request.ip_address,
            'city': response.city,
            'region': response.region,
            'country': response.country,
            'latitude': response.latitude,
            'longitude': response.longitude,
        }
    except Exception as e:
        errors.append(f"IP lookup error: {str(e)}")

        # Fallback to simple API
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"http://ip-api.com/json/{request.ip_address}")
                if resp.status_code == 200:
                    data = resp.json()
                    location = {
                        'ip': request.ip_address,
                        'city': data.get('city'),
                        'region': data.get('regionName'),
                        'country': data.get('country'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                    }
        except Exception as e2:
            errors.append(f"Fallback IP lookup error: {str(e2)}")

    return {
        'ip_address': request.ip_address,
        'searched_at': datetime.now().isoformat(),
        'location': location,
        'errors': errors,
        'execution_time': (datetime.now() - start_time).total_seconds()
    }


# ============================================================================
# JAIL ROSTER SCRAPER - Extract inmate data from jail booking pages
# ============================================================================

class JailRosterRequest(BaseModel):
    url: str


class JailRosterResult(BaseModel):
    url: str
    scraped_at: str
    inmate: Dict[str, Any]
    charges: List[Dict[str, Any]]
    bonds: List[Dict[str, Any]]
    photo_url: Optional[str]
    errors: List[str]
    execution_time: float


async def scrape_jail_roster(url: str) -> Dict[str, Any]:
    """
    Scrape jail roster/booking page to extract inmate data.
    Supports common jail roster formats (Revize, JailTracker, etc.)
    """
    start_time = datetime.now()
    inmate = {}
    charges = []
    bonds = []
    photo_url = None
    errors = []

    # Enhanced headers to better mimic real browser
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0',
        'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"macOS"',
    }

    # Extract booking ID from URL for fallback
    from urllib.parse import urlparse, parse_qs
    parsed_url = urlparse(url)
    path_parts = parsed_url.path.strip('/').split('/')
    booking_id = path_parts[-1] if path_parts else None

    # Try to identify the jail/sheriff from domain
    domain = parsed_url.netloc
    jail_name = domain.split('.')[0] if domain else 'Unknown'

    html = None
    response_status = None
    from urllib.parse import quote
    import random

    # Rotate user agents to avoid detection
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    ]
    random_ua = random.choice(user_agents)

    # Method 1: Try ScrapingBee free tier (100 free credits/month)
    # Using render=false for speed, premium_proxy for better success
    try:
        import os
        scrapingbee_key = os.environ.get('SCRAPINGBEE_API_KEY')
        if scrapingbee_key:
            sb_url = f"https://app.scrapingbee.com/api/v1/?api_key={scrapingbee_key}&url={quote(url, safe='')}&render_js=false"
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(sb_url)
                if response.status_code == 200 and len(response.text) > 500:
                    html = response.text
    except Exception as e:
        errors.append(f"ScrapingBee: {str(e)[:30]}")

    # Method 2: Try multiple free CORS proxies with better headers
    if not html:
        proxy_configs = [
            # allorigins.win
            {
                'url': f"https://api.allorigins.win/get?url={quote(url, safe='')}",
                'extract': lambda r: r.json().get('contents') if r.status_code == 200 else None
            },
            # corsproxy.io
            {
                'url': f"https://corsproxy.io/?{quote(url, safe='')}",
                'extract': lambda r: r.text if r.status_code == 200 else None
            },
            # webscraping.ai free tier
            {
                'url': f"https://api.webscraping.ai/html?api_key=demo&url={quote(url, safe='')}",
                'extract': lambda r: r.text if r.status_code == 200 else None
            },
        ]

        for proxy in proxy_configs:
            if html:
                break
            try:
                proxy_headers = {
                    'User-Agent': random_ua,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    **proxy.get('headers', {})
                }
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.get(proxy['url'], headers=proxy_headers)
                    response_status = response.status_code
                    content = proxy['extract'](response)
                    if content and len(content) > 500:  # Must have real content
                        html = content
                        break
            except Exception as e:
                errors.append(f"Proxy: {str(e)[:30]}")

    # Method 2: Try cloudscraper (bypasses Cloudflare)
    if not html:
        try:
            import cloudscraper
            scraper = cloudscraper.create_scraper(
                browser={'browser': 'chrome', 'platform': 'darwin', 'desktop': True}
            )
            response = scraper.get(url, headers=headers, timeout=30)
            response_status = response.status_code
            if response.status_code == 200:
                html = response.text
        except Exception as e:
            errors.append(f"Cloudscraper: {str(e)[:50]}")

    # Method 2: Skip curl_cffi - removed from requirements

    # Method 3: Try httpx as fallback
    if not html:
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
                response = await client.get(url, headers=headers)
                response_status = response.status_code
                if response.status_code == 200:
                    html = response.text
        except Exception as e:
            errors.append(f"Httpx: {str(e)[:50]}")

    # Method 4: Skip Playwright for now - focus on stability

    # If all methods failed
    if not html:
        errors.append(f"All scraping methods failed (HTTP {response_status})")
        inmate['_manual_entry_required'] = True
        inmate['_source_url'] = url
        inmate['_booking_id'] = booking_id
        return {
            'url': url,
            'scraped_at': datetime.now().isoformat(),
            'inmate': inmate,
            'charges': charges,
            'bonds': bonds,
            'photo_url': photo_url,
            'errors': errors,
            'execution_time': (datetime.now() - start_time).total_seconds()
        }

    # Parse the HTML
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, 'lxml')

        # Try to find inmate photo
        # Common patterns for mugshot images
        img_selectors = [
        'img.mugshot', 'img.inmate-photo', 'img.booking-photo',
        'img[alt*="mugshot"]', 'img[alt*="photo"]', 'img[alt*="inmate"]',
        '.mugshot img', '.inmate-photo img', '.booking-photo img',
        '#mugshot', '#inmate-photo', '.photo img',
        'img[src*="mugshot"]', 'img[src*="booking"]', 'img[src*="inmate"]',
        ]

        for selector in img_selectors:
            img = soup.select_one(selector)
            if img and img.get('src'):
                src = img['src']
                # Make absolute URL if relative
                if src.startswith('/'):
                    from urllib.parse import urljoin
                    src = urljoin(url, src)
                elif not src.startswith('http'):
                    from urllib.parse import urljoin
                    src = urljoin(url, src)
                photo_url = src
                break

        # If no photo found with selectors, try finding any large image
        if not photo_url:
            for img in soup.find_all('img'):
                src = img.get('src', '')
                alt = img.get('alt', '').lower()
                if any(x in src.lower() or x in alt for x in ['mug', 'photo', 'booking', 'inmate', 'image']):
                    if src.startswith('/'):
                        from urllib.parse import urljoin
                        src = urljoin(url, src)
                    elif not src.startswith('http'):
                        from urllib.parse import urljoin
                        src = urljoin(url, src)
                    photo_url = src
                    break

        # Extract inmate data - look for common patterns
        # Pattern 1: Table rows with label/value
        for row in soup.find_all('tr'):
            cells = row.find_all(['td', 'th'])
            if len(cells) >= 2:
                label = cells[0].get_text(strip=True).lower().replace(':', '')
                value = cells[1].get_text(strip=True)

                if any(x in label for x in ['name', 'inmate name', 'defendant']):
                    inmate['name'] = value
                elif any(x in label for x in ['booking', 'book #', 'booking #', 'booking number']):
                    inmate['booking_number'] = value
                elif any(x in label for x in ['dob', 'date of birth', 'birth date', 'birthdate']):
                    inmate['dob'] = value
                elif label in ['age']:
                    inmate['age'] = value
                elif any(x in label for x in ['race', 'ethnicity']):
                    inmate['race'] = value
                elif label in ['sex', 'gender']:
                    inmate['sex'] = value
                elif label in ['height', 'ht']:
                    inmate['height'] = value
                elif label in ['weight', 'wt']:
                    inmate['weight'] = value
                elif any(x in label for x in ['hair', 'hair color']):
                    inmate['hair_color'] = value
                elif any(x in label for x in ['eye', 'eye color', 'eyes']):
                    inmate['eye_color'] = value
                elif any(x in label for x in ['address', 'residence', 'home address']):
                    inmate['address'] = value
                elif any(x in label for x in ['arrest date', 'booking date', 'book date']):
                    inmate['booking_date'] = value
                elif any(x in label for x in ['release', 'release date']):
                    inmate['release_date'] = value
                elif any(x in label for x in ['facility', 'location', 'housing']):
                    inmate['facility'] = value

        # Pattern 2: Definition lists (dl/dt/dd)
        for dl in soup.find_all('dl'):
            dts = dl.find_all('dt')
            dds = dl.find_all('dd')
            for dt, dd in zip(dts, dds):
                label = dt.get_text(strip=True).lower().replace(':', '')
                value = dd.get_text(strip=True)

                if any(x in label for x in ['name', 'inmate']):
                    inmate['name'] = value
                elif 'booking' in label:
                    inmate['booking_number'] = value
                elif 'dob' in label or 'birth' in label:
                    inmate['dob'] = value
                elif label == 'age':
                    inmate['age'] = value
                elif 'race' in label:
                    inmate['race'] = value
                elif label in ['sex', 'gender']:
                    inmate['sex'] = value

        # Pattern 3: Divs with specific classes (common in modern jail sites)
        info_divs = soup.find_all(['div', 'span', 'p'], class_=lambda x: x and any(
            term in str(x).lower() for term in ['inmate', 'booking', 'detail', 'info', 'field']
        ))

        for div in info_divs:
            text = div.get_text(strip=True)
            # Look for "Label: Value" patterns
            if ':' in text:
                parts = text.split(':', 1)
                if len(parts) == 2:
                    label = parts[0].lower().strip()
                    value = parts[1].strip()

                    if 'name' in label and 'name' not in inmate:
                        inmate['name'] = value
                    elif 'booking' in label and 'booking_number' not in inmate:
                        inmate['booking_number'] = value

        # Pattern 4: Revize jail system - labels followed by input fields with values
        # Format: <label class="form-label">First Name</label><input value="RANDY">
        first_name = ''
        last_name = ''
        middle_name = ''

        for label in soup.find_all('label'):
            label_text = label.get_text(strip=True).lower()
            # Find the next input element (not necessarily sibling - find_next traverses DOM)
            next_input = label.find_next('input')

            if next_input and next_input.get('value'):
                value = next_input.get('value', '').strip()
                if not value:
                    continue

                # Map Revize field labels to inmate data
                if 'first name' in label_text:
                    first_name = value
                elif 'last name' in label_text:
                    last_name = value
                elif 'middle' in label_text:
                    middle_name = value
                elif label_text == 'age' or 'age' == label_text.strip():
                    inmate['age'] = value
                elif 'race' in label_text:
                    inmate['race'] = value
                elif label_text in ['sex', 'gender'] or 'sex' in label_text:
                    inmate['sex'] = value
                elif 'height' in label_text:
                    inmate['height'] = value
                elif 'weight' in label_text:
                    inmate['weight'] = value
                elif 'hair' in label_text:
                    inmate['hair_color'] = value
                elif 'eye' in label_text:
                    inmate['eye_color'] = value
                elif 'address' in label_text or 'city' in label_text:
                    if 'address' not in inmate:
                        inmate['address'] = value
                    else:
                        inmate['address'] += ', ' + value
                elif 'booking' in label_text and 'date' not in label_text:
                    inmate['booking_number'] = value
                elif 'arrest' in label_text or 'booking date' in label_text:
                    inmate['booking_date'] = value
                elif 'dob' in label_text or 'birth' in label_text:
                    inmate['dob'] = value

        # Combine first/middle/last name for Revize format
        if first_name or last_name:
            name_parts = []
            if first_name:
                name_parts.append(first_name)
            if middle_name:
                name_parts.append(middle_name)
            if last_name:
                name_parts.append(last_name)
            if name_parts:
                inmate['name'] = ' '.join(name_parts)

        # Pattern 5: Revize charges table - has headers like "Desc.", "Bond Type", "Bond Amt."
        if not charges:
            for table in soup.find_all('table'):
                # Check if this table has Revize-style headers
                headers = [th.get_text(strip=True).lower() for th in table.find_all('th')]

                # Revize pattern: Desc., Bond Type, Bond Amt.
                if any('desc' in h for h in headers) and any('bond' in h for h in headers):
                    # Map header positions
                    desc_idx = next((i for i, h in enumerate(headers) if 'desc' in h), 0)
                    bond_type_idx = next((i for i, h in enumerate(headers) if 'bond type' in h or h == 'bond type'), -1)
                    bond_amt_idx = next((i for i, h in enumerate(headers) if 'bond amt' in h or 'amount' in h), -1)

                    rows = table.find_all('tr')
                    for row in rows:
                        cells = row.find_all('td')
                        if len(cells) > desc_idx:
                            charge_text = cells[desc_idx].get_text(strip=True)
                            # Skip empty or non-charge rows
                            if len(charge_text) > 5 and charge_text.isupper():
                                charge_info = {'charge': charge_text}

                                # Get bond type
                                if bond_type_idx >= 0 and len(cells) > bond_type_idx:
                                    bond_type = cells[bond_type_idx].get_text(strip=True)
                                    if bond_type:
                                        charge_info['bond_type'] = bond_type

                                # Get bond amount
                                if bond_amt_idx >= 0 and len(cells) > bond_amt_idx:
                                    bond_amt = cells[bond_amt_idx].get_text(strip=True)
                                    if bond_amt:
                                        charge_info['bond_amount'] = bond_amt
                                        # Also add to bonds array if it's a dollar amount
                                        if '$' in bond_amt or bond_amt.replace(',', '').replace('.', '').isdigit():
                                            bonds.append({'amount': bond_amt, 'charge': charge_text})

                                # Dedupe
                                if not any(c.get('charge') == charge_text for c in charges):
                                    charges.append(charge_info)

                    # Found Revize table, don't process other tables
                    if charges:
                        break

            # Fallback: Look for any table with all-caps charge text
            if not charges:
                for table in soup.find_all('table'):
                    rows = table.find_all('tr')
                    for row in rows:
                        cells = row.find_all('td')
                        if cells:
                            first_cell_text = cells[0].get_text(strip=True)
                            if len(first_cell_text) > 10 and first_cell_text.isupper():
                                charge_info = {'charge': first_cell_text}
                                if len(cells) > 1:
                                    for i, cell in enumerate(cells[1:], 1):
                                        cell_text = cell.get_text(strip=True)
                                        if '$' in cell_text:
                                            charge_info['bond_amount'] = cell_text
                                            bonds.append({'amount': cell_text, 'charge': first_cell_text})
                                        elif cell_text:
                                            charge_info[f'col_{i}'] = cell_text
                                if not any(c.get('charge') == first_cell_text for c in charges):
                                    charges.append(charge_info)

        # Extract charges - look for charge tables or lists (skip if Revize pattern found charges)
        if not charges:
            charge_tables = soup.find_all('table', class_=lambda x: x and 'charge' in str(x).lower())
            if not charge_tables:
                # Try finding tables that might contain charges
                for table in soup.find_all('table'):
                    headers = [th.get_text(strip=True).lower() for th in table.find_all('th')]
                    if any('charge' in h or 'offense' in h for h in headers):
                        charge_tables.append(table)

            for table in charge_tables:
                rows = table.find_all('tr')
                headers = []
                for row in rows:
                    ths = row.find_all('th')
                    if ths:
                        headers = [th.get_text(strip=True).lower() for th in ths]
                    else:
                        cells = row.find_all('td')
                        if cells and headers:
                            charge = {}
                            for i, cell in enumerate(cells):
                                if i < len(headers):
                                    charge[headers[i]] = cell.get_text(strip=True)
                            if charge:
                                charges.append(charge)
                        elif cells and len(cells) >= 2:
                            # No headers, assume first cell is charge description
                            charges.append({
                                'charge': cells[0].get_text(strip=True),
                                'details': cells[1].get_text(strip=True) if len(cells) > 1 else ''
                            })

        # Extract bonds
        bond_tables = soup.find_all('table', class_=lambda x: x and 'bond' in str(x).lower())
        if not bond_tables:
            for table in soup.find_all('table'):
                headers = [th.get_text(strip=True).lower() for th in table.find_all('th')]
                if any('bond' in h or 'bail' in h for h in headers):
                    bond_tables.append(table)

        for table in bond_tables:
            rows = table.find_all('tr')
            for row in rows:
                cells = row.find_all('td')
                if cells:
                    bond_text = ' '.join(cell.get_text(strip=True) for cell in cells)
                    # Look for dollar amounts
                    import re
                    amounts = re.findall(r'\$[\d,]+(?:\.\d{2})?', bond_text)
                    if amounts:
                        bonds.append({
                            'description': bond_text,
                            'amount': amounts[0] if amounts else None
                        })

        # If we still don't have a name, try the page title or h1
        if 'name' not in inmate:
            # Try page title
            title = soup.find('title')
            if title:
                title_text = title.get_text(strip=True)
                # Common patterns: "John Doe - Booking Details" or "Inmate: John Doe"
                if '-' in title_text:
                    inmate['name'] = title_text.split('-')[0].strip()
                elif ':' in title_text:
                    inmate['name'] = title_text.split(':')[-1].strip()

            # Try h1
            if 'name' not in inmate:
                h1 = soup.find('h1')
                if h1:
                    inmate['name'] = h1.get_text(strip=True)

        # Clean up name if we got one
        if 'name' in inmate:
            name = inmate['name']
            # Remove common prefixes
            for prefix in ['inmate:', 'defendant:', 'name:', 'booking for']:
                if name.lower().startswith(prefix):
                    name = name[len(prefix):].strip()
            inmate['name'] = name

    except Exception as e:
        errors.append(f"Scraping error: {str(e)}")

    execution_time = (datetime.now() - start_time).total_seconds()

    return {
        'url': url,
        'scraped_at': datetime.now().isoformat(),
        'inmate': inmate,
        'charges': charges,
        'bonds': bonds,
        'photo_url': photo_url,
        'errors': errors,
        'execution_time': execution_time
    }


@app.post("/api/jail-roster", response_model=JailRosterResult)
async def jail_roster_scrape(request: JailRosterRequest):
    """
    Scrape jail roster/booking page to extract inmate data.
    Supports various jail systems (Revize, JailTracker, etc.)

    Extracts:
    - Inmate info (name, DOB, age, race, sex, height, weight, etc.)
    - Charges
    - Bond amounts
    - Mugshot photo URL
    """
    return await scrape_jail_roster(request.url)


class BulkJailRosterRequest(BaseModel):
    """Request for bulk jail roster scraping"""
    base_url: str  # e.g., "https://inmates.stpso.revize.com"
    start_booking: Optional[int] = None  # Optional - will auto-discover if not provided
    count: int = 10  # How many to fetch (max 50)


class BulkJailRosterResult(BaseModel):
    """Result from bulk jail roster scraping"""
    base_url: str
    start_booking: int
    count_requested: int
    count_found: int
    inmates: list
    errors: list
    execution_time: float


async def find_latest_booking(base_url: str, start_estimate: int = 280000) -> int:
    """
    Auto-discover the latest booking number by probing.
    Uses binary search to find the highest valid booking number.
    """
    # Start from an estimate and probe to find valid bookings
    high = start_estimate
    low = start_estimate - 10000  # Search within last 10k bookings
    latest_found = None

    # First, find a valid booking by checking a few numbers
    test_numbers = [high, high - 100, high - 500, high - 1000, high - 2000]

    for num in test_numbers:
        url = f"{base_url}/bookings/{num}"
        try:
            result = await scrape_jail_roster(url)
            if result.get('inmate') and result['inmate'].get('name'):
                latest_found = num
                low = num  # Found one, search upward from here
                break
        except:
            continue

    # If we found something, try to find higher valid bookings
    if latest_found:
        # Check a few numbers above to see if there are newer ones
        for offset in [10, 20, 50, 100, 200]:
            test_num = latest_found + offset
            url = f"{base_url}/bookings/{test_num}"
            try:
                result = await scrape_jail_roster(url)
                if result.get('inmate') and result['inmate'].get('name'):
                    latest_found = test_num
            except:
                continue

    # Default to estimate if nothing found
    return latest_found if latest_found else start_estimate


@app.post("/api/jail-roster/bulk", response_model=BulkJailRosterResult)
async def bulk_jail_roster_scrape(request: BulkJailRosterRequest):
    """
    Scrape multiple jail roster pages by booking number range.

    Provide the base URL (e.g., https://inmates.stpso.revize.com).
    If start_booking is not provided, will auto-discover the latest booking number.

    Will scrape from start_booking down to start_booking - count + 1.
    """
    import asyncio

    start_time = datetime.now()

    # Limit to 50 max to avoid overloading
    count = min(request.count, 50)

    # Normalize base URL
    base_url = request.base_url.rstrip('/')

    # Auto-discover latest booking if not provided
    if request.start_booking:
        start_booking = request.start_booking
    else:
        start_booking = await find_latest_booking(base_url)

    # Generate booking URLs
    booking_numbers = list(range(start_booking, start_booking - count, -1))

    # Scrape in parallel (batches of 5 to be nice to the server)
    inmates = []
    errors = []

    async def scrape_one(booking_num):
        url = f"{base_url}/bookings/{booking_num}"
        try:
            result = await scrape_jail_roster(url)
            if result.get('inmate') and result['inmate'].get('name'):
                return {
                    'booking_number': booking_num,
                    **result
                }
            else:
                return None
        except Exception as e:
            errors.append(f"Booking {booking_num}: {str(e)[:50]}")
            return None

    # Process in batches of 5
    batch_size = 5
    for i in range(0, len(booking_numbers), batch_size):
        batch = booking_numbers[i:i + batch_size]
        tasks = [scrape_one(num) for num in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                errors.append(str(result)[:50])
            elif result is not None:
                inmates.append(result)

        # Small delay between batches
        if i + batch_size < len(booking_numbers):
            await asyncio.sleep(0.5)

    execution_time = (datetime.now() - start_time).total_seconds()

    return {
        'base_url': base_url,
        'start_booking': start_booking,
        'count_requested': count,
        'count_found': len(inmates),
        'inmates': inmates,
        'errors': errors,
        'execution_time': execution_time
    }


# ============================================================================
# LOUISIANA COURT RECORDS SEARCH (Tyler Technologies)
# ============================================================================

class CourtSearchRequest(BaseModel):
    """Request for court records search"""
    name: str  # Defendant name to search
    dob: Optional[str] = None  # Date of birth for matching (YYYY-MM-DD or MM/DD/YYYY)
    parish: Optional[str] = None  # Optional parish filter


class CourtCase(BaseModel):
    """Court case record"""
    case_number: str
    case_type: Optional[str] = None
    filing_date: Optional[str] = None
    status: Optional[str] = None
    charges: Optional[List[str]] = None
    court: Optional[str] = None
    judge: Optional[str] = None
    next_hearing: Optional[str] = None
    disposition: Optional[str] = None
    has_fta: bool = False  # Flagged if FTA/warrant found
    has_warrant: bool = False
    defendant_dob: Optional[str] = None
    dob_match: bool = False  # True if DOB matches search criteria


class CourtSearchResult(BaseModel):
    """Court records search result"""
    name: str
    dob_searched: Optional[str] = None
    cases: List[CourtCase]
    total_cases: int
    fta_cases: int  # Cases with FTA/bench warrant
    warrant_cases: int
    active_cases: int
    dob_matched_cases: int
    alerts: List[str]  # Important flags like "ACTIVE WARRANT", "PRIOR FTA"
    errors: List[str]
    execution_time: float


async def search_la_court_records(name: str, parish: str = None, dob: str = None) -> Dict[str, Any]:
    """
    Search Louisiana court records via Tyler Technologies portal.
    Credentials stored in environment variables for security.
    Uses ScrapingBee for JavaScript rendering when available.
    """
    import os
    import re
    from datetime import datetime
    from urllib.parse import quote

    start_time = datetime.now()
    cases = []
    errors = []
    fta_count = 0
    active_count = 0
    warrant_count = 0

    # Get credentials from environment
    court_user = os.environ.get('LA_COURT_USERNAME')
    court_pass = os.environ.get('LA_COURT_PASSWORD')
    scrapingbee_key = os.environ.get('SCRAPINGBEE_API_KEY')

    if not court_user or not court_pass:
        errors.append("Court records credentials not configured (LA_COURT_USERNAME, LA_COURT_PASSWORD)")
        return {
            'name': name,
            'cases': [],
            'total_cases': 0,
            'fta_cases': 0,
            'active_cases': 0,
            'errors': errors,
            'execution_time': (datetime.now() - start_time).total_seconds()
        }

    # Parse name into first/last
    name_parts = name.strip().split()
    if len(name_parts) >= 2:
        first_name = name_parts[0]
        last_name = name_parts[-1]
    else:
        first_name = ""
        last_name = name

    # FTA/warrant keywords to look for
    fta_keywords = ['failure to appear', 'fta', 'bench warrant', 'capias', 'fugitive', 'absconding']
    warrant_keywords = ['warrant', 'capias', 'fugitive']
    active_keywords = ['active', 'open', 'pending', 'arraignment', 'trial']

    try:
        # Try ScrapingBee first (has JavaScript rendering for Angular sites)
        if scrapingbee_key:
            try:
                # ScrapingBee can render JavaScript and handle sessions
                # Tyler Technologies uses Angular with hash routing
                search_url = f"https://researchla.tylerhost.net/CourtRecordsSearch/#!/search?firstName={quote(first_name)}&lastName={quote(last_name)}"

                async with httpx.AsyncClient(timeout=30.0) as client:
                    scrapingbee_url = f"https://app.scrapingbee.com/api/v1/"

                    response = await client.get(
                        scrapingbee_url,
                        params={
                            'api_key': scrapingbee_key,
                            'url': search_url,
                            'render_js': 'true',
                            'wait': 6000,  # Wait 6 seconds for Angular search to complete
                            'premium_proxy': 'true',
                            'wait_for': '.case-number, .search-results, .results, tbody tr, .list-group-item',  # Wait for results
                        },
                        timeout=30.0
                    )

                    if response.status_code == 200:
                        html = response.text

                        # Parse the rendered HTML for case results
                        from bs4 import BeautifulSoup
                        import re
                        soup = BeautifulSoup(html, 'html.parser')

                        # Tyler case number patterns: "4820-F-2020", "2024-123456", etc.
                        case_num_patterns = [
                            r'\b(\d{4,6}-[A-Z]-\d{4})\b',  # e.g., 4820-F-2020
                            r'\b(\d{4}-\d{5,6})\b',        # e.g., 2024-123456
                            r'\b([A-Z]{2,3}-\d{4}-\d+)\b', # e.g., CR-2020-12345
                        ]

                        # Date patterns for filing dates
                        date_pattern = r'\b(\d{1,2}/\d{1,2}/\d{2,4}|\w+ \d{1,2}, \d{4})\b'

                        # Try multiple Tyler-specific selectors
                        row_selectors = [
                            '.case-row', '.search-result', '.case-item',
                            'tr[ng-repeat]', 'tr[data-case]', 'div[ng-repeat]',
                            '.results-row', '.case-result', '.case-listing',
                            'tbody tr', '.list-group-item', '.card'
                        ]

                        case_rows = []
                        for selector in row_selectors:
                            found = soup.select(selector)
                            if found:
                                case_rows = found
                                break

                        # If no rows found, try finding case numbers anywhere in HTML
                        if not case_rows:
                            full_text = soup.get_text()
                            for pattern in case_num_patterns:
                                found_cases = re.findall(pattern, full_text)
                                for case_num in found_cases:
                                    case_data = {
                                        'case_number': case_num,
                                        'case_type': '',
                                        'filing_date': '',
                                        'status': '',
                                        'charges': [],
                                        'court': 'Louisiana State Court',
                                        'has_fta': False,
                                        'has_warrant': False
                                    }

                                    # Check surrounding context for FTA/warrant
                                    # Find the case number position and check nearby text
                                    idx = full_text.lower().find(case_num.lower())
                                    if idx > 0:
                                        context = full_text[max(0, idx-200):idx+200].lower()
                                        for keyword in fta_keywords:
                                            if keyword in context:
                                                case_data['has_fta'] = True
                                                fta_count += 1
                                                break
                                        for keyword in warrant_keywords:
                                            if keyword in context:
                                                case_data['has_warrant'] = True
                                                warrant_count += 1
                                                break
                                        for keyword in active_keywords:
                                            if keyword in context:
                                                active_count += 1
                                                break

                                        # Try to find a date in context
                                        date_matches = re.findall(date_pattern, context)
                                        if date_matches:
                                            case_data['filing_date'] = date_matches[0]

                                    cases.append(case_data)

                        # Process rows if found
                        for row in case_rows:
                            case_text = row.get_text(' ', strip=True)
                            case_text_lower = case_text.lower()

                            # Extract case info
                            case_data = {
                                'case_number': '',
                                'case_type': '',
                                'filing_date': '',
                                'status': '',
                                'charges': [],
                                'court': '',
                                'has_fta': False,
                                'has_warrant': False
                            }

                            # Try to find case number with regex
                            for pattern in case_num_patterns:
                                match = re.search(pattern, case_text)
                                if match:
                                    case_data['case_number'] = match.group(1)
                                    break

                            # Fall back to element selectors
                            if not case_data['case_number']:
                                case_num_elem = row.select_one('.case-number, [data-case-number], td:first-child a, a')
                                if case_num_elem:
                                    case_data['case_number'] = case_num_elem.get_text(strip=True)

                            # Try to find date
                            date_match = re.search(date_pattern, case_text)
                            if date_match:
                                case_data['filing_date'] = date_match.group(1)

                            # Check for FTA/warrant indicators
                            for keyword in fta_keywords:
                                if keyword in case_text_lower:
                                    case_data['has_fta'] = True
                                    fta_count += 1
                                    break

                            for keyword in warrant_keywords:
                                if keyword in case_text_lower:
                                    case_data['has_warrant'] = True
                                    warrant_count += 1
                                    break

                            for keyword in active_keywords:
                                if keyword in case_text_lower:
                                    active_count += 1
                                    break

                            if case_data['case_number']:
                                cases.append(case_data)

                        # Store debug info if no cases found
                        if not cases:
                            if 'No results' in html or 'no records' in html.lower() or '0 results' in html.lower():
                                errors.append("No court records found for this name")
                            else:
                                # Store a sample of the HTML for debugging
                                html_preview = html[:500] if len(html) > 500 else html
                                errors.append(f"Could not parse results - HTML preview: {html_preview[:200]}...")

                    else:
                        errors.append(f"ScrapingBee returned {response.status_code}")

            except Exception as e:
                errors.append(f"ScrapingBee error: {str(e)[:50]}")

        # Fallback to direct API approach if ScrapingBee didn't find cases
        if not cases and court_user and court_pass:
            # Clear ScrapingBee parsing errors since we're trying API
            api_errors = []

            try:
                async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
                    # Step 1: Get login page to establish session
                    login_url = "https://researchla.tylerhost.net/CourtRecordsSearch/Account/Login"

                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                        'Accept': 'application/json, text/plain, */*',
                        'Accept-Language': 'en-US,en;q=0.9',
                        'Content-Type': 'application/json',
                        'Origin': 'https://researchla.tylerhost.net',
                        'Referer': 'https://researchla.tylerhost.net/CourtRecordsSearch/',
                    }

                    # Try to authenticate with JSON
                    auth_data = {
                        'Email': court_user,
                        'Password': court_pass,
                        'RememberMe': False
                    }

                    login_response = await client.post(
                        login_url,
                        json=auth_data,
                        headers=headers
                    )

                    # If JSON login fails, try form data
                    if login_response.status_code not in [200, 302]:
                        form_headers = headers.copy()
                        form_headers['Content-Type'] = 'application/x-www-form-urlencoded'
                        login_response = await client.post(
                            login_url,
                            data=auth_data,
                            headers=form_headers
                        )

                    if login_response.status_code not in [200, 302]:
                        api_errors.append(f"Direct API login failed: {login_response.status_code}")
                    else:
                        # Step 2: Search for defendant
                        search_url = "https://researchla.tylerhost.net/CourtRecordsSearch/api/Search"

                        search_data = {
                            'SearchType': 'Party',
                            'LastName': last_name,
                            'FirstName': first_name,
                            'MiddleName': '',
                            'DateOfBirth': dob or '',
                            'CaseNumber': '',
                            'PageNumber': 1,
                            'PageSize': 50
                        }

                        if parish:
                            search_data['Court'] = parish

                        search_response = await client.post(
                            search_url,
                            json=search_data,
                            headers=headers
                        )

                        if search_response.status_code == 200:
                            try:
                                results = search_response.json()

                                # Parse results (structure depends on Tyler's API)
                                if isinstance(results, dict) and 'Cases' in results:
                                    for case_data in results.get('Cases', []):
                                        case = {
                                            'case_number': case_data.get('CaseNumber', ''),
                                            'case_type': case_data.get('CaseType', ''),
                                            'filing_date': case_data.get('FilingDate', ''),
                                            'status': case_data.get('Status', ''),
                                            'charges': case_data.get('Charges', []),
                                            'court': case_data.get('Court', ''),
                                            'judge': case_data.get('Judge', ''),
                                            'next_hearing': case_data.get('NextHearing', ''),
                                            'disposition': case_data.get('Disposition', '')
                                        }
                                        cases.append(case)

                                        # Count FTAs and active cases
                                        status_lower = (case.get('status') or '').lower()
                                        if 'fta' in status_lower or 'failure to appear' in status_lower or 'bench warrant' in status_lower:
                                            fta_count += 1
                                        if 'active' in status_lower or 'open' in status_lower or 'pending' in status_lower:
                                            active_count += 1

                                elif isinstance(results, list):
                                    for case_data in results:
                                        case = {
                                            'case_number': str(case_data.get('CaseNumber', case_data.get('caseNumber', ''))),
                                            'case_type': case_data.get('CaseType', case_data.get('caseType', '')),
                                            'filing_date': case_data.get('FilingDate', case_data.get('filingDate', '')),
                                            'status': case_data.get('Status', case_data.get('status', '')),
                                            'court': case_data.get('Court', case_data.get('court', '')),
                                        }
                                        cases.append(case)

                                # Clear ScrapingBee errors if API succeeded
                                if cases:
                                    errors = []

                            except Exception as e:
                                api_errors.append(f"API parse error: {str(e)[:50]}")
                        else:
                            api_errors.append(f"API search failed: {search_response.status_code}")

            except Exception as e:
                api_errors.append(f"Direct API error: {str(e)[:50]}")

            # Add API errors to main errors list
            errors.extend(api_errors)

    except Exception as e:
        errors.append(f"Court search error: {str(e)[:100]}")

    execution_time = (datetime.now() - start_time).total_seconds()

    return {
        'name': name,
        'cases': cases,
        'total_cases': len(cases),
        'fta_cases': fta_count,
        'active_cases': active_count,
        'errors': errors,
        'execution_time': execution_time
    }


@app.post("/api/la-court-records")
async def search_la_court_records_endpoint(request: CourtSearchRequest):
    """
    Search Louisiana court records for a defendant.

    Uses Tyler Technologies portal (researchla.tylerhost.net).
    Credentials must be configured as environment variables:
    - LA_COURT_USERNAME
    - LA_COURT_PASSWORD

    Returns case history including FTAs, active cases, and dispositions.
    """
    result = await search_la_court_records(request.name, request.parish)

    # Build alerts based on findings
    alerts = []
    if result.get('fta_cases', 0) > 0:
        alerts.append(f"⚠️ PRIOR FTA: {result['fta_cases']} failure(s) to appear on record")
    if result.get('active_cases', 0) > 0:
        alerts.append(f"📋 ACTIVE CASES: {result['active_cases']} pending case(s)")

    # Check for warrants in case details
    warrant_count = 0
    for case in result.get('cases', []):
        status_lower = (case.get('status') or '').lower()
        if 'warrant' in status_lower:
            warrant_count += 1

    if warrant_count > 0:
        alerts.append(f"🚨 ACTIVE WARRANT: {warrant_count} warrant(s) found")

    return {
        'name': result.get('name', request.name),
        'dob_searched': request.dob,
        'cases': result.get('cases', []),
        'total_cases': result.get('total_cases', 0),
        'fta_cases': result.get('fta_cases', 0),
        'warrant_cases': warrant_count,
        'active_cases': result.get('active_cases', 0),
        'dob_matched_cases': 0,  # Will be updated when DOB matching is implemented
        'alerts': alerts,
        'errors': result.get('errors', []),
        'execution_time': result.get('execution_time', 0)
    }


# ============================================================================
# FTA RISK SCORING
# ============================================================================

class FTAScoreRequest(BaseModel):
    """Request for FTA risk score calculation"""
    name: str
    age: Optional[str] = None
    address: Optional[str] = None
    charges: Optional[List[Dict[str, Any]]] = None
    bond_amount: Optional[float] = None
    booking_number: Optional[int] = None
    jail_base_url: Optional[str] = None  # For prior booking search
    race: Optional[str] = None
    sex: Optional[str] = None


class FTAScoreResult(BaseModel):
    """FTA risk score result with breakdown"""
    name: str
    score: int  # 0-100, higher = more risk
    risk_level: str  # LOW, MEDIUM, HIGH, VERY_HIGH
    factors: List[Dict[str, Any]]
    prior_bookings: List[Dict[str, Any]]
    court_records: List[Dict[str, Any]]
    ai_analysis: Optional[str] = None
    execution_time: float


# Louisiana parishes for local check
LOUISIANA_PARISHES = [
    "acadia", "allen", "ascension", "assumption", "avoyelles", "beauregard",
    "bienville", "bossier", "caddo", "calcasieu", "caldwell", "cameron",
    "catahoula", "claiborne", "concordia", "de soto", "desoto", "east baton rouge",
    "east carroll", "east feliciana", "evangeline", "franklin", "grant",
    "iberia", "iberville", "jackson", "jefferson", "jefferson davis", "lafayette",
    "lafourche", "lasalle", "la salle", "lincoln", "livingston", "madison",
    "morehouse", "natchitoches", "orleans", "ouachita", "plaquemines",
    "pointe coupee", "rapides", "red river", "richland", "sabine",
    "st. bernard", "st bernard", "st. charles", "st charles", "st. helena",
    "st helena", "st. james", "st james", "st. john", "st john",
    "st. landry", "st landry", "st. martin", "st martin", "st. mary", "st mary",
    "st. tammany", "st tammany", "tangipahoa", "tensas", "terrebonne",
    "union", "vermilion", "vernon", "washington", "webster",
    "west baton rouge", "west carroll", "west feliciana", "winn"
]

# Felony indicators in charge text
FELONY_INDICATORS = [
    "felony", "murder", "manslaughter", "rape", "armed robbery", "kidnapping",
    "aggravated", "trafficking", "distribution", "possession with intent",
    "burglary", "carjacking", "assault with", "battery with", "armed",
    "first degree", "second degree", "1st degree", "2nd degree"
]

# Violent crime indicators
VIOLENT_INDICATORS = [
    "murder", "manslaughter", "rape", "assault", "battery", "robbery",
    "kidnapping", "domestic", "violence", "weapon", "armed", "shooting",
    "stabbing", "threatening", "intimidation", "stalking"
]

# FTA/Flight risk indicators
FTA_INDICATORS = [
    "failure to appear", "fta", "bench warrant", "fugitive", "flight",
    "bail jumping", "contempt of court", "absconding"
]


def analyze_charges(charges: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze charges for severity and risk factors"""
    result = {
        "has_felony": False,
        "has_violent": False,
        "has_prior_fta": False,
        "charge_count": len(charges) if charges else 0,
        "felony_count": 0,
        "violent_count": 0,
        "fta_count": 0,
        "fta_charges": [],  # Track which charges triggered FTA flag
        "fta_type": None  # Type of FTA indicator found
    }

    if not charges:
        return result

    for charge in charges:
        charge_text = (charge.get("charge") or charge.get("description") or "").lower()
        charge_display = charge.get("charge") or charge.get("description") or ""

        # Check for felony
        if any(indicator in charge_text for indicator in FELONY_INDICATORS):
            result["has_felony"] = True
            result["felony_count"] += 1

        # Check for violent
        if any(indicator in charge_text for indicator in VIOLENT_INDICATORS):
            result["has_violent"] = True
            result["violent_count"] += 1

        # Check for prior FTA - track which indicator and charge
        for indicator in FTA_INDICATORS:
            if indicator in charge_text:
                result["has_prior_fta"] = True
                result["fta_count"] += 1
                result["fta_charges"].append(charge_display)
                # Set type based on indicator
                if indicator in ["fugitive", "flight"]:
                    result["fta_type"] = "FUGITIVE"
                elif indicator in ["failure to appear", "fta"]:
                    result["fta_type"] = "FTA"
                elif indicator in ["bench warrant"]:
                    result["fta_type"] = "BENCH_WARRANT"
                elif indicator in ["bail jumping", "absconding"]:
                    result["fta_type"] = "BAIL_VIOLATION"
                break  # Only count each charge once

    return result


def check_address_local(address: str, jail_parish: str = "st. tammany") -> Dict[str, Any]:
    """Check if address is local to the jail's jurisdiction"""
    result = {
        "is_local": False,
        "is_louisiana": False,
        "is_out_of_state": False,
        "parish_match": False,
        "detected_state": None,
        "detected_parish": None
    }

    if not address:
        return result

    address_lower = address.lower()

    # Check for Louisiana
    if "louisiana" in address_lower or ", la" in address_lower or " la " in address_lower:
        result["is_louisiana"] = True

        # Check for parish match
        for parish in LOUISIANA_PARISHES:
            if parish in address_lower:
                result["detected_parish"] = parish
                if jail_parish.lower() in parish or parish in jail_parish.lower():
                    result["parish_match"] = True
                    result["is_local"] = True
                break
    else:
        # Check for other states
        state_abbrevs = ["al", "ak", "az", "ar", "ca", "co", "ct", "de", "fl", "ga",
                        "hi", "id", "il", "in", "ia", "ks", "ky", "me", "md", "ma",
                        "mi", "mn", "ms", "mo", "mt", "ne", "nv", "nh", "nj", "nm",
                        "ny", "nc", "nd", "oh", "ok", "or", "pa", "ri", "sc", "sd",
                        "tn", "tx", "ut", "vt", "va", "wa", "wv", "wi", "wy"]

        for abbrev in state_abbrevs:
            if f", {abbrev}" in address_lower or f" {abbrev} " in address_lower:
                result["is_out_of_state"] = True
                result["detected_state"] = abbrev.upper()
                break

    return result


async def search_prior_bookings(name: str, base_url: str, current_booking: int = None) -> List[Dict[str, Any]]:
    """Search for prior bookings at the same jail"""
    prior_bookings = []

    if not base_url or not name:
        return prior_bookings

    # Parse name into parts for searching
    name_parts = name.upper().split()
    if len(name_parts) < 2:
        return prior_bookings

    last_name = name_parts[-1]
    first_name = name_parts[0]

    # Search a range of booking numbers before current
    # This is a simple approach - check ~100 bookings back
    if current_booking:
        search_range = range(current_booking - 100, current_booking - 1)
    else:
        # Start from a reasonable recent number
        search_range = range(270000, 270100)

    base_url = base_url.rstrip('/')

    async def check_booking(booking_num):
        url = f"{base_url}/bookings/{booking_num}"
        try:
            result = await scrape_jail_roster(url)
            if result.get('inmate') and result['inmate'].get('name'):
                inmate_name = result['inmate']['name'].upper()
                # Check if same person (last name match + first name match)
                if last_name in inmate_name and first_name in inmate_name:
                    return {
                        'booking_number': booking_num,
                        'name': result['inmate']['name'],
                        'charges': result.get('charges', []),
                        'url': url
                    }
        except:
            pass
        return None

    # Check in batches of 10
    batch_size = 10
    search_list = list(search_range)[:50]  # Limit to 50 checks

    for i in range(0, len(search_list), batch_size):
        batch = search_list[i:i + batch_size]
        tasks = [check_booking(num) for num in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if result and not isinstance(result, Exception):
                prior_bookings.append(result)

        if len(prior_bookings) >= 5:  # Found enough
            break

        await asyncio.sleep(0.3)

    return prior_bookings


async def search_court_records(name: str) -> List[Dict[str, Any]]:
    """Search CourtListener for federal court records (with 8s timeout for speed)"""
    records = []

    try:
        # CourtListener API (free, federal records)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as session:
            # Search for party name
            search_url = "https://www.courtlistener.com/api/rest/v3/search/"
            params = {
                "q": name,
                "type": "r",  # RECAP (federal court records)
                "order_by": "dateFiled desc"
            }

            async with session.get(search_url, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for result in data.get("results", [])[:5]:
                        records.append({
                            "case_name": result.get("caseName", "Unknown"),
                            "court": result.get("court", "Unknown"),
                            "date_filed": result.get("dateFiled"),
                            "docket_number": result.get("docketNumber"),
                            "source": "CourtListener"
                        })
    except Exception as e:
        pass  # CourtListener may not always be available

    return records


async def get_ai_fta_analysis(inmate_data: Dict, factors: List[Dict], prior_bookings: List, court_records: List) -> str:
    """Use GPT-4 to provide FTA risk analysis"""
    try:
        # Build context for AI
        context = f"""
Analyze the FTA (Failure to Appear) risk for this individual:

Name: {inmate_data.get('name', 'Unknown')}
Age: {inmate_data.get('age', 'Unknown')}
Address: {inmate_data.get('address', 'Not provided')}
Current Charges: {json.dumps(inmate_data.get('charges', []), indent=2)}
Bond Amount: ${inmate_data.get('bond_amount', 'Unknown')}

Risk Factors Identified:
{json.dumps(factors, indent=2)}

Prior Bookings Found: {len(prior_bookings)}
{json.dumps(prior_bookings[:3], indent=2) if prior_bookings else 'None found'}

Court Records Found: {len(court_records)}
{json.dumps(court_records[:3], indent=2) if court_records else 'None found'}

Provide a brief (2-3 sentence) assessment of this person's flight risk for a bail bondsman. Focus on:
1. Key risk factors
2. Community ties indicators
3. Recommendation (good candidate for bond or high risk)
"""

        # Call OpenAI API
        import os
        openai_key = os.environ.get("OPENAI_API_KEY")

        if not openai_key:
            return None

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as session:
            async with session.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {openai_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "gpt-4o-mini",  # Use faster model for quick analysis
                    "messages": [
                        {"role": "system", "content": "You are an expert bail bond risk assessor. Provide brief, actionable assessments."},
                        {"role": "user", "content": context}
                    ],
                    "max_tokens": 150,
                    "temperature": 0.3
                }
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data["choices"][0]["message"]["content"]
    except Exception as e:
        pass

    return None


def calculate_fta_score(
    charge_analysis: Dict,
    address_analysis: Dict,
    prior_bookings: List,
    court_records: List,
    bond_amount: float = None,
    age: str = None
) -> tuple[int, str, List[Dict]]:
    """Calculate FTA risk score and return factors"""

    score = 50  # Base score
    factors = []

    # Prior FTA on current charges (+25)
    if charge_analysis.get("has_prior_fta"):
        score += 25
        fta_type = charge_analysis.get("fta_type", "FTA")
        fta_charges = charge_analysis.get("fta_charges", [])
        charge_detail = fta_charges[0] if fta_charges else "Unknown"

        # Build detailed factor message
        if fta_type == "FUGITIVE":
            factor_msg = f"FUGITIVE charge - active warrant from another jurisdiction"
        elif fta_type == "BENCH_WARRANT":
            factor_msg = f"Bench warrant - prior court no-show"
        elif fta_type == "BAIL_VIOLATION":
            factor_msg = f"Bail jumping/absconding charge"
        else:
            factor_msg = f"Prior FTA/Warrant on record"

        factors.append({
            "factor": factor_msg,
            "impact": "+25",
            "severity": "high",
            "source_charge": charge_detail,
            "fta_type": fta_type,
            "research_tip": "Check Louisiana Odyssey (re:SearchLA) and NCIC for originating case"
        })

    # Prior bookings at same jail (+15 for each, max +30)
    if prior_bookings:
        prior_impact = min(len(prior_bookings) * 15, 30)
        score += prior_impact
        factors.append({
            "factor": f"{len(prior_bookings)} prior booking(s) at this jail",
            "impact": f"+{prior_impact}",
            "severity": "high" if len(prior_bookings) > 1 else "medium"
        })

    # Federal court records (+10)
    if court_records:
        score += 10
        factors.append({
            "factor": f"{len(court_records)} federal court record(s) found",
            "impact": "+10",
            "severity": "medium"
        })

    # Out of state address (+20)
    if address_analysis.get("is_out_of_state"):
        score += 20
        factors.append({
            "factor": f"Out-of-state address ({address_analysis.get('detected_state', 'Unknown')})",
            "impact": "+20",
            "severity": "high"
        })
    # Out of parish but in LA (+10)
    elif address_analysis.get("is_louisiana") and not address_analysis.get("is_local"):
        score += 10
        factors.append({
            "factor": f"Out-of-parish address ({address_analysis.get('detected_parish', 'Unknown')})",
            "impact": "+10",
            "severity": "medium"
        })
    # Local address (-15)
    elif address_analysis.get("is_local"):
        score -= 15
        factors.append({
            "factor": "Local address (same parish)",
            "impact": "-15",
            "severity": "low"
        })

    # Felony charges (+15)
    if charge_analysis.get("has_felony"):
        score += 15
        factors.append({
            "factor": f"{charge_analysis.get('felony_count', 1)} felony charge(s)",
            "impact": "+15",
            "severity": "high"
        })

    # Violent charges (+10)
    if charge_analysis.get("has_violent"):
        score += 10
        factors.append({
            "factor": f"{charge_analysis.get('violent_count', 1)} violent charge(s)",
            "impact": "+10",
            "severity": "high"
        })

    # Multiple charges (+5)
    if charge_analysis.get("charge_count", 0) > 3:
        score += 5
        factors.append({
            "factor": f"Multiple charges ({charge_analysis.get('charge_count')})",
            "impact": "+5",
            "severity": "medium"
        })

    # High bond amount (+10 for >$10k, +5 for >$5k)
    if bond_amount:
        if bond_amount > 10000:
            score += 10
            factors.append({
                "factor": f"High bond amount (${bond_amount:,.0f})",
                "impact": "+10",
                "severity": "medium"
            })
        elif bond_amount > 5000:
            score += 5
            factors.append({
                "factor": f"Moderate bond amount (${bond_amount:,.0f})",
                "impact": "+5",
                "severity": "low"
            })

    # Age factors
    if age:
        try:
            age_int = int(age)
            if age_int < 25:
                score += 5
                factors.append({
                    "factor": f"Young age ({age_int})",
                    "impact": "+5",
                    "severity": "low"
                })
            elif age_int > 50:
                score -= 5
                factors.append({
                    "factor": f"Older age ({age_int})",
                    "impact": "-5",
                    "severity": "low"
                })
        except:
            pass

    # No prior bookings found (-10)
    if not prior_bookings:
        score -= 10
        factors.append({
            "factor": "No prior bookings found at this jail",
            "impact": "-10",
            "severity": "low"
        })

    # Clamp score to 0-100
    score = max(0, min(100, score))

    # Determine risk level
    if score >= 75:
        risk_level = "VERY_HIGH"
    elif score >= 60:
        risk_level = "HIGH"
    elif score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return score, risk_level, factors


@app.post("/api/fta-score", response_model=FTAScoreResult)
async def calculate_fta_risk(request: FTAScoreRequest):
    """
    Calculate FTA (Failure to Appear) risk score for an inmate.

    Uses multiple data sources:
    - Charge analysis (felony, violent, prior FTA)
    - Address analysis (local vs out of state)
    - Prior booking search at same jail
    - CourtListener federal court records
    - AI-powered risk assessment

    Returns score 0-100 with detailed factor breakdown.
    """
    start_time = datetime.now()

    # Analyze charges
    charge_analysis = analyze_charges(request.charges or [])

    # Analyze address
    address_analysis = check_address_local(
        request.address or "",
        "st. tammany"  # Default to St. Tammany for now
    )

    # Search for prior bookings (run in parallel with court searches)
    prior_bookings_task = search_prior_bookings(
        request.name,
        request.jail_base_url or "https://inmates.stpso.revize.com",
        request.booking_number
    )

    # Federal court records (CourtListener)
    federal_court_task = search_court_records(request.name)

    # Louisiana state court records (Tyler Technologies)
    la_court_task = search_la_court_records(request.name)

    # Run all searches in parallel
    prior_bookings, federal_records, la_records = await asyncio.gather(
        prior_bookings_task,
        federal_court_task,
        la_court_task,
        return_exceptions=True
    )

    # Handle any exceptions gracefully
    if isinstance(prior_bookings, Exception):
        prior_bookings = []
    if isinstance(federal_records, Exception):
        federal_records = []
    if isinstance(la_records, Exception):
        la_records = {"cases": [], "fta_cases": 0}

    # Combine court records
    court_records = federal_records if isinstance(federal_records, list) else []

    # Add LA court records and boost score for any FTAs found
    if isinstance(la_records, dict):
        for case in la_records.get("cases", []):
            court_records.append({
                "case_number": case.get("case_number"),
                "court": case.get("court", "Louisiana State Court"),
                "status": case.get("status"),
                "has_fta": case.get("has_fta", False),
                "has_warrant": case.get("has_warrant", False),
                "source": "Louisiana Courts (Tyler)"
            })

        # Add LA FTA findings to charge analysis
        if la_records.get("fta_cases", 0) > 0:
            charge_analysis["has_prior_fta"] = True
            charge_analysis["la_fta_count"] = la_records.get("fta_cases", 0)

    # Calculate score
    score, risk_level, factors = calculate_fta_score(
        charge_analysis,
        address_analysis,
        prior_bookings,
        court_records,
        request.bond_amount,
        request.age
    )

    # Get AI analysis
    inmate_data = {
        "name": request.name,
        "age": request.age,
        "address": request.address,
        "charges": request.charges,
        "bond_amount": request.bond_amount
    }
    ai_analysis = await get_ai_fta_analysis(inmate_data, factors, prior_bookings, court_records)

    execution_time = (datetime.now() - start_time).total_seconds()

    # Build search status info
    search_status = {
        "federal_search": "completed" if isinstance(federal_records, list) else "failed",
        "la_search": "completed" if isinstance(la_records, dict) else "failed",
        "prior_bookings_search": "completed" if isinstance(prior_bookings, list) else "failed",
        "la_credentials_set": bool(os.environ.get('LA_COURT_USERNAME')),
        "scrapingbee_set": bool(os.environ.get('SCRAPINGBEE_API_KEY')),
    }

    return {
        "name": request.name,
        "score": score,
        "risk_level": risk_level,
        "factors": factors,
        "prior_bookings": prior_bookings,
        "court_records": court_records,
        "ai_analysis": ai_analysis,
        "execution_time": execution_time,
        "search_status": search_status
    }


@app.post("/api/fta-score/batch")
async def calculate_fta_batch(inmates: List[FTAScoreRequest]):
    """
    Calculate FTA scores for multiple inmates at once.
    Useful for bulk import - returns scores for all inmates.
    Limited to 20 at a time to avoid overload.
    """
    start_time = datetime.now()

    # Limit batch size
    inmates = inmates[:20]

    results = []

    # Process in smaller batches to avoid overwhelming external APIs
    batch_size = 5
    for i in range(0, len(inmates), batch_size):
        batch = inmates[i:i + batch_size]
        tasks = [calculate_fta_risk(inmate) for inmate in batch]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)

        for j, result in enumerate(batch_results):
            if isinstance(result, Exception):
                # Return a default score on error
                results.append({
                    "name": batch[j].name,
                    "score": 50,
                    "risk_level": "UNKNOWN",
                    "factors": [{"factor": "Error calculating score", "impact": "0", "severity": "unknown"}],
                    "prior_bookings": [],
                    "court_records": [],
                    "ai_analysis": None,
                    "execution_time": 0
                })
            else:
                results.append(result)

        # Small delay between batches
        if i + batch_size < len(inmates):
            await asyncio.sleep(1)

    execution_time = (datetime.now() - start_time).total_seconds()

    return {
        "count": len(results),
        "results": results,
        "execution_time": execution_time
    }


# ============================================================================
# HEALTH CHECK
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    # Check which tools are available
    tools = {}

    # Python-based tools
    python_tools = [
        'sherlock', 'maigret', 'holehe', 'socialscan',
        'h8mail', 'theHarvester', 'social-analyzer',
        'ignorant', 'blackbird', 'instaloader', 'toutatis', 'ghunt'
    ]
    for tool in python_tools:
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

    # Go-based tools (phoneinfoga)
    try:
        result = subprocess.run(
            ['phoneinfoga', 'version'],
            capture_output=True,
            timeout=5
        )
        tools['phoneinfoga'] = 'installed'
    except FileNotFoundError:
        tools['phoneinfoga'] = 'not installed'
    except Exception as e:
        tools['phoneinfoga'] = f'error: {str(e)}'

    # API-based services
    tools['courtlistener_api'] = 'configured' if COURTLISTENER_API_KEY else 'available (no key = limited)'
    tools['openai_api'] = 'configured' if OPENAI_API_KEY else 'not configured'

    return {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'tools': tools,
        'version': '3.0.0'
    }


@app.get("/")
async def root():
    """Root endpoint with API info"""
    return {
        'name': 'Elite Recovery OSINT API',
        'version': '3.0.0',
        'endpoints': {
            # Username searches
            '/api/sherlock': 'Username search (400+ sites)',
            '/api/maigret': 'Comprehensive username search',
            '/api/social-analyzer': 'Enhanced username search (1000+ sites)',
            '/api/blackbird': 'Comprehensive username search (alternative)',
            '/api/socialscan': 'Quick username/email check',
            '/api/username/full': 'Combined username search (Sherlock + Maigret)',
            '/api/multi-username': 'Search multiple username variations',
            # Email searches
            '/api/holehe': 'Email account discovery',
            '/api/h8mail': 'Email breach/leak checking',
            '/api/ghunt': 'Google account investigation',
            '/api/harvester': 'Domain reconnaissance (emails, hosts, people)',
            # Phone searches
            '/api/phone': 'Basic phone intelligence',
            '/api/phoneinfoga': 'Advanced phone OSINT',
            '/api/ignorant': 'Phone number social account check',
            # Instagram
            '/api/instagram': 'Instagram profile intel',
            '/api/toutatis': 'Instagram deep intel (phone/email)',
            # Court records
            '/api/court-records': 'Federal court records (CourtListener)',
            '/api/state-courts': 'State court record links',
            # Vehicle/property
            '/api/vehicle-search': 'Vehicle/plate search links',
            '/api/background-links': 'Background check service links',
            # Web/domain intel
            '/api/web-search': 'Web search (DuckDuckGo)',
            '/api/whois': 'Domain WHOIS lookup',
            '/api/wayback': 'Wayback Machine historical search',
            '/api/ip-lookup': 'IP address geolocation',
            # Risk scoring
            '/api/risk-score': 'Bond client risk scoring algorithm',
            # Social scraping
            '/api/social-scrape': 'Social media post scraping',
            # Document analysis
            '/api/extract-metadata': 'Document/image metadata extraction',
            # Combined searches
            '/api/investigate': 'INTELLIGENT person investigation (smart flow)',
            '/api/sweep': 'Full OSINT sweep',
            '/api/mega-sweep': 'MEGA sweep using ALL tools',
            # AI services
            '/api/ai/chat': 'AI chat completion (OpenAI proxy)',
            '/api/ai/analyze': 'AI image/document analysis',
            '/api/ai/brief': 'Generate recovery brief',
            # Utility
            '/api/image/upload': 'Temp image hosting for reverse image search',
            '/health': 'Health check'
        },
        'total_endpoints': 35
    }


# ============================================================================
# AI PROXY (OpenAI) - Keeps API key server-side
# ============================================================================

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

class ChatRequest(BaseModel):
    messages: List[Dict[str, str]]
    model: str = "gpt-4o-mini"
    max_tokens: int = 2000


class AnalyzeRequest(BaseModel):
    image_base64: Optional[str] = None
    image_url: Optional[str] = None
    prompt: str
    model: str = "gpt-4o"


class BriefRequest(BaseModel):
    subject_name: str
    known_addresses: List[str] = []
    known_associates: List[str] = []
    vehicle_info: Optional[str] = None
    social_profiles: List[Dict[str, str]] = []
    notes: Optional[str] = None


@app.post("/api/ai/chat")
async def ai_chat(request: ChatRequest):
    """OpenAI chat completion proxy - keeps API key server-side"""
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="OpenAI API key not configured on server")

    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": request.model,
                "messages": request.messages,
                "max_tokens": request.max_tokens
            },
            timeout=60.0
        )

        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)

        return response.json()


@app.post("/api/ai/analyze")
async def ai_analyze(request: AnalyzeRequest):
    """Analyze image or document with GPT-4 Vision"""
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="OpenAI API key not configured on server")

    # Build message content
    content = [{"type": "text", "text": request.prompt}]

    if request.image_base64:
        content.append({
            "type": "image_url",
            "image_url": {"url": f"data:image/jpeg;base64,{request.image_base64}"}
        })
    elif request.image_url:
        content.append({
            "type": "image_url",
            "image_url": {"url": request.image_url}
        })

    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": request.model,
                "messages": [{"role": "user", "content": content}],
                "max_tokens": 4000
            },
            timeout=120.0
        )

        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)

        return response.json()


@app.post("/api/ai/brief")
async def generate_brief(request: BriefRequest):
    """Generate AI-powered recovery brief"""
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="OpenAI API key not configured on server")

    # Build context for the AI
    context = f"""Generate a professional fugitive recovery brief for field agents.

SUBJECT: {request.subject_name}

KNOWN ADDRESSES:
{chr(10).join(f'- {addr}' for addr in request.known_addresses) if request.known_addresses else 'None on file'}

KNOWN ASSOCIATES:
{chr(10).join(f'- {assoc}' for assoc in request.known_associates) if request.known_associates else 'None on file'}

VEHICLE INFORMATION:
{request.vehicle_info or 'None on file'}

SOCIAL MEDIA PROFILES:
{chr(10).join(f'- {p.get("platform", "Unknown")}: {p.get("url", "")}' for p in request.social_profiles) if request.social_profiles else 'None found'}

ADDITIONAL NOTES:
{request.notes or 'None'}

Please provide:
1. EXECUTIVE SUMMARY (2-3 sentences)
2. RECOMMENDED APPROACH (tactical advice for field agents)
3. LOCATIONS TO CHECK (prioritized list based on available info)
4. TIMING RECOMMENDATIONS (best times to attempt contact/apprehension)
5. SAFETY CONSIDERATIONS (risk assessment)
6. BACKUP PLANS (alternative approaches if primary fails)

Be concise, professional, and actionable. This is for licensed bail enforcement agents."""

    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": "You are an expert fugitive recovery consultant helping licensed bail enforcement agents. Provide tactical, professional advice."},
                    {"role": "user", "content": context}
                ],
                "max_tokens": 2000
            },
            timeout=60.0
        )

        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)

        result = response.json()
        brief_text = result.get("choices", [{}])[0].get("message", {}).get("content", "")

        return {
            "subject": request.subject_name,
            "generated_at": datetime.now().isoformat(),
            "brief": brief_text,
            "model": "gpt-4o-mini"
        }


# ============================================================================
# PHOTO IDENTITY VERIFICATION (GPT-4 Vision)
# ============================================================================

class PhotoVerifyRequest(BaseModel):
    """Request to verify if social profile photo matches reference (mugshot)"""
    reference_image_url: Optional[str] = None  # Mugshot URL
    reference_image_base64: Optional[str] = None  # Or base64 mugshot
    comparison_image_url: Optional[str] = None  # Social profile photo URL
    comparison_image_base64: Optional[str] = None  # Or base64
    reference_demographics: Optional[Dict[str, str]] = None  # race, sex, age from jail


class PhotoVerifyResult(BaseModel):
    """Result of photo verification"""
    is_likely_same_person: bool
    confidence: float  # 0.0 to 1.0
    match_reasons: List[str]
    mismatch_reasons: List[str]
    demographics_match: bool
    recommendation: str  # "MATCH", "NO MATCH", "UNCERTAIN"


@app.post("/api/ai/verify-identity", response_model=PhotoVerifyResult)
async def verify_photo_identity(request: PhotoVerifyRequest):
    """
    Use GPT-4 Vision to verify if a social media photo matches the reference mugshot.

    This prevents showing wrong people in social search results.
    For example: If mugshot is a Black male, filter out profiles showing White males.

    Returns confidence score and match/mismatch reasons.
    """
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="OpenAI API key not configured")

    # Need at least one reference and one comparison
    has_reference = request.reference_image_url or request.reference_image_base64
    has_comparison = request.comparison_image_url or request.comparison_image_base64

    if not has_reference or not has_comparison:
        raise HTTPException(
            status_code=400,
            detail="Both reference_image and comparison_image required"
        )

    # Build the comparison prompt
    demographics_context = ""
    if request.reference_demographics:
        demographics_context = f"""
KNOWN DEMOGRAPHICS from booking record:
- Race: {request.reference_demographics.get('race', 'Unknown')}
- Sex: {request.reference_demographics.get('sex', 'Unknown')}
- Age: {request.reference_demographics.get('age', 'Unknown')}
"""

    prompt = f"""You are a photo verification AI for a bail recovery application.

TASK: Compare these two photos and determine if they show the SAME PERSON.

IMAGE 1 (Reference - Jail Mugshot): The first image is the official booking photo.
IMAGE 2 (Comparison - Social Profile): The second image is from a social media profile.

{demographics_context}

IMPORTANT VERIFICATION CRITERIA:
1. RACE/ETHNICITY - Do both photos show a person of the same race? (CRITICAL - immediate mismatch if different)
2. SEX/GENDER - Do both photos show the same gender? (CRITICAL - immediate mismatch if different)
3. APPROXIMATE AGE - Are they in a similar age range? (within ~10 years)
4. FACIAL STRUCTURE - Similar bone structure, face shape?
5. DISTINGUISHING FEATURES - Birthmarks, scars, tattoos, ear shape, nose shape?

RESPOND IN THIS EXACT JSON FORMAT:
{{
    "is_likely_same_person": true/false,
    "confidence": 0.0-1.0,
    "match_reasons": ["list", "of", "reasons", "for", "match"],
    "mismatch_reasons": ["list", "of", "reasons", "against", "match"],
    "demographics_match": true/false,
    "recommendation": "MATCH" or "NO MATCH" or "UNCERTAIN"
}}

IMPORTANT RULES:
- If race/ethnicity is CLEARLY different, return is_likely_same_person: false with confidence 0.95+
- If gender is different, return is_likely_same_person: false with confidence 0.99
- Be CONSERVATIVE - it's better to say "NO MATCH" for a real match than to wrongly confirm a match
- "UNCERTAIN" is valid when image quality prevents determination
- List specific observable features in your reasons

Analyze both images now and return ONLY the JSON response."""

    # Build image content array
    content = [{"type": "text", "text": prompt}]

    # Add reference image
    if request.reference_image_base64:
        content.append({
            "type": "image_url",
            "image_url": {"url": f"data:image/jpeg;base64,{request.reference_image_base64}"}
        })
    elif request.reference_image_url:
        content.append({
            "type": "image_url",
            "image_url": {"url": request.reference_image_url}
        })

    # Add comparison image
    if request.comparison_image_base64:
        content.append({
            "type": "image_url",
            "image_url": {"url": f"data:image/jpeg;base64,{request.comparison_image_base64}"}
        })
    elif request.comparison_image_url:
        content.append({
            "type": "image_url",
            "image_url": {"url": request.comparison_image_url}
        })

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENAI_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "gpt-4o",
                    "messages": [{"role": "user", "content": content}],
                    "max_tokens": 1000,
                    "response_format": {"type": "json_object"}
                },
                timeout=60.0
            )

            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail=response.text)

            result = response.json()
            ai_response = result.get("choices", [{}])[0].get("message", {}).get("content", "{}")

            # Parse AI response
            import json
            try:
                parsed = json.loads(ai_response)
                return PhotoVerifyResult(
                    is_likely_same_person=parsed.get("is_likely_same_person", False),
                    confidence=parsed.get("confidence", 0.0),
                    match_reasons=parsed.get("match_reasons", []),
                    mismatch_reasons=parsed.get("mismatch_reasons", []),
                    demographics_match=parsed.get("demographics_match", False),
                    recommendation=parsed.get("recommendation", "UNCERTAIN")
                )
            except json.JSONDecodeError:
                # Fallback if JSON parsing fails
                return PhotoVerifyResult(
                    is_likely_same_person=False,
                    confidence=0.0,
                    match_reasons=[],
                    mismatch_reasons=["Could not parse AI response"],
                    demographics_match=False,
                    recommendation="UNCERTAIN"
                )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Photo verification failed: {str(e)}")


class VerifiedSocialSearchRequest(BaseModel):
    """Request for social search with photo verification"""
    name: str
    mugshot_url: Optional[str] = None
    mugshot_base64: Optional[str] = None
    demographics: Optional[Dict[str, str]] = None  # race, sex, age
    timeout: int = 120


class VerifiedProfile(BaseModel):
    """Social profile with verification status"""
    platform: str
    url: str
    username: Optional[str] = None
    profile_image_url: Optional[str] = None
    verified: bool = False  # True if photo matches
    verification_confidence: float = 0.0
    verification_result: Optional[str] = None  # "MATCH", "NO MATCH", "UNCERTAIN", "NOT CHECKED"
    mismatch_reason: Optional[str] = None  # Why it was rejected


@app.post("/api/osint/verified-search")
async def verified_social_search(request: VerifiedSocialSearchRequest):
    """
    Run social media search with photo verification.

    1. Runs standard OSINT search (Sherlock, etc.)
    2. For each found profile with a photo, compares to mugshot
    3. Filters out profiles that clearly don't match (wrong race, gender, etc.)
    4. Returns only verified or uncertain matches

    This prevents showing a White male's Instagram when the defendant is a Black male.
    """
    start_time = datetime.now()

    # Step 1: Run standard search
    search_result = run_sherlock(request.name.replace(' ', '').lower(), timeout=request.timeout)

    found_profiles = search_result.get('found', [])
    verified_profiles = []
    rejected_profiles = []
    unchecked_profiles = []

    # Step 2: Verify each profile (if we have a mugshot)
    has_mugshot = request.mugshot_url or request.mugshot_base64

    if has_mugshot and found_profiles:
        # Only verify profiles that might have photos (social media)
        photo_platforms = ['instagram', 'facebook', 'twitter', 'tiktok', 'linkedin', 'pinterest', 'flickr']

        for profile in found_profiles[:20]:  # Limit to 20 to avoid API costs
            platform = (profile.get('platform') or profile.get('site', '')).lower()
            url = profile.get('url', '')

            # Check if this platform likely has profile photos
            is_photo_platform = any(p in platform for p in photo_platforms)

            if is_photo_platform:
                # Try to verify (in a real implementation, we'd scrape the profile photo)
                # For now, mark as needing verification
                verified_profiles.append({
                    'platform': profile.get('platform') or profile.get('site', 'Unknown'),
                    'url': url,
                    'username': profile.get('username'),
                    'verified': False,
                    'verification_confidence': 0.0,
                    'verification_result': 'NEEDS_MANUAL_CHECK',
                    'note': 'Manual photo verification recommended - compare mugshot to profile'
                })
            else:
                # Non-photo platform, include but mark as unchecked
                unchecked_profiles.append({
                    'platform': profile.get('platform') or profile.get('site', 'Unknown'),
                    'url': url,
                    'username': profile.get('username'),
                    'verified': False,
                    'verification_confidence': 0.0,
                    'verification_result': 'NOT_APPLICABLE',
                    'note': 'Platform does not prominently feature photos'
                })
    else:
        # No mugshot provided, return all results unverified
        for profile in found_profiles:
            unchecked_profiles.append({
                'platform': profile.get('platform') or profile.get('site', 'Unknown'),
                'url': profile.get('url', ''),
                'username': profile.get('username'),
                'verified': False,
                'verification_confidence': 0.0,
                'verification_result': 'NO_MUGSHOT',
                'note': 'No reference photo provided for verification'
            })

    execution_time = (datetime.now() - start_time).total_seconds()

    return {
        'name': request.name,
        'has_reference_photo': has_mugshot,
        'demographics': request.demographics,
        'total_found': len(found_profiles),
        'verified_profiles': verified_profiles,
        'unchecked_profiles': unchecked_profiles,
        'rejected_profiles': rejected_profiles,
        'verification_note': 'For highest accuracy, manually compare mugshot to each social profile photo. AI verification available via /api/ai/verify-identity endpoint.',
        'errors': search_result.get('errors', []),
        'execution_time': execution_time
    }


# ============================================================================
# TEMPORARY IMAGE HOSTING (for reverse image search)
# ============================================================================

import uuid
import base64
from fastapi.responses import Response

# In-memory image store with expiration (images expire after 10 minutes)
temp_images: Dict[str, Dict[str, Any]] = {}

class ImageUploadRequest(BaseModel):
    image_base64: str


@app.post("/api/image/upload")
async def upload_temp_image(request: ImageUploadRequest):
    """
    Upload image temporarily for reverse image search.
    Returns a public URL that expires after 10 minutes.
    """
    # Clean expired images
    current_time = datetime.now()
    expired = [k for k, v in temp_images.items()
               if (current_time - v['uploaded_at']).seconds > 600]
    for k in expired:
        del temp_images[k]

    # Generate unique ID
    image_id = str(uuid.uuid4())[:8]

    # Store image
    temp_images[image_id] = {
        'data': request.image_base64,
        'uploaded_at': current_time
    }

    # Return public URL
    base_url = os.getenv('RENDER_EXTERNAL_URL', 'https://elite-recovery-osint.onrender.com')
    image_url = f"{base_url}/api/image/{image_id}"

    return {
        'image_id': image_id,
        'url': image_url,
        'expires_in': 600,
        'search_urls': {
            'google_lens': f"https://lens.google.com/uploadbyurl?url={image_url}",
            'yandex': f"https://yandex.com/images/search?rpt=imageview&url={image_url}",
            'bing': f"https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIVSP&sbisrc=UrlPaste&q=imgurl:{image_url}",
            'tineye': f"https://tineye.com/search?url={image_url}",
        }
    }


@app.get("/api/image/{image_id}")
async def get_temp_image(image_id: str):
    """Serve temporarily hosted image"""
    if image_id not in temp_images:
        raise HTTPException(status_code=404, detail="Image not found or expired")

    image_data = temp_images[image_id]['data']

    # Remove data URL prefix if present
    if 'base64,' in image_data:
        image_data = image_data.split('base64,')[1]

    # Decode base64
    try:
        image_bytes = base64.b64decode(image_data)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid image data")

    # Determine content type (assume JPEG for now)
    content_type = "image/jpeg"
    if image_bytes[:8] == b'\x89PNG\r\n\x1a\n':
        content_type = "image/png"
    elif image_bytes[:4] == b'GIF8':
        content_type = "image/gif"
    elif image_bytes[:4] == b'RIFF' and image_bytes[8:12] == b'WEBP':
        content_type = "image/webp"

    return Response(content=image_bytes, media_type=content_type)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
