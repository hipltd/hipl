import os 
import asyncio 
import ipaddress
import re
import socket 
import httpx 
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from protego import Protego 
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
# ------------------------------------------------------------- #

# AI bots 
AI_BOTS = {
    "GPTBot": "OpenAI (training)",
    "OAI-SearchBot": "OpenAI (search)",
    "ChatGPT-User": "OpenAI (live browsing)",
    "ClaudeBot": "Anthropic (training)",
    "Claude-User": "Anthropic (live browsing)",
    "PerplexityBot": "Perplexity",
    "Google-Extended": "Google (Gemini training)",
    "Applebot-Extended": "Apple (AI training)",
    "CCBot": "Common Crawl",
}
# ------------------------------------------------------------- #

# bot ua strings 
BOT_UA_STRINGS = {
    "GPTBot": {
        "label": "OpenAI (training)",
        "ua": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); "
              "compatible; GPTBot/1.1; +https://openai.com/gptbot",
    },
    "ChatGPT-User": {
        "label": "OpenAI (live browsing)",
        "ua": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); "
              "compatible; ChatGPT-User/1.0; +https://openai.com/bot",
    },
    "ClaudeBot": {
        "label": "Anthropic (training)",
        "ua": "Mozilla/5.0 (compatible; ClaudeBot/1.0; "
              "+claudebot@anthropic.com)",
    },
    "PerplexityBot": {
        "label": "Perplexity",
        "ua": "Mozilla/5.0 (compatible; PerplexityBot/1.0; "
              "+https://perplexity.ai/perplexitybot)",
    },
}
# ------------------------------------------------------------- #

# challenge markers 
CHALLENGE_MARKERS = [
    "just a moment",           # Cloudflare interstitial
    "cf-browser-verification", # Cloudflare
    "__cf_chl",                # Cloudflare challenge script
    "attention required",      # Cloudflare block page title
    "checking your browser",   # generic / older Cloudflare
    "access denied",           # generic WAF block
    "ddos-guard",               # DDoS-Guard block page
    "px-captcha",               # PerimeterX
    "distil_r_captcha",         # Distil Networks / Imperva
]
# ------------------------------------------------------------- #

# bot management signatures
BOT_MANAGEMENT_SIGNATURES = {
    "cf-ray": "Cloudflare",
    "cf-mitigated": "Cloudflare Bot Management",
    "x-datadome": "DataDome",
    "x-px": "PerimeterX / HUMAN Security",
    "x-distil-cs": "Imperva / Distil Networks",
}
# ------------------------------------------------------------- #

# consent managers 
CONSENT_MANAGERS = {
    "cdn.cookielaw.org": "OneTrust",
    "consent.cookiebot.com": "Cookiebot",
    "quantcast.mgr.consensu.org": "Quantcast",
    "app.termly.io": "Termly",
    "osano.com/osano.js": "Osano"
}
# ------------------------------------------------------------- #

# raw vs rendered settings 
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
MIN_WORDS = 50          # below this the page is too thin to judge
PASS_RATIO = 0.80       # raw HTML has >= 80% of the rendered text
PARTIAL_RATIO = 0.40    # 40%-80% = partial, below 40% = fail
# ------------------------------------------------------------- #

def count_visible_words(html):
    clean_soup = BeautifulSoup(html, "html.parser")
    for tag in clean_soup(["script", "style", "noscript", "template", "svg"]):
        tag.decompose()
    return len(clean_soup.get_text(" ", strip=True).split())
# ------------------------------------------------------------- #

# helper: blocks localhost / private / internal addresses (SSRF guard)
def is_public_host(hostname):
    try:
        for info in socket.getaddrinfo(hostname, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
        return True
    except (socket.gaierror, ValueError):
        return False
# ------------------------------------------------------------- #

# helper functions for check_bot_ua_response function 
def looks_challenged(body_sample: str) -> bool:
    lowered = body_sample.lower()
    return any(marker in lowered for marker in CHALLENGE_MARKERS)
 
 
def detect_bot_management(headers: httpx.Headers) -> list[str]:
    found = []
    for header_name, vendor in BOT_MANAGEMENT_SIGNATURES.items():
        if header_name in headers and vendor not in found:
            found.append(vendor)
    return found
# ------------------------------------------------------------- #

# bot ua response checker function 

async def check_bot_ua_responses(client: httpx.AsyncClient, url: str, baseline_word_count: int) -> dict:
    result = {"bots": {}, "bot_management_detected": []}

    for bot_name, info in BOT_UA_STRINGS.items():
        bot_result = {
            "label": info["label"],
            "status": None,
            "http_status": None, 
            "content_length": None
        }

        try:
            resp = await client.get(
                url,
                headers={"User-Agent": info["ua"]},
                timeout=10,
                follow_redirects=True
            )
            bot_result["http_status"] = resp.status_code

            management = detect_bot_management(resp.headers)
            for vendor in management:
                if vendor not in result["bot_management_detected"]:
                    result["bot_management_detected"].append(vendor)

            if resp.status_code in (403, 429, 503):
                bot_result["status"] = "blocked"
            elif looks_challenged(resp.text[:2000]):
                bot_result["status"] = "challenged"
            elif resp.status_code >= 400:
                bot_result["status"] = "blocked"
            else:
                bot_result["content_length"] = len(resp.text)

                if baseline_word_count > 0:
                    rough_word_estimate = len(resp.text.split())
                    if rough_word_estimate < baseline_word_count * 0.5:
                        bot_result["status"] = "challenged"
                    else:
                        bot_result["status"] = "ok"
                else:
                    bot_result["status"] = "ok"
        except httpx.HTTPError:
            bot_result["status"] = "error"

            result["bots"][bot_name] = bot_result

    return result
# ------------------------------------------------------------- #

async def scrape_website(url):

    # url validation
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    root = urlparse(url)
    if not root.hostname:
        return {"error": "Invalid URL."}
    if not await asyncio.to_thread(is_public_host, root.hostname):
        return {"error": "This URL can't be audited."}
    # ------------------------------------------------------------- #

    async with httpx.AsyncClient(headers={"User-Agent": BROWSER_UA}, timeout=15) as client:

        # initiliazing the audit_results dictionaries 
        
        audit_results = {"seo": {}, "socials": {}, "content": {}, "accessibility": {}}
        audit_results["seo"]["schema_detected"] = False
        audit_results["security"] = {}
        audit_results["performance"] = {}
        audit_results["tracking"] = {"google_analytics": False, "meta_analytics": False}
        audit_results["ai_readiness"] = {}
        # ------------------------------------------------------------- #

        # ai readiness check
        base = f"{root.scheme}://{root.netloc}"
        audit_results["ai_readiness"] = {"robots_status": None, "bots": {}, 
                                         "llms_text": 
                                         {"exists": False, "word_count": 0, "has_markdown": False}}

        try:
            resp = await client.get(f"{base}/robots.txt", follow_redirects=True, timeout=10)
            if resp.status_code == 200:
                rp = Protego.parse(resp.text)
                sitemap = list(rp.sitemaps)
                audit_results["ai_readiness"]["robots_status"] = "found"
                audit_results["ai_readiness"]["sitemaps"] = sitemap
            elif resp.status_code in (401, 403):
                # we were probably blocked, this does NOT mean bots are blocked, so no bot table
                audit_results["ai_readiness"]["robots_status"] = "forbidden"
            elif 400 <= resp.status_code < 500:
                rp = Protego.parse("")
                audit_results["ai_readiness"]["robots_status"] = "missing"
            else:
                audit_results["ai_readiness"]["robots_status"] = "server_error"
        except httpx.HTTPError:
            audit_results["ai_readiness"]["robots_status"] = "unreachable"
        
        if audit_results["ai_readiness"]["robots_status"] in ("found", "missing"):
            for bot, label in AI_BOTS.items():
                audit_results["ai_readiness"]["bots"][bot] = {
                    "label": label,
                    "allowed": rp.can_fetch(f"{base}/", bot)
                }
        # ------------------------------------------------------------- #

        # llms txt check 
        try: 
            r = await client.get(f"{base}/llms.txt", follow_redirects=True, timeout=10)
            if r.status_code == 200 and "html" not in r.headers.get("content-type", ""):
                audit_results["ai_readiness"]["llms_text"]["exists"] = True
                content = r.text 

                words = content.split()
                audit_results["ai_readiness"]["llms_text"]["word_count"] = len(words)

                if re.search(r'(^|\n)#+\s|\]\(|\*\*|```', content):
                    audit_results["ai_readiness"]["llms_text"]["has_markdown"] = True
        except httpx.HTTPError:
            pass
        # ------------------------------------------------------------- #

        # checking for sitemap data 
        sitemap_list = audit_results["ai_readiness"].get("sitemaps", [])
        if sitemap_list:
            target_sitemap_url = sitemap_list[0]
        else:
            target_sitemap_url = f"{base}/sitemap.xml"

        audit_results["ai_readiness"]["sitemap_data"] = {
            "found": False, 
            "type": None, 
            "url_count": 0, 
            "has_lastmod": False
        }
        try:
            sitemap_resp = await client.get(target_sitemap_url)

            if sitemap_resp.status_code == 200:
                audit_results["ai_readiness"]["sitemap_data"]["found"] = True 

                xml_parser = BeautifulSoup(sitemap_resp.content, "xml")

                # check if its an index or a standard url set 
                sitemap_index = xml_parser.find("sitemapindex")

                if sitemap_index:
                    audit_results["ai_readiness"]["sitemap_data"]["type"] = "index"

                    # counting child sitemap directories
                    sitemaps = xml_parser.find_all("sitemap")
                    audit_results["ai_readiness"]["sitemap_data"]["url_count"] = len(sitemaps)
                else:
                    audit_results["ai_readiness"]["sitemap_data"]["type"] = "urlset"

                    # counting standard url tags
                    urls = xml_parser.find_all("url")
                    audit_results["ai_readiness"]["sitemap_data"]["url_count"] = len(urls)

                # checking freshness
                lastmod_tag = xml_parser.find("lastmod")
                if lastmod_tag:
                    audit_results["ai_readiness"]["sitemap_data"]["has_lastmod"] = True
            
        except httpx.HTTPError:
            pass
        # ------------------------------------------------------------- #

        # parsing html using beautiful soup
        try:
            response = await client.get(url, follow_redirects=True)
            soup = BeautifulSoup(response.text, "html.parser")
        except httpx.HTTPError:
            return {"error": "Could not reach this website."}

        # raw vs rendered content check
        # raw = the HTML we already fetched above (no JavaScript), rendered = what a real browser sees
        audit_results["ai_readiness"]["raw_vs_rendered"] = {
            "raw_words": None,
            "rendered_words": None,
            "ratio": None,
            "status": None,  
        }
 
        try:
            # if the raw fetch returned an error page, the comparison is meaningless
            if response.status_code >= 400:
                raise ValueError("raw fetch failed")

            raw_words = count_visible_words(response.text)
            audit_results["ai_readiness"]["active_bot_challenge"] = await check_bot_ua_responses(client, url, raw_words)
            audit_results["ai_readiness"]["raw_vs_rendered"]["raw_words"] = raw_words
 
            async with async_playwright() as p:
                browser = await p.chromium.launch()
                context = await browser.new_context(user_agent=BROWSER_UA)
                page = await context.new_page()
                await page.goto(url, wait_until="domcontentloaded", timeout=20000)
                try:
                    # many sites poll forever, so don't fail if this times out
                    await page.wait_for_load_state("networkidle", timeout=8000)
                except PlaywrightTimeout:
                    pass
                rendered_html = await page.content()
                await browser.close()
 
            rendered_words = count_visible_words(rendered_html)
            audit_results["ai_readiness"]["raw_vs_rendered"]["rendered_words"] = rendered_words
 
            if rendered_words < MIN_WORDS:
                audit_results["ai_readiness"]["raw_vs_rendered"]["status"] = "insufficient_content"
            else:
                ratio = min(raw_words / rendered_words, 1.0)  # capped at 1, raw can exceed rendered
                audit_results["ai_readiness"]["raw_vs_rendered"]["ratio"] = round(ratio, 2)
 
                if ratio >= PASS_RATIO:
                    audit_results["ai_readiness"]["raw_vs_rendered"]["status"] = "pass"
                elif ratio >= PARTIAL_RATIO:
                    audit_results["ai_readiness"]["raw_vs_rendered"]["status"] = "partial"
                else:
                    audit_results["ai_readiness"]["raw_vs_rendered"]["status"] = "fail"
        except Exception:
            audit_results["ai_readiness"]["raw_vs_rendered"]["status"] = "error"
        # ------------------------------------------------------------- #

        # schema check
        script_tags = soup.find_all("script", attrs={"type": "application/ld+json"})

        if not script_tags:
            audit_results["seo"]["schema_detected"] = False
        else:
            audit_results["seo"]["schema_detected"] = True
        # ------------------------------------------------------------- #

        # security check 
        security_headers = ["strict-transport-security", "x-frame-options", "x-content-type-options"]

        for item in security_headers:
            if item in response.headers:
                audit_results["security"][item] = True 
            else:
                audit_results["security"][item] = False

        if "x-robots-tag" in response.headers:
            audit_results["ai_readiness"]["x_robots_tag"] = response.headers.get("x-robots-tag")
        else:
            audit_results["ai_readiness"]["x_robots_tag"] = "None"
        # ------------------------------------------------------------- #

        # analytics check
        google_analytics = re.search(r"GTM-[A-Z0-9]+|G-[A-Z0-9]+", response.text)
        meta_analytics = re.search(r"fbevents\.js", response.text)

        # initializing the cookie wall check 
        audit_results["ai_readiness"]["cookie_wall_detected"] = False 

        for signature in CONSENT_MANAGERS:
            if signature in response.text:
                audit_results["ai_readiness"]["cookie_wall_detected"] = True 
                break

        if not google_analytics:
            audit_results["tracking"]["google_analytics"] = False 
        else:
            audit_results["tracking"]["google_analytics"] = True 

        if not meta_analytics:
            audit_results["tracking"]["meta_analytics"] = False 
        else:
            audit_results["tracking"]["meta_analytics"] = True 
        # ------------------------------------------------------------- #

        # load time check 
        # this is server response time (time to headers), not full page load
        time_elapsed = response.elapsed.total_seconds()
        audit_results["performance"]["load_time_seconds"] = time_elapsed
        # ------------------------------------------------------------- #

        # title check 
        if not soup.title:
            audit_results["seo"]["title"] = "None"
        else:
            audit_results["seo"]["title"] = soup.title.text
        # ------------------------------------------------------------- #

        # meta description check 
        meta_desc_tag = soup.find("meta", attrs={"name": "description"})
        if not meta_desc_tag:
            audit_results["seo"]["meta_desc"] = "None"
        else:
            audit_results["seo"]["meta_desc"] = meta_desc_tag.get("content")
        # ------------------------------------------------------------- #

        # headings check 
        headings = soup.find_all(['h1', 'h2', 'h3'])
        audit_results["seo"]["h1_count"] = 0
        audit_results["seo"]["h2_count"] = 0
        audit_results["seo"]["h3_count"] = 0

        for heading in headings:
            if heading.name == 'h1':
                audit_results["seo"]["h1_count"] += 1
            elif heading.name == 'h2':
                audit_results["seo"]["h2_count"] += 1
            elif heading.name == 'h3':
                audit_results["seo"]["h3_count"] += 1
        # ------------------------------------------------------------- #

        # alt text check 
        # only counts images with NO alt attribute (alt="" is valid for decorative images)
        alt_text = soup.find_all("img")
        total_images = 0
        missing_alt = 0
        for text in alt_text:
            if text.get("alt") is None:
                missing_alt += 1
        
            total_images += 1
        
        audit_results["seo"]["alt_text"] = missing_alt 
        audit_results["seo"]["images"] = total_images
        # ------------------------------------------------------------- #

        # canonical tag check 
        tag = soup.find("link", attrs={"rel": "canonical"})
        if not tag:
            audit_results["seo"]["canonical_tag"] = "None"
        else:
            audit_results["seo"]["canonical_tag"] = tag.get("href")
        # ------------------------------------------------------------- #

        # word count check 
        audit_results["seo"]["word_count"] = count_visible_words(response.text)
        # ------------------------------------------------------------- #

        # socials check 
        audit_results["socials"]["open_graph"] = {}
        audit_results["socials"]["twitter"] = {}

        all_meta = soup.find_all("meta")
        for meta in all_meta:
            meta_property = meta.get("property")
            if meta_property and meta_property.startswith("og:"):
                content_variable = meta.get("content")
                audit_results["socials"]["open_graph"][meta_property] = content_variable

            meta_name = meta.get("name")
            if meta_name and meta_name.startswith("twitter:"):
                meta_twitter = meta.get("content")
                audit_results["socials"]["twitter"][meta_name] = meta_twitter

            elif meta.get("name") == "robots":
                audit_results["ai_readiness"]["meta_robots"] = meta.get("content")
        # ------------------------------------------------------------- #

        # favicon check
        favicon = soup.find("link", attrs={"rel": "icon"})

        if not favicon:
            favicon = soup.find("link", attrs={"rel": "shortcut icon"})

            if not favicon:
                audit_results["socials"]["favicon"] = "None"
            else:
                audit_results["socials"]["favicon"] = favicon.get("href")
        else:
            audit_results["socials"]["favicon"] = favicon.get("href")
        # ------------------------------------------------------------- #

        # social profiles check  
        social_profiles = soup.find_all("a", href=True)

        for profile in social_profiles:
            link_variable = profile.get("href")

            if "linkedin.com" in link_variable:
                audit_results["socials"]["linkedin"] = link_variable 
            elif "facebook.com" in link_variable:
                audit_results["socials"]["facebook"] = link_variable 
            elif "instagram.com" in link_variable:
                audit_results["socials"]["instagram"] = link_variable 
            elif "tiktok" in link_variable:
                audit_results["socials"]["tiktok"] = link_variable 
        # ------------------------------------------------------------- #
        
        # footer check
        footer_tag = soup.find("footer")
        if not footer_tag:
            footer_tag = soup.find("div", attrs={"class": "footer"})
        if not footer_tag:
            footer_tag = soup.find("div", attrs={"id": "footer"})
        if not footer_tag:
            audit_results["content"]["copyright_year"] = "None"
        else:
            footer_tag = footer_tag.get_text(separator=" ", strip=True)
            year_match = re.search(r"20\d{2}", footer_tag)

            if not year_match:
                audit_results["content"]["copyright_year"] = "None"
            else:
                audit_results["content"]["copyright_year"] = year_match.group(0)
        # ------------------------------------------------------------- #

        # accessibility check 
        missing_labels = 0
        total_inputs = 0

        input_field = soup.find_all("input")

        for field in input_field:
            if field.get("type") == "hidden" or field.get("type") == "submit":
                continue
            else:
                total_inputs += 1

                if not field.get("aria-label"):
                    input_id = field.get("id")
                    if not input_id:
                        missing_labels += 1
                    else:
                        find_input = soup.find("label", attrs={"for": input_id})

                        if not find_input:
                            missing_labels += 1
        audit_results["accessibility"]["missing_labels"] = missing_labels 
        audit_results["accessibility"]["total_inputs"] = total_inputs    
        # ------------------------------------------------------------- #
    
    audit_results["scorecard"] = generate_scorecard(audit_results)
    return audit_results
# ------------------------------------------------------------- #

# generating the scorecard 

def generate_scorecard(audit_results):
    
    # initializing variables
    total_score = 0
    category_scores = {}
    action_items = []
    strengths = []
    # ------------------------------------------------------------- #
    
    # initializing the score variables 
    # ai readiness scores
    ai_bots_score = 0
    ai_content_score = 0
    ai_llms_score = 0
    ai_bonus = 0
    ai_penalty = 0
    ai_net_score = 0
    # ------------------------------------------------------------- #
    
    # seo scores 
    seo_score = 0
    # ------------------------------------------------------------- #

    # performance score 
    perf_score = 0
    # ------------------------------------------------------------- #

    # content score 
    content_score = 0 
    # ------------------------------------------------------------- #

    # accessibility score 
    access_score = 0
    # ------------------------------------------------------------- #

    # security and tracking score 
    sec_track_score = 0
    # ------------------------------------------------------------- #

    # ai readiness score 
    for bot_name in audit_results["ai_readiness"].get("bots", {}):
        if audit_results["ai_readiness"]["bots"][bot_name].get("allowed") is True:
            ai_bots_score += 1.66

    ai_bots_score = min(15.0, ai_bots_score)

    render_status = audit_results["ai_readiness"].get("raw_vs_rendered", {}).get("status")
    has_cookie_wall = audit_results["ai_readiness"].get("cookie_wall_detected", False)

    if render_status == "pass":
        ai_content_score += 10
    elif render_status == "partial":
        ai_content_score += 5
    else:
        # Split the failure state to check for consent managers
        if has_cookie_wall:
            ai_penalty -= 5
            action_items.append("Critical: A strict cookie consent wall is blocking AI crawlers from reading your content. Consider conditionally allowing known AI bots.")
        else:
            action_items.append("JavaScript reliance may be blocking AI crawlers.")

    llms_data = audit_results["ai_readiness"].get("llms_text", {})
    if llms_data.get("exists") is True:
        if llms_data.get("word_count", 0) >= 20 and llms_data.get("has_markdown") is True:
            ai_llms_score += 5
            strengths.append("LLMS.txt documentation detected for AI crawlers.")
        else:
            action_items.append("Your /llms.txt file was found, but it appears to lack sufficient content or proper Markdown formatting.")
    else:
        action_items.append("Suggest creating an /llms.txt file to guide AI crawlers to your key documentation.")
    # ------------------------------------------------------------- #
    
    # reward the Sitemap
    sitemap_metrics = audit_results["ai_readiness"].get("sitemap_data", {})
    
    if sitemap_metrics.get("found") is True:
        ai_bonus += 2
        strengths.append("Valid XML sitemap deteced.")
        
        # Reward populated URLs
        if sitemap_metrics.get("url_count", 0) > 0:
            ai_bonus += 1
            
        # Reward freshness signals
        if sitemap_metrics.get("has_lastmod") is True:
            ai_bonus += 2
        else:
            action_items.append("Configure your CMS to inject <lastmod> tags in your sitemap so AI crawlers know when to re-index content.")
    else:
        action_items.append("Critical: No valid XML sitemap was found. Generate a sitemap.xml to improve crawler discovery.")
    # ------------------------------------------------------------- #

    # penalize the On-Page Tags
    blocks_ai = False
    meta_robots = audit_results["ai_readiness"].get("meta_robots")
    x_robots_tag = audit_results["ai_readiness"].get("x_robots_tag")

    if meta_robots:
        mr_lower = meta_robots.lower()
        if any(tag in mr_lower for tag in ["noindex", "noai", "noimageai"]):
            blocks_ai = True

    if x_robots_tag and x_robots_tag != "None":
        xr_lower = x_robots_tag.lower()
        if any(tag in xr_lower for tag in ["noindex", "noai", "noimageai"]):
            blocks_ai = True

    if blocks_ai:
        ai_penalty -= 15
        action_items.append("Critical: On-page meta tags or X-Robots headers are explicitly blocking AI crawlers (noindex/noai/noimageai).")
    # ------------------------------------------------------------- #

    # penalize the Bot Management Walls
    active_challenge = audit_results["ai_readiness"].get("active_bot_challenge", {})
    challenged_bots = active_challenge.get("bots", {})
    vendors = active_challenge.get("bot_management_detected", [])
    
    bot_blocked = False
    for bot_name, data in challenged_bots.items():
        if data.get("status") in ("blocked", "challenged"):
            bot_blocked = True
            break
            
    if bot_blocked:
        ai_penalty -= 10
        vendor_str = f" ({', '.join(vendors)})" if vendors else ""
        action_items.append(f"Critical: Your server's security firewall{vendor_str} is actively blocking or challenging AI agents.")
    # ------------------------------------------------------------- #

    # Calculate net score (preventing it from dropping below 0)
    ai_net_score = round((ai_bots_score + ai_content_score + ai_llms_score + ai_bonus + ai_penalty), 2)
    ai_net_score = max(0, ai_net_score)

    category_scores["ai_readiness"] = ai_net_score
    total_score += ai_net_score
    # ------------------------------------------------------------- #

    # seo scores
    if audit_results["seo"].get("title") != "None":
        seo_score += 4
    else:
        action_items.append("Add a descriptive Title tag to improve search visibility.")

    if audit_results["seo"].get("meta_desc") != "None":
        seo_score += 4
        strengths.append("Meta description configured.")
    else:
        action_items.append("Add a Meta Description to improve click-through rates from search engines.")

    if audit_results["seo"].get("h1_count") == 1:
        seo_score += 4
        strengths.append("Decent H1 tag structure.")
    else:
        action_items.append("Ensure your page has exactly one H1 tag to establish the main topic.")

    total_images = audit_results["seo"].get("images", 0)
    if total_images == 0:
        seo_score += 4
    else:
        missing_alt = audit_results["seo"].get("alt_text", 0)
        seo_score += ((total_images - missing_alt) / total_images) * 4
        if missing_alt > 0:
            action_items.append(f"Add descriptive alt text to the {missing_alt} image(s) missing it for accessibility and SEO.")

    if audit_results["seo"].get("canonical_tag") != "None":
        seo_score += 3
    else:
        action_items.append("Add a canonical tag to prevent duplicate content issues.")

    if audit_results["seo"].get("schema_detected") is True:
        seo_score += 3
    else:
        action_items.append("Implement JSON-LD structured data to qualify for rich search snippets.")

    if audit_results["seo"].get("word_count", 0) > 300:
        seo_score += 3
    else:
        action_items.append("Increase word count above 300 words to provide more topical depth for search engines.")

    category_scores["seo"] = round(seo_score, 2)
    total_score += seo_score
    # ------------------------------------------------------------- #

    # performance score 
    load_time = audit_results["performance"].get("load_time_seconds", 5.0)

    if load_time < 1.0:
        perf_score += 15
        strengths.append("Great server response time (under 1 second).")
    elif load_time <= 2.5:
        perf_score += 10
        action_items.append("Load time is acceptable but could be improved (between 1-2.5s).")
    else:
        action_items.append(f"Critical: Page load time is {round(load_time, 2)}s (over 2.5s). Optimize images and defer scripts.")

    category_scores["performance"] = perf_score
    total_score += perf_score
    # ------------------------------------------------------------- #

    # content score 
    content_score = 0

    if len(audit_results["socials"].get("open_graph", {})) > 0 or len(audit_results["socials"].get("twitter", {})) > 0:
        content_score += 5
    else:
        action_items.append("Add Open Graph or Twitter Card tags so your links look appealing when shared on social media.")

    social_links_found = 0
    for platform in ["linkedin", "facebook", "instagram", "tiktok"]:
        if platform in audit_results["socials"]:
            social_links_found += 1
    
    # Cap at 4 points maximum
    content_score += min(4, social_links_found)
    if social_links_found == 0:
        action_items.append("No social media profiles detected. Link your social accounts to build brand authority.")

    if audit_results["socials"].get("favicon") != "None":
        content_score += 3
    else:
        action_items.append("Add a favicon to improve brand recognition in browser tabs.")

    # Checking against current year (2026)
    if audit_results["content"].get("copyright_year") == "2026":
        content_score += 3
    else:
        action_items.append("Update your footer copyright year to 2026 to signal that the business is active.")

    category_scores["content_social"] = content_score
    total_score += content_score
    # ------------------------------------------------------------- #

    # accessibility score 
    total_inputs = audit_results["accessibility"].get("total_inputs", 0)
    missing_labels = audit_results["accessibility"].get("missing_labels", 0)

    if total_inputs == 0:
        access_score += 10
    else:
        access_score += ((total_inputs - missing_labels) / total_inputs) * 10
        if missing_labels > 0:
            action_items.append("Add explicit <label> tags or aria-label attributes to all form inputs for screen readers.")

    category_scores["accessibility"] = round(access_score, 2)
    total_score += access_score
    # ------------------------------------------------------------- #

    # security tracking score 
    for header in ["strict-transport-security", "x-frame-options", "x-content-type-options"]:
        if audit_results["security"].get(header) is True:
            sec_track_score += 1
            strengths.append("Strict Transport Security (HSTS) enabled.")
        else:
            action_items.append(f"Missing security header: {header}. Add this to protect your visitors.")

    if audit_results["tracking"].get("google_analytics") is True:
        sec_track_score += 1
        strengths.append("Google Analytics tracking active.")
    else:
        action_items.append("No Google Analytics detected. Install analytics to track your marketing efforts.")

    if audit_results["tracking"].get("meta_analytics") is True:
        sec_track_score += 1
    else:
        action_items.append("No Meta (Facebook) Pixel detected. Consider adding one for retargeting campaigns.")

    category_scores["security_tracking"] = sec_track_score
    total_score += sec_track_score
    # ------------------------------------------------------------- #

    # final grade calculation 
    total_score = round(min(100.0, total_score), 2)
    
    if total_score >= 90:
        letter_grade = "A"
    elif total_score >= 80:
        letter_grade = "B"
    elif total_score >= 70:
        letter_grade = "C"
    elif total_score >= 60:
        letter_grade = "D"
    else:
        letter_grade = "F"

    # Assemble the final dictionary
    final_scorecard = {
        "total_score": total_score,
        "ai_readiness_grade": letter_grade,
        "category_scores": category_scores,
        "strengths": strengths,
        "action_items": action_items
    }

    return final_scorecard