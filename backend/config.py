import os
import ipaddress
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY is not set. Add it to your backend/.env file.")

SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "trvstpulse.vercel.app").split(",")

GEMINI_MODELS = ["gemini-2.0-flash-lite", "gemini-2.0-flash", "gemini-1.5-flash"]

MAX_URL_LENGTH = 2048
MAX_URLS_PER_REQUEST = 20
MAX_BULK_TEXT_LENGTH = 50_000
REQUEST_TIMEOUT_SECONDS = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "10"))
MAX_REDIRECTS = int(os.getenv("MAX_REDIRECTS", "5"))

DEFAULT_RATE_LIMIT = "60/minute"
CHECK_LINKS_RATE_LIMIT = "30/minute"
EXTRACT_LINKS_RATE_LIMIT = "20/minute"

BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("0.0.0.0/8"),
]

KNOWN_BRANDS = [
    "paypal", "google", "apple", "microsoft", "amazon", "facebook", "instagram",
    "twitter", "netflix", "steam", "discord", "roblox", "bank", "chase", "wellsfargo",
    "citibank", "hsbc", "barclays", "ebay", "shopify", "dropbox", "linkedin",
    "whatsapp", "telegram", "yahoo", "outlook", "office365",
]

BRAND_OFFICIAL_DOMAINS = {
    "google":     ["google.com", "google.com.hk", "google.co.uk", "google.com.ph",
                   "google.co.jp", "google.com.au", "google.de", "google.fr",
                   "google.co.in", "google.com.br", "google.ca", "google.co.id",
                   "youtube.com", "googlevideo.com", "googleusercontent.com",
                   "googleapis.com", "gstatic.com", "gmail.com", "google.com.sg",
                   "google.com.tw", "google.com.mx", "google.com.ar", "google.co.nz"],
    "paypal":     ["paypal.com"],
    "apple":      ["apple.com", "icloud.com"],
    "microsoft":  ["microsoft.com", "microsoft.com.hk", "live.com", "azure.com",
                   "microsoftonline.com", "office.com", "sharepoint.com"],
    "amazon":     ["amazon.com", "amazon.co.uk", "amazon.co.jp", "amazon.de",
                   "amazon.fr", "amazon.ca", "amazon.com.au", "aws.amazon.com",
                   "amazonwebservices.com"],
    "facebook":   ["facebook.com", "fb.com", "meta.com"],
    "instagram":  ["instagram.com"],
    "twitter":    ["twitter.com", "x.com"],
    "netflix":    ["netflix.com"],
    "steam":      ["steampowered.com", "steamcommunity.com"],
    "discord":    ["discord.com", "discord.gg"],
    "roblox":     ["roblox.com"],
    "chase":      ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "citibank":   ["citibank.com", "citi.com"],
    "hsbc":       ["hsbc.com", "hsbc.co.uk"],
    "barclays":   ["barclays.co.uk", "barclays.com"],
    "ebay":       ["ebay.com", "ebay.co.uk", "ebay.de"],
    "shopify":    ["shopify.com", "myshopify.com"],
    "dropbox":    ["dropbox.com"],
    "linkedin":   ["linkedin.com"],
    "whatsapp":   ["whatsapp.com", "whatsapp.net"],
    "telegram":   ["telegram.org", "t.me"],
    "yahoo":      ["yahoo.com", "yahoo.co.jp", "yahoo.co.uk"],
    "outlook":    ["outlook.com", "outlook.live.com"],
    "office365":  ["office.com", "office365.com"],
}

TRUSTED_DOMAINS: set[str] = {
    "google.com", "youtube.com", "gmail.com", "googlemail.com",
    "googlevideo.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "google.co.uk", "google.com.ph", "google.co.jp", "google.de", "google.fr",
    "google.ca", "google.com.au", "google.co.in", "google.com.br", "google.co.id",
    "google.com.sg", "google.com.tw", "google.com.mx", "google.com.ar",
    "microsoft.com", "live.com", "outlook.com", "hotmail.com", "office.com",
    "office365.com", "azure.com", "microsoftonline.com", "sharepoint.com",
    "onedrive.live.com", "skype.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp",
    "amazon.fr", "amazon.ca", "amazon.com.au", "aws.amazon.com",
    "facebook.com", "fb.com", "meta.com", "instagram.com",
    "twitter.com", "x.com", "reddit.com", "discord.com", "discord.gg",
    "linkedin.com", "whatsapp.com", "telegram.org", "t.me",
    "tiktok.com", "snapchat.com", "pinterest.com",
    "netflix.com", "spotify.com", "twitch.tv", "hulu.com",
    "disneyplus.com", "hbomax.com",
    "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
    "npmjs.com", "pypi.org", "docker.com", "cloudflare.com",
    "digitalocean.com", "heroku.com", "vercel.com", "netlify.com",
    "shopify.com", "myshopify.com", "stripe.com", "twilio.com",
    "sendgrid.com", "mailchimp.com", "hubspot.com", "salesforce.com",
    "shodan.io", "censys.io", "virustotal.com", "urlvoid.com",
    "haveibeenpwned.com", "abuse.ch", "hybrid-analysis.com",
    "any.run", "greynoise.io", "urlscan.io",
    "dropbox.com", "box.com", "wetransfer.com", "drive.google.com",
    "docs.google.com", "notion.so", "airtable.com", "trello.com",
    "slack.com", "zoom.us", "webex.com", "teams.microsoft.com",
    "paypal.com", "venmo.com", "stripe.com", "chase.com",
    "wellsfargo.com", "bankofamerica.com", "citibank.com", "citi.com",
    "hsbc.com", "barclays.com", "barclays.co.uk",
    "wikipedia.org", "britannica.com", "bbc.com", "bbc.co.uk",
    "cnn.com", "reuters.com", "apnews.com", "theguardian.com",
    "nytimes.com", "wsj.com", "forbes.com", "techcrunch.com",
    "wired.com", "arstechnica.com",
    "yahoo.com", "ebay.com", "etsy.com", "craigslist.org",
    "medium.com", "substack.com", "wordpress.com", "blogspot.com",
    "tumblr.com", "quora.com", "yelp.com", "tripadvisor.com",
    "booking.com", "airbnb.com", "uber.com", "lyft.com",
    "doordash.com", "grubhub.com", "instacart.com",
    "steampowered.com", "steamcommunity.com", "roblox.com",
    "epicgames.com", "ea.com", "blizzard.com", "battle.net",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".online", ".site", ".website", ".pw",
    ".cc", ".ws", ".nu", ".to", ".buzz",
    ".live", ".click", ".link", ".download", ".win", ".loan",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "lnkd.in",
}

PHISHING_PATTERNS: list[tuple[str, str, int]] = [
    (r"(paypa[l1]|pay-pal|paypai)[^.]*\.",                         "PayPal brand spoofing",      3),
    (r"(arnazon|amaz[o0]n-secure|amazon-update)[^.]*\.",           "Amazon brand spoofing",      3),
    (r"(g[o0]{2}gle|googIe|google-verify|google-support)[^.]*\.",  "Google brand spoofing",      3),
    (r"(micros[o0]ft|mircosoft|micro-soft)[^.]*\.",                "Microsoft brand spoofing",   3),
    (r"(app[l1]e-id|apple-support|icloud-verify)[^.]*\.",         "Apple brand spoofing",       3),
    (r"\d{2,4}(gb|tb|mb)-?free",          "Fake free-storage lure (e.g. 51gb-free)",  3),
    (r"free-?\d{2,4}(gb|tb|mb)",          "Fake free-storage lure (reversed)",        3),
    (r"labor.?day.{0,30}(free|gb|prize)",  "Fake holiday giveaway lure",               3),
    (r"(black.?friday|cyber.?monday|christmas|easter|holiday).{0,30}(free|gb|prize|gift|reward)", "Fake holiday giveaway lure", 3),
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",             "Direct IP address URL",                     3),
    (r"%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}",      "Heavy URL encoding (obfuscation)",          2),
    (r"[a-z0-9]+-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.",               "Highly hyphenated domain (4+ segments)",    2),
    (r"(free|gift|prize|winner|lucky|bonus|reward|claim).{0,30}(click|now|here|login)", "Reward/urgency language", 2),
    (r"^https?://[a-z]{2,5}\d{1,4}[a-z]{1,4}\.(top|xyz|online|site|click|live|win|loan)", "Random-looking domain on high-risk TLD", 2),
    (r"(coin|crypto|wallet|token|nft|defi|bitcoin|ethereum|binance)[a-z0-9]*\.(io|cash|top|xyz|online|site|finance|capital|exchange|market)", "Crypto-themed domain on high-risk TLD — common investment scam", 3),
    (r"(kringle|xmas|santa|holiday)[a-z0-9]*\.(cash|io|top|xyz|online)", "Suspicious seasonal/gift domain on high-risk TLD", 3),
    (r"(earn|profit|invest|income|revenue|payout|dividend)[a-z0-9-]*\.(cash|io|top|xyz|online|finance)", "Investment lure on high-risk TLD", 3),
    (r"/(registration_form|register_form|signup_form|login_form|verify_form)\.", "Credential harvesting form path detected", 3),
    (r"/(registration|signup|enroll|join|create.?account)[^/]*\.php", "Suspicious registration PHP page", 2),
    (r"(sbc|doge|shib|pepe|floki|luna|bnb|trx|usdt)[a-z0-9]*coin[a-z0-9]*\.", "Meme/altcoin scam domain pattern", 3),
    (r"(sbc|doge|shib|pepe|floki|luna|bnb|trx|usdt)[a-z0-9]*\.(io|cash|finance|exchange|market|capital)", "Altcoin-themed domain on financial TLD", 3),
]

BRAND_IN_DOMAIN_PATTERNS: list[tuple[str, str]] = [
    ("paypal",    r"paypal[^.]*\.(?!com$)"),           
    ("google",    r"google[^.]*\.(?!com|co\.|google)"),
    ("apple",     r"apple[^.]*\.(?!com$)"),
    ("microsoft", r"microsoft[^.]*\.(?!com$)"),
    ("amazon",    r"amazon[^.]*\.(?!com|co\.|amazon)"),
    ("facebook",  r"facebook[^.]*\.(?!com$)"),
    ("netflix",   r"netflix[^.]*\.(?!com$)"),
    ("instagram", r"instagram[^.]*\.(?!com$)"),
    ("discord",   r"discord[^.]*\.(?!com|gg$)"),
    ("steam",     r"steam[^.]*\.(?!powered\.com|community\.com)"),
    ("roblox",    r"roblox[^.]*\.(?!com$)"),
    ("chase",     r"chase[^.]*\.(?!com$)"),
    ("wellsfargo",r"wellsfargo[^.]*\.(?!com$)"),
    ("hsbc",      r"hsbc[^.]*\.(?!com|co\.uk$)"),
    ("linkedin",  r"linkedin[^.]*\.(?!com$)"),
    ("ebay",      r"ebay[^.]*\.(?!com|co\.uk|de$)"),
    ("yahoo",     r"yahoo[^.]*\.(?!com|co\.)"),
    ("outlook",   r"outlook[^.]*\.(?!com$)"),
    ("whatsapp",  r"whatsapp[^.]*\.(?!com|net$)"),
    ("telegram",  r"telegram[^.]*\.(?!org$)"),
    ("dropbox",   r"dropbox[^.]*\.(?!com$)"),
]

SEVERITY_WEIGHT = {1: 1, 2: 3, 3: 7}

SCORE_SUSPICIOUS = 4
SCORE_DANGEROUS = 10
