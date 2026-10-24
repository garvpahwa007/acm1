"""Static knowledge base: brands, TLDs, homoglyphs, BEC lexicon, India scam corpus.

Kept as plain data so a non-engineer can extend coverage without touching logic.
"""

# ---------------------------------------------------------------- brands ----
# Brands worth typosquatting. Mix of global + India-specific.
BRANDS = [
    # global tech
    "google", "gmail", "microsoft", "office365", "outlook", "apple", "icloud",
    "amazon", "aws", "facebook", "instagram", "whatsapp", "netflix", "adobe",
    "dropbox", "linkedin", "twitter", "paypal", "stripe", "coinbase", "binance",
    "metamask", "zoom", "slack", "github", "docusign", "salesforce", "oracle",
    # banking / finance (global)
    "hsbc", "citibank", "barclays", "chase", "wellsfargo", "standardchartered",
    "americanexpress", "mastercard", "visa", "swift",
    # India banking / payments
    "sbi", "onlinesbi", "hdfcbank", "hdfc", "icicibank", "icici", "axisbank",
    "axis", "kotak", "kotakbank", "yesbank", "idfcfirst", "pnb", "bankofbaroda",
    "canarabank", "unionbankofindia", "federalbank", "indusind", "paytm",
    "phonepe", "googlepay", "bhim", "upi", "npci", "razorpay", "payu", "billdesk",
    "cred", "zerodha", "groww", "upstox", "policybazaar", "lic", "epfindia",
    # India gov
    "incometax", "gst", "gstn", "uidai", "aadhaar", "digilocker", "passportindia",
    "irdai", "sebi", "rbi", "npci", "morth", "parivahan", "ntpc", "upsc", "ssc",
    "jee", "nta", "cbse", "irctc", "indianrailways", "indiapost", "bharatgas",
    # India utilities / telecom
    "airtel", "jio", "vi", "bsnl", "tatapower", "adani", "bescom", "msedcl",
    "uppcl", "torrentpower", "actfibernet", "hathway",
    # commerce / logistics
    "flipkart", "myntra", "meesho", "snapdeal", "ajio", "nykaa", "swiggy",
    "zomato", "bigbasket", "blinkit", "zepto", "dhl", "fedex", "ups", "aramex",
    "bluedart", "delhivery", "ekart", "indiamart", "olx", "quikr",
    # enterprise SaaS commonly spoofed
    "workday", "okta", "auth0", "atlassian", "jira", "servicenow", "sap",
    "concur", "expensify", "quickbooks", "intuit", "zoho", "freshworks",
]

# Words that make a hostname *claim* to be a brand without being one.
BRAND_HINTS_IN_SUBDOMAIN = BRANDS

# ------------------------------------------------- suspicious TLDs (abuse) -
# Ordered roughly by observed abuse volume. Not a verdict on their own.
RISKY_TLDS = {
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "click",
    "link", "rest", "mom", "icu", "cam", "sbs", "cyou", "shop", "live", "online",
    "site", "monster", "quest", "bar", "cfd", "best", "support", "help", "work",
    "fit", "surf", "lol", "autos", "beauty", "bond", "casa", "christmas", "dad",
    "download", "feedback", "gdn", "hair", "homes", "makeup", "security", "skin",
    "storage", "theater", "uno", "wtf", "pw", "cc", "su", "ws", "info", "biz",
}

# Free / throwaway hosting & tunnelling that abuse actors use heavily.
ABUSE_HOSTS = {
    "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "netlify.app",
    "vercel.app", "github.io", "gitlab.io", "glitch.me", "repl.co", "replit.app",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "loca.lt", "serveo.net",
    "000webhostapp.com", "weeblysite.com", "wixsite.com", "blogspot.com",
    "sharepoint.com", "onedrive.live.com", "docs.google.com", "forms.gle",
    "r2.dev", "s3.amazonaws.com", "blob.core.windows.net", "storage.googleapis.com",
}

# Brand-owned domains that must never be scored as lookalikes. Every real product
# needs this list; without it "amazonaws.com" reads as "amazon" + gibberish.
LEGIT_DOMAINS = {
    "amazonaws.com", "amazon.in", "amazon.co.uk", "googleapis.com", "googleusercontent.com",
    "gstatic.com", "google.co.in", "youtube.com", "youtu.be", "gmail.com", "withgoogle.com",
    "microsoftonline.com", "office.com", "office365.com", "live.com", "outlook.com",
    "sharepoint.com", "onedrive.com", "azure.com", "windows.net", "msftconnecttest.com",
    "apple.com", "icloud.com", "cdn-apple.com", "githubusercontent.com", "githubassets.com",
    "linkedin.com", "licdn.com", "fbcdn.net", "whatsapp.net", "instagram.com",
    "sbi.co.in", "onlinesbi.sbi", "sbicard.com", "hdfcbank.com", "hdfc.com", "icicibank.com",
    "icicidirect.com", "axisbank.com", "kotak.com", "kotakbank.com", "yesbank.in",
    "pnbindia.in", "bankofbaroda.in", "canarabank.com", "unionbankofindia.co.in",
    "federalbank.co.in", "indusind.com", "idfcfirstbank.com", "rbi.org.in", "npci.org.in",
    "paytm.com", "phonepe.com", "razorpay.com", "billdesk.com", "cred.club", "zerodha.com",
    "groww.in", "upstox.com", "policybazaar.com", "licindia.in", "epfindia.gov.in",
    "incometax.gov.in", "gst.gov.in", "uidai.gov.in", "digilocker.gov.in", "passportindia.gov.in",
    "irdai.gov.in", "sebi.gov.in", "parivahan.gov.in", "irctc.co.in", "indianrailways.gov.in",
    "indiapost.gov.in", "upsc.gov.in", "nta.ac.in", "cbse.gov.in", "morth.nic.in",
    "airtel.in", "jio.com", "myvi.in", "bsnl.co.in", "tatapower.com", "adani.com",
    "bescom.karnataka.gov.in", "mahadiscom.in", "uppcl.org", "torrentpower.com",
    "flipkart.com", "myntra.com", "meesho.com", "snapdeal.com", "ajio.com", "nykaa.com",
    "swiggy.com", "zomato.com", "bigbasket.com", "blinkit.com", "zepto.co",
    "dhl.com", "fedex.com", "ups.com", "aramex.com", "bluedart.com", "delhivery.com",
    "indiamart.com", "olx.in", "quikr.com", "workday.com", "okta.com", "atlassian.com",
    "servicenow.com", "sap.com", "concur.com", "expensify.com", "quickbooks.intuit.com",
    "zoho.com", "freshworks.com", "docusign.com", "salesforce.com", "zoom.us",
    "slack.com", "dropbox.com", "adobe.com", "netflix.com", "stripe.com", "paypal.com",
    "binance.com", "coinbase.com", "hsbc.com", "citibank.com", "barclays.co.uk",
    "chase.com", "wellsfargo.com", "sc.com", "americanexpress.com", "mastercard.com",
    "visa.com", "swift.com", "gdpr.eu", "w3.org", "cloudflare.com", "akamai.net",
}

# Abusable but legitimate platforms: worth a gentle note, never a verdict.
TRUSTED_HOSTING = {"sharepoint.com", "onedrive.live.com", "docs.google.com",
                   "forms.gle", "s3.amazonaws.com", "blob.core.windows.net",
                   "storage.googleapis.com", "github.io"}

SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "s.id", "rebrand.ly", "shorturl.at",
    "tiny.cc", "lnkd.in", "t.ly", "shorte.st", "adf.ly", "clck.ru", "wa.link",
    "wa.me", "rebrand.ly", "v.gd", "soo.gd", "chilp.it", "bl.ink", "short.io",
}

# Extensions that are executable/macro-bearing, or commonly used as droppers.
DANGEROUS_EXT = {
    "exe", "scr", "com", "pif", "bat", "cmd", "hta", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "ps1", "psm1", "msi", "msp", "cpl", "jar", "lnk", "iso", "img",
    "vhd", "vhdx", "dll", "reg", "ade", "adp", "cab", "chm", "apk", "app", "dmg",
    "xll", "doc", "docm", "xls", "xlsm", "ppt", "pptm", "rtf", "svg", "html",
    "htm", "xhtml", "iqy", "slk", "pub", "one", "url",
}
MACRO_EXT = {"docm", "xlsm", "pptm", "xlam", "dotm", "xltm", "potm"}

# Path/label words used to fake a credential or payment flow.
SENSITIVE_WORDS = {
    "login", "signin", "logon", "verify", "verification", "validate", "account",
    "secure", "security", "update", "confirm", "unlock", "suspend", "suspended",
    "billing", "payment", "pay", "refund", "invoice", "receipt", "kyc", "pan",
    "aadhaar", "otp", "pin", "password", "credential", "wallet", "recover",
    "reset", "support", "helpdesk", "webscr", "customer", "auth", "authorize",
    "session", "token", "activate", "reactivate", "dispute", "claim", "reward",
    "bonus", "winner", "lottery", "prize", "delivery", "courier", "customs",
    "tracking", "electricity", "disconnection", "bill", "recharge", "job",
    "salary", "hiring", "parttime", "task", "invest", "profit", "loan",
}

# Redirect / open-redirect parameters used to wrap a benign host around evil.
REDIRECT_PARAMS = {
    "url", "u", "redirect", "redirect_uri", "redirect_url", "next", "return",
    "returnurl", "return_url", "continue", "dest", "destination", "target",
    "goto", "out", "link", "r", "q", "to", "forward", "callback", "checkout_url",
}

# ------------------------------------------------------- homoglyphs ---------
# Confusable codepoints (Cyrillic / Greek / Latin-ext / math) -> ascii target.
HOMOGLYPHS = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h",
    "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "і": "i",
    "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ԛ": "q", "ԝ": "w",
    "ӏ": "l", "һ": "h", "п": "n", "г": "r", "ԍ": "g", "ү": "y",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
    "ρ": "p", "σ": "o", "τ": "t", "υ": "u", "χ": "x", "ω": "w", "ϲ": "c",
    "μ": "u", "η": "n",
    # Latin lookalikes / small caps
    "ı": "i", "ȷ": "j", "ɑ": "a", "ɩ": "i", "ʟ": "l", "ᴏ": "o", "ᴜ": "u",
    "ᴀ": "a", "ʀ": "r", "ᴇ": "e", "ᴍ": "m", "ᴠ": "v", "ᴡ": "w", "ᴢ": "z",
    # digits / punctuation tricks
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s",
    "а́": "a", "‐": "-", "–": "-", "—": "-", "。": ".", "｡": ".", "٫": ".",
}

# Keyboard-adjacency for realistic typo generation (QWERTY).
KEYBOARD_NEIGHBORS = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh",
    "u": "yij", "i": "uok", "o": "ipl", "p": "ol", "a": "qsz", "s": "awdx",
    "d": "sefc", "f": "drgv", "g": "fthb", "h": "gyjn", "j": "hukm",
    "k": "jil", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb",
    "b": "vghn", "n": "bhjm", "m": "njk",
}

# ------------------------------------------------ BEC / social lexicon -----
BEC_PATTERNS = {
    "payment_urgency": (
        r"\b(urgent|immediately|asap|right away|time[- ]sensitive|within \d+ hours|"
        r"today only|final reminder|last warning|expires? (today|soon|in \d+))\b",
        "Pressure to act now",
    ),
    "bank_change": (
        r"\b(new bank (account|details)|updated (bank|account|payment) details|"
        r"changed our (bank|account)|remittance (details|instructions)|"
        r"beneficiary (account )?(changed|updated)|wire (funds|transfer) to|"
        r"account number has (changed|been updated)|standing instruction)\b",
        "Bank / remittance detail change",
    ),
    "giftcard": (
        r"\b(gift ?card|itunes card|amazon card|google play card|steam card|"
        r"voucher code|scratch card)\b",
        "Gift-card payment request",
    ),
    "secrecy": (
        r"\b(confidential|between us|don'?t (tell|discuss|inform)|do not (tell|inform)|"
        r"keep this (quiet|private)|handle (this )?discreetly|off the record)\b",
        "Secrecy / isolation request",
    ),
    "authority": (
        r"\b(ceo|managing director|md sir|chairman|director|founder|hr head|"
        r"on behalf of (the )?(ceo|director)|board (meeting|approval))\b",
        "Authority / executive impersonation",
    ),
    "credential": (
        r"\b(verify your (account|identity|password)|re-?validate|re-?activate|"
        r"your account (will be|has been) (suspended|locked|closed|deactivated)|"
        r"unusual (sign[- ]?in|activity|login)|confirm your (password|credentials)|"
        r"update your (payment|billing|kyc)|one[- ]time password|otp)\b",
        "Credential / account-threat lure",
    ),
    "payroll_invoice": (
        r"\b(invoice (attached|enclosed)|purchase order|po number|remittance advice|"
        r"salary revision|payroll update|vendor registration|outstanding (amount|payment))\b",
        "Invoice / payroll workflow lure",
    ),
    "callback": (
        r"\b(call (me|us) (back )?(on|at)|reply with your (mobile|number)|"
        r"whatsapp me|text me on|reach me on \+?\d[\d \-]{7,})\b",
        "Requests an out-of-band callback",
    ),
    "generic_greeting": (
        r"^(dear (customer|user|client|sir/madam|valued customer)|hello user|"
        r"dear account holder)\b",
        "Generic, non-personalised greeting",
    ),
    "threat_legal": (
        r"\b(legal action|fir will be|police complaint|account will be frozen|"
        r"penalty of|non[- ]compliance|Income Tax (notice|department)|"
        r"GST notice|case has been registered)\b",
        "Legal / financial threat language",
    ),
    "too_good": (
        r"\b(congratulations|you have (won|been selected)|selected as (a )?winner|"
        r"lucky (winner|draw)|free (iphone|gift)|claim your (prize|reward)|"
        r"earn (₹|rs\.?|inr|\$)?\s?\d+[\d,]*\s*(per|/)\s*(day|hour|task|week))\b",
        "Reward / easy-money bait",
    ),
}

# ------------------------------------------- India-specific scam corpus ----
# India-first coverage. This is the moat: global tools score these poorly.
INDIA_RULES = [
    {
        "id": "upi_collect",
        "pattern": (r"\b(upi (collect )?request|approve the (upi )?request|"
                    r"accept (the )?(payment|collect) request|enter (your )?upi pin to "
                    r"(receive|accept)|money will be (credited|debited) after you approve)\b"),
        "title": "UPI collect-request trick",
        "evidence": "Asks the user to approve a UPI collect request 'to receive' money — approving actually debits them.",
        "weight": 30,
        "tip": "A UPI collect request only ever TAKES money. Nobody needs your PIN to send you money.",
    },
    {
        "id": "kyc_expiry",
        "pattern": (r"\b(kyc (is )?(expired|expiring|pending|incomplete|update required)|"
                    r"re-?kyc|pan[- ]aadhaar link(ing)? (pending|required)|"
                    r"account (will be )?(blocked|frozen) (due to|for) (non-?kyc|kyc))\b"),
        "title": "KYC-expiry pressure",
        "evidence": "Claims KYC/PAN-Aadhaar linkage is expiring to force a link click.",
        "weight": 26,
        "tip": "Banks never ask you to re-do KYC through a link in an SMS or email. Use the app or the branch.",
    },
    {
        "id": "electricity_disconnection",
        "pattern": (r"\b(electricity (connection )?(will be )?(disconnected|disconnection)|"
                    r"power (supply )?(disconnection|cut)|bill (is )?(not )?(updated|pending)|"
                    r"your (electricity|power) bill (is due|overdue).{0,40}(disconnect|cut)|"
                    r"(update|pay) (your )?(electricity|power) bill (tonight|today))\b"),
        "title": "Electricity-bill disconnection threat",
        "evidence": "Classic India SMS scam: threatens same-night power disconnection to force an immediate payment link.",
        "weight": 30,
        "tip": "Discoms don't text you a payment link at 9pm with a 2-hour deadline. Pay only on the official discom app/site.",
    },
    {
        "id": "digital_arrest",
        "pattern": (r"\b(digital arrest|arrest warrant|(cbi|customs|narcotics|trai|"
                    r"cyber ?crime|ed) (notice|officer|case)|fir (has been|will be) (registered|filed)|"
                    r"join (the )?(video|skype) (call|interrogation)|do not (disconnect|tell anyone))\b"),
        "title": "Digital-arrest / fake-officer scam",
        "evidence": "Impersonates police/CBI/customs with an arrest threat and demands a private video call — the hallmark of 'digital arrest' fraud.",
        "weight": 35,
        "tip": "No agency arrests anyone over a video call or asks for money to 'clear your name'. Hang up and dial 1930.",
    },
    {
        "id": "courier_customs",
        "pattern": (r"\b(parcel|consignment|shipment|courier).{0,60}(detained|held at customs|"
                    r"illegal (item|goods)|customs (duty|clearance|fee))|"
                    r"(customs (duty|clearance) (of|fee)|pay.{0,20}to release (the )?parcel)\b"),
        "title": "Fake courier / customs detention",
        "evidence": "Says a parcel is detained and demands a clearance fee — a pretext to take payment or card details.",
        "weight": 30,
        "tip": "Couriers never ask for customs duty over WhatsApp/SMS links. Track only on the official courier site.",
    },
    {
        "id": "parttime_task",
        "pattern": (r"\b(part[- ]?time (job|work)|work from home.{0,40}(earn|₹|rs)|"
                    r"(like|review|rate) (youtube )?videos?.{0,30}(earn|paid|₹)|"
                    r"telegram (group|channel).{0,40}(task|job|earn)|"
                    r"prepaid task|recharge task|daily (payout|settlement))\b"),
        "title": "Part-time 'task' job scam",
        "evidence": "Recruits for paid 'tasks' (liking videos, prepaid orders) with Telegram onboarding — the entry to a deposit-fraud pipeline.",
        "weight": 28,
        "tip": "Legit jobs never ask you to pay first or move to Telegram for 'tasks'. Any 'deposit to unlock payout' is theft.",
    },
    {
        "id": "loan_app",
        "pattern": (r"\b(instant loan|loan approved|pre-?approved (personal )?loan|"
                    r"loan (of )?(₹|rs\.?|inr)?\s?\d+.{0,30}(minutes|without (cibil|documents))|"
                    r"download (the )?loan app|contact list permission)\b"),
        "title": "Predatory instant-loan app bait",
        "evidence": "Pushes an 'instant, document-free' loan app — the pattern behind extortion via contact-list harvesting.",
        "weight": 24,
        "tip": "Install loan apps only from the official store and check the lender's RBI registration. No app needs your contact list.",
    },
    {
        "id": "govt_scheme",
        "pattern": (r"\b(pm ?kisan|pm ?awas|ayushman|free (laptop|ration|cycle) (scheme|yojana)|"
                    r"(subsidy|instalment) (of )?(₹|rs\.?)\s?\d+.{0,40}(register|apply|click)|"
                    r"(aadhaar|pan).{0,20}(update|link|verify).{0,30}(₹|rs\.?|fee)\b)"),
        "title": "Fake government-scheme payout",
        "evidence": "Uses a real-looking government scheme/instalment to collect an 'update fee' or Aadhaar/PAN details.",
        "weight": 26,
        "tip": "Scheme benefits never require a fee or OTP. Verify on the official .gov.in portal only.",
    },
    {
        "id": "irctc_train",
        "pattern": (r"\b(irctc|train (ticket|booking)).{0,60}(cancelled|waitlist|refund|"
                    r"tatkal.{0,20}(agent|confirm)|chart prepared)\b"),
        "title": "IRCTC refund / tatkal-agent lure",
        "evidence": "Uses train cancellation/refund or 'guaranteed tatkal' to harvest login or payment details.",
        "weight": 22,
        "tip": "Refunds land back on the original payment method. IRCTC has no 'tatkal agent' WhatsApp number.",
    },
    {
        "id": "upi_id_in_body",
        "pattern": r"\b[a-z0-9.\-_]{2,}@(okaxis|oksbi|okhdfcbank|okicici|ybl|paytm|ibl|axl|apl|upi)\b",
        "title": "Raw UPI ID payment request",
        "evidence": "Payment requested directly to a UPI VPA in the message body, bypassing any invoice or merchant trail.",
        "weight": 20,
        "tip": "Verify the VPA name in your UPI app before paying. A VPA is not proof of who you're paying.",
    },
    {
        "id": "shortlink_india_bank",
        "pattern": (r"\b(sbi|hdfc|icici|axis|kotak|pnb|paytm|phonepe|airtel|jio)\b.{0,40}"
                    r"(bit\.ly|tinyurl|rb\.gy|t\.co|shorturl|wa\.link|is\.gd|cutt\.ly)"),
        "title": "Bank brand + link shortener",
        "evidence": "Bank/telecom brand paired with a URL shortener — hides the real destination from the user.",
        "weight": 28,
        "tip": "Banks don't shorten their own links. Type the bank's address yourself instead of tapping.",
    },
]

# ------------------------------------------------------- teach-in-the-moment
# One-line transferable lesson per signal id. This is the training layer.
TEACH = {
    "ip_host": "Real companies use domain names. A raw IP address in a link is a red flag.",
    "userinfo": "Everything before '@' is decoration. Read the domain immediately AFTER the '@'.",
    "punycode": "Letters from other alphabets can look identical to Latin ones. Trust the letter-by-letter comparison, not your eyes.",
    "typosquat": "Compare the domain character by character, not by glance. One swapped letter is the whole attack.",
    "brand_in_subdomain": "The registrable domain is the part just before the TLD. Everything to its left is attacker-controlled.",
    "risky_tld": "Cheap, high-abuse endings (.zip, .top, .xyz) are used because they cost almost nothing to burn.",
    "shortener": "Short links hide their destination. Expand before you click.",
    "sensitive_path": "Words like 'verify' and 'kyc' in a URL are chosen to make you act before you think.",
    "dangerous_ext": "Look at the LAST extension. 'invoice.pdf.exe' is an executable, not a PDF.",
    "domain_age": "A 'trusted' brand domain registered days ago is not the brand.",
    "no_resolve": "A domain that doesn't resolve today may be armed tomorrow. Never trust a link you can't verify.",
    "password_form_external": "Check where a login form sends your password. If it's not the site's own domain, it's harvesting.",
    "spf_fail": "SPF failing means the mail did not come from an authorised server for that domain.",
    "dmarc_fail": "DMARC failure means the sender's own domain policy rejects this mail.",
    "replyto_mismatch": "Reply-To outranks From in practice. A mismatch means replies go to a different party.",
    "display_name_spoof": "The display name is free text. Only the address after '@' identifies the sender.",
    "bec_bank_change": "Bank details only change by verified callback to a number you already had — never from the email itself.",
    "bec_urgency": "Urgency is the attacker's tool to make verification feel optional.",
    "bec_secrecy": "Any request that must stay secret from colleagues is fraud.",
    "bec_giftcard": "No legitimate organisation takes payment in gift cards.",
    "first_contact": "First-ever contact asking for money or credentials is the strongest single warning sign.",
    "india_upi": "A UPI request only debits you. You never need a PIN to receive money.",
    "india_kyc": "KYC is never re-done through a link.",
    "india_digital_arrest": "No police agency interrogates over video call or demands money to close a case.",
    "attachment_macro": "Macro-enabled documents can run code the moment you 'Enable Content'.",
    "attachment_archive_protected": "Password-protected archives are used to slip past scanners. The password in the body is the giveaway.",
    "link_changed": "A link that was clean at delivery and changed later is a 'time-of-click' attack. Re-check before trusting.",
    "org_baseline_new_domain": "This domain has never mailed your organisation before. Novelty is a risk signal.",
}
