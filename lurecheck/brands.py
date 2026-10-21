"""Names worth imitating: the organisations phishing pretends to be.

Each brand has the domains it really uses, and the phrases that name it in a
sender's display name. A lookalike is only a lookalike *of* something, so this
list is what the lookalike check compares against. Your own organisation can be
added with ``--protect``, which is usually the comparison that matters most.

The list is short on purpose and cannot be complete. A brand's genuine domain
that is missing here (a regional site, a newly bought name) can be reported as
an imitation of that brand. The finding says which brand and which domain, so
that is easy to see.

Display-name phrases avoid ordinary words: "Apple Support", not "Apple", since
"Apple Hill Farm" is not pretending to be anyone.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Tuple

from lurecheck.domains import registrable
from lurecheck.urls import host_kind


@dataclass(frozen=True)
class Brand:
    name: str
    domains: Tuple[str, ...]  # registrable domains the brand really uses
    phrases: Tuple[str, ...] = ()  # how a display name would name it, lower-case


def _brand(name: str, domains: str, phrases: str = "") -> Brand:
    return Brand(name=name, domains=tuple(domains.split()), phrases=tuple(p.strip().lower() for p in phrases.split("|") if p.strip()))


BUILT_IN: Tuple[Brand, ...] = (
    _brand("PayPal", "paypal.com paypal.me paypal-communication.com paypalobjects.com", "paypal"),
    _brand("Microsoft", "microsoft.com microsoftonline.com office.com office365.com live.com outlook.com hotmail.com "
           "sharepoint.com onedrive.com azure.com msn.com windows.com bing.com skype.com xbox.com microsoft365.com",
           "microsoft|office 365|microsoft 365|outlook team|onedrive|sharepoint"),
    _brand("Apple", "apple.com icloud.com me.com mac.com apple.co", "apple support|apple id|icloud|itunes|app store"),
    _brand("Amazon", "amazon.com amazon.co.uk amazon.com.au amazon.de amazon.fr amazon.ca amazon.in amazon.co.jp "
           "amazon.it amazon.es amazonses.com primevideo.com", "amazon.com|amazon prime|amazon web services|aws"),
    _brand("Google", "google.com gmail.com googlemail.com youtube.com google.com.au google.co.uk withgoogle.com",
           "google|gmail|youtube"),
    _brand("Netflix", "netflix.com netflix.net", "netflix"),
    _brand("Meta", "facebook.com facebookmail.com instagram.com whatsapp.com meta.com fb.com", "facebook|instagram|whatsapp|meta for business"),
    _brand("LinkedIn", "linkedin.com licdn.com", "linkedin"),
    _brand("DocuSign", "docusign.com docusign.net", "docusign"),
    _brand("Dropbox", "dropbox.com dropboxmail.com", "dropbox"),
    _brand("Adobe", "adobe.com adobesign.com", "adobe"),
    _brand("Coinbase", "coinbase.com", "coinbase"),
    _brand("Binance", "binance.com", "binance"),
    _brand("Wells Fargo", "wellsfargo.com", "wells fargo"),
    _brand("Bank of America", "bankofamerica.com bofa.com", "bank of america"),
    _brand("Chase", "chase.com jpmorganchase.com", "chase bank|chase online|jpmorgan chase"),
    _brand("American Express", "americanexpress.com aexp.com", "american express|amex"),
    _brand("DHL", "dhl.com dhl.de dhl.com.au", "dhl"),
    _brand("FedEx", "fedex.com", "fedex"),
    _brand("UPS", "ups.com", "ups"),
    _brand("USPS", "usps.com", "usps|postal service"),
    _brand("Australia Post", "auspost.com.au", "australia post|auspost"),
    _brand("Australian Taxation Office", "ato.gov.au", "australian taxation office|ato"),
    _brand("myGov", "my.gov.au mygov.au servicesaustralia.gov.au", "mygov|services australia|centrelink|medicare"),
    _brand("Commonwealth Bank", "commbank.com.au", "commonwealth bank|commbank|netbank"),
    _brand("Westpac", "westpac.com.au", "westpac"),
    _brand("ANZ", "anz.com anz.com.au", "anz"),
    _brand("NAB", "nab.com.au", "nab|national australia bank"),
    _brand("HMRC", "hmrc.gov.uk gov.uk", "hmrc"),
    _brand("IRS", "irs.gov", "internal revenue service|irs"),
    _brand("Steam", "steampowered.com steamcommunity.com", "steam support|steam community"),
    _brand("Spotify", "spotify.com", "spotify"),
    _brand("eBay", "ebay.com ebay.co.uk ebay.com.au", "ebay"),
    _brand("Zoom", "zoom.us zoom.com", "zoom video"),
    _brand("Okta", "okta.com", "okta"),
    _brand("Salesforce", "salesforce.com force.com", "salesforce"),
    _brand("WeTransfer", "wetransfer.com", "wetransfer"),
    _brand("GitHub", "github.com", "github"),
)  # fmt: skip


def protected(domains: Iterable[str]) -> List[Brand]:
    """Brands for domains the user named with --protect. The name is the domain's first label, spaced out."""
    brands = []
    for domain in domains:
        owner = registrable(domain)
        if owner and host_kind(owner) == "name":  # a numeric address is not a brand
            label = owner.split(".")[0]
            brands.append(Brand(name=owner, domains=(owner,), phrases=(label.replace("-", " "),) if len(label) >= 4 else ()))
    return brands
