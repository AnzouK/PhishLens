"""
URL agent: a Random Forest over the URL features of an email (domain
properties, brand look-alikes, path and query patterns, shorteners, ports,
HTTPS). Trained in the PhishingDetector repository by Udodinachukwu David
Nwoke; this module only runs inference (rf_agent.py).
"""

from rf_agent import RandomForestAgent


class URLAgent(RandomForestAgent):
    """Scores FeatureExtractor.extract_url_features() output."""
