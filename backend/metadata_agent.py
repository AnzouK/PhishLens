"""
Metadata agent: a Random Forest over the header features of an email
(sender and reply-to domains, authentication results, routing). Trained
in the PhishingDetector repository by Udodinachukwu David Nwoke; this
module only runs inference (rf_agent.py).
"""
from rf_agent import RandomForestAgent


class MetadataAgent(RandomForestAgent):
    """Scores FeatureExtractor.extract_metadata_features() output."""
