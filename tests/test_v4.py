"""
Verification Test for V4: Autonomous Web Learner
"""

import sys
from pathlib import Path
from core.knowledge_engine import KnowledgeEngine
from core.web_harvester import WebHarvester

def test_v4_extraction():
    print("🧪 Testing V4: Web Harvesting & NL Extraction...")
    
    # Mock knowledge engine
    ke = KnowledgeEngine(Path("knowledge"))
    harvester = WebHarvester(ke)
    
    # Mock technical text
    mock_html = """
    <html>
        <body>
            <h1>FORGE Guide</h1>
            <p>Use the <b>requests</b> library to <b>download web pages</b>.</p>
            <p>The <b>BeautifulSoup</b> parser <b>provides extraction</b> of HTML tags.</p>
            <p><b>sqlite3</b> is used for <b>storing results</b> in a local file.</p>
        </body>
    </html>
    """
    
    print("Running extraction on mock documentation...")
    triplets = harvester.extract_triplets(mock_html, "mock_source")
    
    for t in triplets:
        print(f"  Extracted: {t['trigger']} -> {t['mechanism']} -> {t['outcome']} (Conf: {t['confidence']})")
    
    # Assertions
    triggers = {t['trigger'].lower() for t in triplets}
    assert 'requests' in triggers, "Failed to extract requests"
    assert 'beautifulsoup' in triggers, "Failed to extract BeautifulSoup"
    assert 'sqlite3' in triggers, "Failed to extract sqlite3"
    
    print("\n✅ V4 Extraction Logic PASSED.")

if __name__ == "__main__":
    try:
        test_v4_extraction()
    except Exception as e:
        print(f"\n❌ FAIL: {e}")
        sys.exit(1)
