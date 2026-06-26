"""
Bulk Harvest — Scale FORGE to the moon
"""

import json
from pathlib import Path
from core.knowledge_harvester import KnowledgeHarvester

def main():
    harvester = KnowledgeHarvester()
    print("🚀 Starting Bulk Harvest...")
    
    triplets = harvester.harvest_standard_library()
    
    output_path = Path("harvested_stdlib_triplets.json")
    with open(output_path, 'w') as f:
        json.dump(triplets, f, indent=4)
        
    print(f"\n✅ Harvest Complete!")
    print(f"📊 Total Triplets: {len(triplets)}")
    print(f"💾 Saved to {output_path}")

if __name__ == "__main__":
    main()
