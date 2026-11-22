#!/usr/bin/env python3
"""Process SDK example: annotate analysis summary with aggregate section stats."""
import json, sys
request=json.load(sys.stdin)
sections=request.get('sections', [])
json.dump({'sdkVersion':1, 'plugin':'section-stats', 'section_count':len(sections),
           'executable_sections':[s['name'] for s in sections if s.get('executable')]},sys.stdout)
print()
