#!/usr/bin/env python3
"""Offline OSV Maven version matching. Matches are candidates, not reachability findings."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import xml.etree.ElementTree as XML
import zipfile

ROOT = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--database', type=Path, required=True)
parser.add_argument('--maven-jar', type=Path, required=True)
parser.add_argument('--java-home', type=Path, required=True)
parser.add_argument('--snapshot-date', required=True, help='Recorded upstream Last-Modified UTC timestamp')
args = parser.parse_args()
jar_sha = hashlib.sha256(args.maven_jar.read_bytes()).hexdigest()
assert jar_sha == '30f015d1c1a393e19c18cd4f43532089c36d4ca328608ce3dda78b74d3d31515', 'Unexpected Maven 3.9.9 comparator artifact'
components = {(node.get('group') + ':' + node.get('name'), node.get('version'))
              for node in XML.parse(ROOT / 'gradle/verification-metadata.xml').iter()
              if node.tag.rsplit('}', 1)[-1] == 'component'}
by_package = {}
for package, version in components:
    by_package.setdefault(package, set()).add(version)
roles = {row['component']: row['observed_scope'] for row in csv.DictReader((ROOT / 'docs/DEPENDENCY_LICENSES.csv').open())}
records = []
pairs = set()
record_count = 0
with zipfile.ZipFile(args.database) as archive:
    for entry in archive.infolist():
        if not entry.filename.endswith('.json'):
            continue
        assert entry.file_size <= 16 * 1024 * 1024, 'Oversized advisory record'
        data = json.loads(archive.read(entry))
        record_count += 1
        if data.get('withdrawn'):
            continue
        for affected in data.get('affected', []):
            package = affected.get('package', {})
            if package.get('ecosystem') != 'Maven' or package.get('name') not in by_package:
                continue
            name = package['name']
            records.append((data, affected, name))
            for version in by_package[name]:
                for version_range in affected.get('ranges', []):
                    if version_range['type'] == 'ECOSYSTEM':
                        for event in version_range['events']:
                            for key, value in event.items():
                                if key != 'introduced' or value != '0':
                                    pairs.add((version, value))
for pair in pairs:
    assert all(len(value) <= 256 and re.fullmatch(r'[0-9A-Za-z_.+~\-]+', value) for value in pair), 'Unsupported Maven version form'
pairs = sorted(pairs)
source = '''import java.io.*;
import org.apache.maven.artifact.versioning.ComparableVersion;
public class MavenVersionBatch {
 public static void main(String[] args) throws Exception {
  BufferedReader input = new BufferedReader(new InputStreamReader(System.in, "UTF-8"));
  for(String line; (line=input.readLine())!=null;) {
   String[] pair=line.split("\\t",-1);
   if(pair.length!=2) throw new IllegalArgumentException("Invalid pair");
   System.out.println(new ComparableVersion(pair[0]).compareTo(new ComparableVersion(pair[1])));
  }
 }
}'''
with tempfile.TemporaryDirectory(prefix='firewall-maven-audit-') as temporary:
    file = Path(temporary) / 'MavenVersionBatch.java'
    file.write_text(source)
    subprocess.run([str(args.java_home / 'bin/javac'), '-cp', str(args.maven_jar), str(file)], check=True, capture_output=True)
    result = subprocess.run([str(args.java_home / 'bin/java'), '-cp', temporary + os.pathsep + str(args.maven_jar), 'MavenVersionBatch'],
                            input=''.join(a + '\t' + b + '\n' for a, b in pairs), text=True, capture_output=True, check=True)
values = [int(line) for line in result.stdout.splitlines()]
assert len(values) == len(pairs)
comparisons = dict(zip(pairs, values))


def event_match(version, events):
    lower = None
    for event in events:
        if 'introduced' in event:
            assert lower is None, 'Invalid interval ordering'
            lower = event['introduced']
        else:
            key = next(iter(event))
            assert key in {'fixed', 'last_affected', 'limit'} and lower is not None, 'Unsupported interval event'
            above = lower == '0' or comparisons[(version, lower)] >= 0
            upper = comparisons[(version, event[key])]
            if above and (upper <= 0 if key == 'last_affected' else upper < 0):
                return True
            lower = None
    return lower is not None and (lower == '0' or comparisons[(version, lower)] >= 0)


matches = {}
unsupported = []
for data, affected, package in records:
    for version in sorted(by_package[package]):
        match = version in affected.get('versions', [])
        for version_range in affected.get('ranges', []):
            if version_range['type'] != 'ECOSYSTEM':
                unsupported.append({'id': data['id'], 'package': package, 'version': version, 'range_type': version_range['type']})
                continue
            match |= event_match(version, version_range['events'])
        if match:
            key = (data['id'], package, version)
            matches[key] = {'id': data['id'], 'aliases': data.get('aliases', []), 'package': package, 'version': version,
                            'observed_scope': roles.get(package + ':' + version, 'build/plugin or metadata'),
                            'upstream_severity': data.get('database_specific', {}).get('severity'),
                            'summary': data.get('summary', ''), 'url': 'https://osv.dev/vulnerability/' + data['id']}
findings = [matches[key] for key in sorted(matches)]
runtime = [finding for finding in findings if 'firewall-release-runtime' in finding['observed_scope']]
report = {'source': 'https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip',
          'snapshot_sha256': hashlib.sha256(args.database.read_bytes()).hexdigest(),
          'snapshot_last_modified_utc': args.snapshot_date,
          'maven_comparator_version': '3.9.9', 'maven_comparator_sha256': jar_sha,
          'advisory_record_count': record_count, 'component_record_count': len(components),
          'version_match_count': len(findings), 'release_runtime_match_count': len(runtime),
          'unsupported_ranges': unsupported, 'matches': findings,
          'limits': 'Maven metadata/version matching only. Native/Android/JDK vulnerabilities and reachability are not established. Aliases can duplicate upstream vulnerabilities.'}
output = ROOT / 'docs/DEPENDENCY_ADVISORIES.json'
output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
print(f'{record_count} records, {len(components)} component records, {len(findings)} version candidates; '
      f'{len(runtime)} release-runtime candidates; {len(unsupported)} unsupported ranges')
