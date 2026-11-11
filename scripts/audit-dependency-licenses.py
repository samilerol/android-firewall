#!/usr/bin/env python3
"""Offline inventory of declared cached POM licenses; not a legal/CVE/source audit."""
import argparse
import csv
import os
from pathlib import Path
import xml.etree.ElementTree as XML

ROOT = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--cache', type=Path, default=Path(os.environ.get('GRADLE_USER_HOME', '/workspace/toolchains/gradle-home')) / 'caches/modules-2/files-2.1')
args = parser.parse_args()
cache = args.cache.resolve()


def licenses_for(coordinate, visited=frozenset()):
    if coordinate in visited or len(visited) >= 16:
        return set()
    group, name, version = coordinate
    location = (cache / group / name / version).resolve()
    if not location.is_relative_to(cache):
        raise ValueError('Invalid Maven cache coordinate')
    result = set()
    for pom in sorted(location.glob('*/*.pom')):
        root = XML.parse(pom).getroot()
        direct = root.findall('./{*}licenses/{*}license')
        for item in direct:
            label = item.findtext('{*}name') or ''
            url = item.findtext('{*}url') or ''
            if label or url:
                result.add((label, url, ':'.join(coordinate)))
        if not direct:
            parent = root.find('{*}parent')
            if parent is not None:
                values = tuple(parent.findtext('{*}' + key) for key in ('groupId', 'artifactId', 'version'))
                if all(values):
                    result.update(licenses_for(values, visited | {coordinate}))
    return result


scopes = {}
for lock in (ROOT / 'app/gradle.lockfile', ROOT / 'probe/gradle.lockfile'):
    for line in lock.read_text().splitlines():
        if line.startswith('#') or '=' not in line:
            continue
        component, configs = line.split('=', 1)
        if component.count(':') != 2:
            continue
        roles = scopes.setdefault(component, set())
        if lock.parent.name == 'app' and 'releaseRuntimeClasspath' in configs.split(','):
            roles.add('firewall-release-runtime')
        elif lock.parent.name == 'app' and 'debugRuntimeClasspath' in configs.split(','):
            roles.add('firewall-debug-only')
        elif 'AndroidTest' in configs:
            roles.add('device-test')
        elif 'UnitTest' in configs:
            roles.add('JVM-test')
        else:
            roles.add('build/metadata')

components = {tuple(node.get(key) for key in ('group', 'name', 'version'))
              for node in XML.parse(ROOT / 'gradle/verification-metadata.xml').iter()
              if node.tag.rsplit('}', 1)[-1] == 'component'}
rows = []
for coordinate in sorted(components):
    key = ':'.join(coordinate)
    evidence = licenses_for(coordinate)
    rows.append([key, '; '.join(sorted(scopes.get(key, {'build/plugin or metadata'}))),
                 '; '.join(sorted({item[0] for item in evidence})) or 'NOT DECLARED IN CACHED POM/PARENTS',
                 '; '.join(sorted({item[1] for item in evidence})),
                 '; '.join(sorted({item[2] for item in evidence}))])
output = ROOT / 'docs/DEPENDENCY_LICENSES.csv'
output.parent.mkdir(exist_ok=True)
with output.open('w', newline='') as stream:
    writer = csv.writer(stream)
    writer.writerow(['component', 'observed_scope', 'POM_declared_license', 'POM_license_URL', 'license_metadata_provider'])
    writer.writerows(rows)
runtime = [row for row in rows if 'firewall-release-runtime' in row[1]]
print(f'{len(rows)} component records; {len(runtime)} release-runtime graph records; '
      f'{sum(row[2].startswith("NOT DECLARED") for row in runtime)} missing runtime declarations')
