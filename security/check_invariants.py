#!/usr/bin/env python3
"""Repository-specific gates complement scanners that do not understand QML."""
import ast
from pathlib import Path
import re
import subprocess
ROOT=Path(__file__).resolve().parents[1]
errors=[]
# Omarchy plugin validation rejects symlinks anywhere inside a plugin
# directory, and this whole repository is the plugin folder `omarchy plugin
# add <git-url>` clones. A committed symlink (bin/omapager-run-icon used to
# alias bin/omapager-run-helper this way) installs cleanly by hand but fails
# that validator, blocking the documented git-install path. Check what git
# actually tracks, since that is what a fresh clone ships.
tracked=subprocess.run(['git','-C',str(ROOT),'ls-files','-s'],capture_output=True,text=True,check=True).stdout
for line in tracked.splitlines():
    mode,rel=line.split(None,1)[0],line.split('\t',1)[1]
    if mode=='120000':errors.append(rel+': tracked symlink (Omarchy plugin validation rejects symlinks inside plugin directories)')
for path in [*ROOT.glob('*.qml'),*ROOT.glob('*.js'),*(ROOT/'bin').glob('*')]:
    if not path.is_file() or path.is_symlink():continue
    text=path.read_text()
    rel=str(path.relative_to(ROOT))
    if 'Qt.openUrlExternally' in text and rel!='Security.js':errors.append(rel+': URL broker bypass')
    if re.search(r'''["'](?:ba)?sh["']\s*,\s*["']-c["']''',text):errors.append(rel+': command shell')
    if re.search(r'urllib\.request|OPENER\.open|urlopen\(',text):errors.append(rel+': unpinned network client')
    if 'console.log(' in text:errors.append(rel+': notification logging')
    # One transport. A second http.client would be a second place to forget the
    # address validation, so the only raw connections allowed are in the
    # transport itself and in the model helper, which must keep its literal
    # loopback guard: a hostname there would be resolved instead of compared.
    if 'http.client.HTTPConnection(' in text and rel not in ('bin/omapager_http.py','bin/omapager-llm'):
        errors.append(rel+': second HTTP client')
    if rel=='bin/omapager-llm' and 'ipaddress.ip_address' not in text:
        errors.append(rel+': loopback check removed from the model helper')
    if rel=='bin/omapager-llm' and 'is_loopback' not in text:
        errors.append(rel+': loopback check no longer requires a loopback address')
    if path.suffix=='.py' or text.startswith('#!/usr/bin/env python3') or text.startswith('#!/usr/bin/python3'):
        tree=ast.parse(text)
        for n in ast.walk(tree):
            if isinstance(n,ast.Call):
                name=ast.unparse(n.func)
                if name=='os.system' or any(k.arg=='shell' and isinstance(k.value,ast.Constant) and k.value.value for k in n.keywords):errors.append(rel+': shell execution')
                if rel=='bin/omapager_http.py' and name.endswith(('.read','.read1')) and not n.args:errors.append(rel+': unbounded network read')
for path in (ROOT/'.github/workflows').glob('*.yml'):
    text=path.read_text()
    for use in re.findall(r'uses:\s*([^\s#]+)',text):
        if not re.search(r'@[a-f0-9]{40}$',use):errors.append(str(path)+': unpinned action '+use)
    if 'pull_request_target' in text or 'secrets.' in text:errors.append(str(path)+': privileged PR context')
service=(ROOT/'Service.qml').read_text()
for helper in ('store','icon','kdeconnect'):
    if f'"bin/omapager-{helper}"' in service:errors.append('raw helper launch: '+helper)
if 'property bool allowDefaultActionOnCardClick: false' not in service:errors.append('default actions no longer opt-in')
if errors:raise SystemExit('\n'.join(errors))
print('static security invariants: passed')
