"""Real wheel/venv/fresh-HOME staging, with a synthetic candidate archive.

Never commits or activates services. Resulting provenance explicitly prevents
activation; temporary fixture releases are deleted on exit. Network is used only
for build/service dependencies. Run with the development .venv Python.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
from unittest.mock import patch

from universal_agent_middleware import installer
from universal_agent_middleware.runtime import sha256, load_runtime, validate_release


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as tar:
        paths = [source / 'pyproject.toml', source / 'README.md', source / 'LICENSE']
        paths += sorted((source / 'src/universal_agent_middleware').rglob('*.py'))
        paths += [source / 'src/universal_agent_middleware/tool_contract.json']
        paths += [p for p in sorted((source / 'tools/system-service').rglob('*')) if p.is_file()]
        for path in paths:
            if '__pycache__' not in path.parts:
                tar.add(path, arcname=str(path.relative_to(source)))
    data = archive.getvalue()
    real_run = subprocess.run
    def fixture_archive(cmd, **kwargs):
        if cmd[0] == 'git' and 'archive' in cmd:
            return subprocess.CompletedProcess(cmd, 0, data)
        return real_run(cmd, **kwargs)
    identity = {'source_commit':'f'*40,'source_tree':'e'*40,'source_dirty':False,
                'source_kind':'SYNTHETIC_UNCOMMITTED_TEST_FIXTURE'}
    with tempfile.TemporaryDirectory(prefix='uam-fresh-home-rehearsal-') as td:
        root = Path(td)
        home = root / 'Fresh Home & Spaces'
        home.mkdir()
        workspace = root / 'workspace'; workspace.mkdir(); (workspace/'README.md').write_text('canary\n')
        registry = root/'workspaces.json'; registry.write_text(json.dumps({
            'registry_version':'uam-workspace-registry-v1','workspaces':[{
                'workspace_id':'fixture','root':str(workspace),'kind':'git-repository','capabilities':['filesystem.read']}]}))
        scopes = root/'root_scopes.json'; scopes.write_text(json.dumps({'schema_version':'root-scope-registry-v1','scopes':[]}))
        canaries = root/'canaries.json'; canaries.write_text(json.dumps([{'workspace_id':'fixture','path':'README.md'}]))
        config = home/'.config/tunnel-client/uam-chatgpt-read.yaml'; config.parent.mkdir(parents=True)
        config.write_text(json.dumps({'mcp':{'commands':[{'command':'fixture-placeholder'}]}}))
        with patch.object(installer,'clean_source',return_value=identity), patch.object(installer.subprocess,'run',side_effect=fixture_archive):
            plan = installer.stage(source,home=home,state_root=home/'private/state',registry=registry,
                scopes=scopes,canaries=canaries,tunnel_config=config,tunnel_client=Path('/bin/echo'))
        runtime = load_runtime(plan)
        release = Path(runtime['current_release'])
        manifest = json.loads((release/'RELEASE_MANIFEST.json').read_text())
        blocked = False
        try: validate_release(runtime,executing=False,require_current=False)
        except ValueError as exc: blocked = str(exc) == 'invalid release provenance'
        assert blocked, 'synthetic candidate must never be activatable'
        assert not (Path(runtime['uam_home'])/'current').exists()
        assert not (home/'.local/share/openjay/uam').exists()
        assert not (home/'Library/LaunchAgents').exists()
        report = {'scope':'synthetic archive; real wheel build and service-dependency install; no launchctl',
            'state':'STAGED_NOT_ACTIVE','candidate_archive_sha256':hashlib.sha256(data).hexdigest(),
            'release_manifest_sha256':sha256(release/'RELEASE_MANIFEST.json'),
            'wheel_sha256':manifest['wheel_sha256'],'installed_files':len(manifest['files']),
            'tool_contract_count':len(manifest['tool_contract']),'fresh_home_has_spaces':True,
            'no_alias_required':True,'no_service_activation':True,'synthetic_provenance_rejected':blocked,
            'clean_source_provenance':'NOT_PROVEN_BY_THIS_FIXTURE','fixture_removed_on_exit':True}
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report,indent=2))


if __name__ == '__main__':
    main()
