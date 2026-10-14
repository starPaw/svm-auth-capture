"""Shared fail-closed release eligibility; no deployment or economic side effects."""
import datetime
import re

REPOSITORY = 'starPaw/capture402'
REQUIRED_JOBS = {'SBF build and component checks', 'x402 integration, typecheck and wallet build'}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def verify(sha, api):
    require(bool(re.fullmatch('[0-9a-f]{40}', sha)), 'exact lowercase SHA required')
    root = 'repos/' + REPOSITORY
    main = lambda: api(root + '/git/ref/heads/main')['object']['sha']
    require(main() == sha, 'revision is not current main')
    runs = api(root + '/actions/workflows/components.yml/runs?event=push&head_sha=' + sha + '&per_page=1')['workflow_runs']
    require(len(runs) == 1 and runs[0]['head_sha'] == sha and runs[0]['event'] == 'push'
            and runs[0]['status'] == 'completed' and runs[0]['conclusion'] == 'success',
            'current-main push CI has not succeeded')
    run = runs[0]
    jobs = api(root + f"/actions/runs/{run['id']}/jobs?per_page=100")
    require(jobs['total_count'] == len(jobs['jobs']), 'incomplete CI jobs response')
    for name in REQUIRED_JOBS:
        matches = [j for j in jobs['jobs'] if j['name'] == name]
        require(len(matches) == 1 and matches[0]['status'] == 'completed'
                and matches[0]['conclusion'] == 'success', 'required CI job failed, skipped or ambiguous')
    def pages(route):
        output = []
        for page in range(1, 101):
            batch = api(root + route + f'?per_page=100&page={page}')
            require(isinstance(batch, list), 'invalid paginated response')
            output.extend(batch)
            if len(batch) < 100:
                return output
        raise RuntimeError('release metadata exceeds pagination bound')
    pulls = pages('/commits/' + sha + '/pulls')
    matched = [p for p in pulls if p.get('merged_at') and p.get('merge_commit_sha') == sha
               and p['base']['ref'] == 'main']
    require(len(matched) == 1, 'main revision lacks an unambiguous merged PR')
    pull = matched[0]
    latest = {}
    for review in pages(f"/pulls/{pull['number']}/reviews"):
        user = review['user']
        if user.get('type') == 'User' and user['login'] != 'starPaw' and review['state'] in ('APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'):
            latest[user['login']] = review
    accepted = [r for r in latest.values() if r['state'] == 'APPROVED' and r['commit_id'] == pull['head']['sha']]
    require(bool(accepted), 'eligible exact-head reviewer approval missing')
    tree = api(root + '/git/commits/' + sha)['tree']['sha']
    require(tree == api(root + '/git/commits/' + pull['head']['sha'])['tree']['sha'],
            'merged tree differs from reviewed head')
    require(main() == sha, 'main changed during release verification')
    return {'sha': sha, 'tree': tree, 'pull': pull['number'], 'reviewedHead': pull['head']['sha'],
            'reviewer': accepted[0]['user']['login'], 'reviewId': accepted[0]['id'],
            'ciRun': run['id'], 'checkedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat()}


def verify_dev(sha, api):
    """Dev heads require exact tested/reviewed source; main retains its existing gate."""
    require(bool(re.fullmatch('[0-9a-f]{40}', sha)), 'exact lowercase SHA required')
    root = 'repos/' + REPOSITORY
    main = api(root + '/git/ref/heads/main')['object']['sha']
    if sha == main:
        return {**verify(sha, api), 'branch': 'main'}

    def pages(route):
        output = []
        for page in range(1, 101):
            batch = api(root + route + f'?per_page=100&page={page}')
            require(isinstance(batch, list), 'invalid paginated response')
            output.extend(batch)
            if len(batch) < 100:
                return output
        raise RuntimeError('dev metadata exceeds pagination bound')

    pulls = pages('/commits/' + sha + '/pulls')
    matched = [p for p in pulls if p.get('state') == 'open' and p['head']['sha'] == sha
               and p['base']['ref'] == 'main'
               and p['head'].get('repo', {}).get('full_name') == REPOSITORY
               and p['base'].get('repo', {}).get('full_name') == REPOSITORY]
    require(len(matched) == 1, 'dev revision requires one same-repository open main PR')
    pull = api(root + f"/pulls/{matched[0]['number']}")
    require(pull['state'] == 'open' and pull['head']['sha'] == sha
            and pull['base']['sha'] == main, 'dev PR or base changed')
    branch = pull['head']['ref']
    require(bool(re.fullmatch(r'[A-Za-z0-9_./-]+', branch)) and not branch.startswith('-')
            and '..' not in branch, 'invalid development branch')
    from urllib.parse import quote
    ref = root + '/git/ref/heads/' + quote(branch, safe='')
    require(api(ref)['object']['sha'] == sha, 'development branch moved')
    comparison = api(root + '/compare/' + main + '...' + sha)
    require(comparison['status'] in ('ahead', 'identical') and comparison['behind_by'] == 0,
            'dev branch must contain current main')
    runs = api(root + '/actions/workflows/components.yml/runs?event=pull_request&head_sha=' + sha + '&per_page=1')['workflow_runs']
    require(len(runs) == 1, 'dev CI missing')
    run = runs[0]
    require(run['head_sha'] == sha and run['event'] == 'pull_request'
            and run['status'] == 'completed' and run['conclusion'] == 'success'
            and any(p['number'] == pull['number'] for p in run['pull_requests']), 'dev CI has not succeeded for this PR head')
    jobs = api(root + f"/actions/runs/{run['id']}/jobs?per_page=100")
    require(jobs['total_count'] == len(jobs['jobs']), 'incomplete CI jobs response')
    for name in REQUIRED_JOBS:
        found = [j for j in jobs['jobs'] if j['name'] == name]
        require(len(found) == 1 and found[0]['status'] == 'completed'
                and found[0]['conclusion'] == 'success', 'required dev CI job failed, skipped or ambiguous')
    latest = {}
    for review in pages(f"/pulls/{pull['number']}/reviews"):
        user = review['user']
        if user.get('type') == 'User' and user['login'] != 'starPaw' and review['state'] in ('APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'):
            latest[user['login']] = review
    approved = [r for r in latest.values() if r['state'] == 'APPROVED' and r['commit_id'] == sha]
    require(approved and not any(r['state'] == 'CHANGES_REQUESTED' for r in latest.values()), 'eligible exact-head dev approval missing or changes requested')
    tree = api(root + '/git/commits/' + sha)['tree']['sha']
    require(pull.get('mergeable') is True and pull.get('merge_commit_sha')
            and api(root + '/git/commits/' + pull['merge_commit_sha'])['tree']['sha'] == tree,
            'tested PR merge tree differs from dev head')
    require(api(ref)['object']['sha'] == sha and api(root + '/git/ref/heads/main')['object']['sha'] == main,
            'dev source moved during verification')
    return {'sha': sha, 'tree': tree, 'branch': branch, 'pull': pull['number'],
            'reviewedHead': sha, 'reviewer': approved[0]['user']['login'], 'reviewId': approved[0]['id'],
            'ciRun': run['id'], 'main': main,
            'checkedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
