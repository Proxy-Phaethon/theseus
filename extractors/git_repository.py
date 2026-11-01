from pathlib import Path
from datetime import datetime, timezone
import hashlib

from git import Repo, InvalidGitRepositoryError, NoSuchPathError, GitCommandError

from core.packets import Packet, PacketStatus

def _timestamp(value):
    if value is None:
        return None

    return datetime.fromtimestamp(
        value,
        tz=timezone.utc,
    ).isoformat()

def _hash_file(path):
    hashes = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
    }

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            for digest in hashes.values():
                digest.update(chunk)

    return {
        name: digest.hexdigest()
        for name, digest in hashes.items()
    }

def _extract_config(repo):
    config = {}

    for section in repo.config_reader().sections():
        config[section] = {}

        for key, value in repo.config_reader().items(section):
            config[section][key] = value

    return config

def _extract_remotes(repo):
    remotes = []

    for remote in repo.remotes:
        remotes.append({
            "name": remote.name,
            "urls": list(remote.urls),
            "fetch_refspecs": [
                str(refspec)
                for refspec in remote.fetch_refspecs
            ],
            "push_refspecs": [
                str(refspec)
                for refspec in remote.push_refspecs
            ],
        })

    return remotes

def _extract_branches(repo):
    branches = []

    for branch in repo.branches:
        commit = branch.commit

        branches.append({
            "name": branch.name,
            "commit": commit.hexsha,
            "is_active": branch == repo.active_branch
            if not repo.head.is_detached
            else False,
            "tracking_branch": (
                str(branch.tracking_branch())
                if branch.tracking_branch()
                else None
            ),
        })

    return branches

def _extract_tags(repo):
    tags = []

    for tag in repo.tags:
        commit = tag.commit

        tags.append({
            "name": tag.name,
            "commit": commit.hexsha,
            "message": (
                tag.tag.message
                if tag.tag is not None
                else None
            ),
            "tagger": (
                str(tag.tag.tagger)
                if tag.tag is not None
                else None
            ),
            "tag_date": (
                _timestamp(tag.tag.tagged_date)
                if tag.tag is not None
                else None
            ),
        })

    return tags

def _extract_commit(commit):
    return {
        "hash": commit.hexsha,
        "short_hash": commit.hexsha[:12],
        "message": commit.message.strip(),
        "author": {
            "name": commit.author.name,
            "email": commit.author.email,
        },
        "committer": {
            "name": commit.committer.name,
            "email": commit.committer.email,
        },
        "authored": _timestamp(commit.authored_date),
        "committed": _timestamp(commit.committed_date),
        "parents": [
            parent.hexsha
            for parent in commit.parents
        ],
        "stats": {
            "files_changed": commit.stats.total.get("files", 0),
            "insertions": commit.stats.total.get("insertions", 0),
            "deletions": commit.stats.total.get("deletions", 0),
        },
    }

def _extract_commits(repo, limit):
    commits = []

    for commit in repo.iter_commits(max_count=limit):
        commits.append(_extract_commit(commit))

    return commits

def _extract_contributors(repo):
    contributors = {}

    for commit in repo.iter_commits():
        author = commit.author
        key = (author.name, author.email)

        contributors[key] = contributors.get(key, 0) + 1

    return [
        {
            "name": name,
            "email": email,
            "commit_count": count,
        }
        for (name, email), count in contributors.items()
    ]

def _extract_working_tree(repo):
    untracked = repo.untracked_files

    changed = [
        item.a_path
        for item in repo.index.diff(None)
    ]

    staged = [
        item.a_path
        for item in repo.index.diff("HEAD")
    ]

    return {
        "is_dirty": repo.is_dirty(untracked_files=True),
        "untracked_files": untracked,
        "modified_files": changed,
        "staged_files": staged,
    }

def _extract_repository(repo, commit_limit):
    head = repo.head

    return {
        "repository": {
            "working_directory": str(Path(repo.working_tree_dir).resolve()),
            "git_directory": str(Path(repo.git_dir).resolve()),
            "common_directory": str(Path(repo.common_dir).resolve()),
            "is_bare": repo.bare,
            "is_shallow": repo.is_shallow,
            "is_detached": head.is_detached,
            "current_branch": (
                repo.active_branch.name
                if not head.is_detached
                else None
            ),
            "head_commit": (
                head.commit.hexsha
                if not head.is_unborn
                else None
            ),
        },
        "config": _extract_config(repo),
        "remotes": _extract_remotes(repo),
        "branches": _extract_branches(repo),
        "tags": _extract_tags(repo),
        "commits": _extract_commits(repo, commit_limit),
        "contributors": _extract_contributors(repo),
        "working_tree": _extract_working_tree(repo),
    }

def gitrepositoryextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="git_repository",
        status=PacketStatus.RUNNING,
    )

    try:
        value = packet.input

        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                "Git repository input must be a non-empty directory path."
            )

        path = Path(value.strip())

        if not path.exists():
            raise FileNotFoundError("Git repository path was not found.")

        if not path.is_dir():
            raise ValueError("Git repository input must be a directory.")

        if not (path / ".git").exists() and not (path / "HEAD").exists():
            raise InvalidGitRepositoryError(
                "Directory does not contain a Git repository."
            )

        repo = Repo(path, search_parent_directories=False)

        if repo.bare:
            raise ValueError(
                "Bare repositories are not supported by this extractor."
            )

        commit_limit = 1000

        result.data = _extract_repository(repo, commit_limit)

        result.data["limits"] = {
            "commit_limit": commit_limit,
            "commits_extracted": len(result.data["commits"]),
            "history_complete": (
                len(result.data["commits"]) < commit_limit
            ),
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="GIT_REPOSITORY_NOT_FOUND",
            message=str(exc),
            component="extractors.git_repository",
        )

    except PermissionError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="GIT_REPOSITORY_PERMISSION_DENIED",
            message="Permission denied while accessing the repository.",
            component="extractors.git_repository",
        )

    except InvalidGitRepositoryError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="INVALID_GIT_REPOSITORY",
            message=str(exc),
            component="extractors.git_repository",
        )

    except NoSuchPathError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="GIT_REPOSITORY_NOT_FOUND",
            message=str(exc),
            component="extractors.git_repository",
        )

    except GitCommandError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="GIT_COMMAND_FAILED",
            message=str(exc),
            component="extractors.git_repository",
        )

    except (ValueError, OSError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="GIT_REPOSITORY_INVALID_INPUT",
            message=str(exc),
            component="extractors.git_repository",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="GIT_REPOSITORY_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.git_repository",
        )

    return result