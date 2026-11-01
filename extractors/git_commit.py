from pathlib import Path
from datetime import datetime, timezone

from git import Repo, InvalidGitRepositoryError, BadName, GitCommandError

from core.packets import Packet, PacketStatus

def _timestamp(value):
    if value is None:
        return None

    return datetime.fromtimestamp(
        value,
        tz=timezone.utc,
    ).isoformat()

def _extract_identity(identity):
    if identity is None:
        return None

    return {
        "name": identity.name,
        "email": identity.email,
    }

def _extract_stats(commit):
    stats = commit.stats

    return {
        "files_changed": stats.total.get("files", 0),
        "insertions": stats.total.get("insertions", 0),
        "deletions": stats.total.get("deletions", 0),
        "total_changes": (
            stats.total.get("insertions", 0)
            + stats.total.get("deletions", 0)
        ),
        "files": {
            path: {
                "insertions": values.get("insertions", 0),
                "deletions": values.get("deletions", 0),
                "lines": values.get("lines", 0),
            }
            for path, values in stats.files.items()
        },
    }

def _extract_file_changes(commit):
    changes = []

    if not commit.parents:
        # Initial commit: compare against an empty tree.
        diff = commit.diff(
            None,
            create_patch=False,
        )
    else:
        diff = commit.parents[0].diff(
            commit,
            create_patch=False,
        )

    for item in diff:
        if item.new_file:
            change_type = "added"
        elif item.deleted_file:
            change_type = "deleted"
        elif item.renamed:
            change_type = "renamed"
        elif item.copied:
            change_type = "copied"
        elif item.a_blob and item.b_blob:
            change_type = "modified"
        else:
            change_type = "unknown"

        changes.append({
            "change_type": change_type,
            "old_path": item.a_path,
            "new_path": item.b_path,
            "old_mode": item.a_mode,
            "new_mode": item.b_mode,
            "old_blob": item.a_blob.hexsha if item.a_blob else None,
            "new_blob": item.b_blob.hexsha if item.b_blob else None,
        })

    return changes

def _extract_commit(commit):
    return {
        "hash": commit.hexsha,
        "short_hash": commit.hexsha[:12],
        "tree": commit.tree.hexsha,
        "message": commit.message,
        "summary": commit.summary,
        "encoding": commit.encoding,
        "author": _extract_identity(commit.author),
        "committer": _extract_identity(commit.committer),
        "authored": _timestamp(commit.authored_date),
        "committed": _timestamp(commit.committed_date),
        "author_timezone_offset": commit.author_tz_offset,
        "committer_timezone_offset": commit.committer_tz_offset,
        "parents": [
            {
                "hash": parent.hexsha,
                "short_hash": parent.hexsha[:12],
            }
            for parent in commit.parents
        ],
        "parent_count": len(commit.parents),
        "is_merge_commit": len(commit.parents) > 1,
        "stats": _extract_stats(commit),
        "file_changes": _extract_file_changes(commit),
    }

def gitcommitextract(packet: Packet) -> Packet:
    result = packet.child(
        stage="extraction",
        artefact_type="git_commit",
        status=PacketStatus.RUNNING,
    )

    try:
        value = packet.input

        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                "Git commit input must be a commit hash or repository path and commit hash."
            )

        candidate = value.strip()

        # Supported input:
        #   <commit-hash>
        #   <repository-path>::<commit-hash>
        if "::" in candidate:
            repository_path, commit_reference = candidate.rsplit("::", 1)

            if not repository_path.strip() or not commit_reference.strip():
                raise ValueError(
                    "Repository path and commit reference must both be supplied."
                )

            repo_path = Path(repository_path.strip())

            if not repo_path.exists():
                raise FileNotFoundError(
                    "Git repository path was not found."
                )

            if not repo_path.is_dir():
                raise ValueError(
                    "Git repository path must be a directory."
                )

            repo = Repo(
                repo_path,
                search_parent_directories=False,
            )

        else:
            commit_reference = candidate
            repo = Repo(
                Path.cwd(),
                search_parent_directories=True,
            )

        if repo.bare:
            raise ValueError(
                "Bare repositories are not supported."
            )

        try:
            commit = repo.commit(commit_reference)
        except (BadName, ValueError) as exc:
            raise ValueError(
                f"Commit reference could not be resolved: {commit_reference}"
            ) from exc

        result.data = {
            "repository": {
                "working_directory": str(
                    Path(repo.working_tree_dir).resolve()
                ),
                "git_directory": str(
                    Path(repo.git_dir).resolve()
                ),
            },
            "commit": _extract_commit(commit),
        }

        result.status = PacketStatus.SUCCESS

    except FileNotFoundError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="GIT_COMMIT_REPOSITORY_NOT_FOUND",
            message=str(exc),
            component="extractors.git_commit",
        )

    except PermissionError:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="GIT_COMMIT_PERMISSION_DENIED",
            message="Permission denied while accessing the Git repository.",
            component="extractors.git_commit",
        )

    except InvalidGitRepositoryError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="INVALID_GIT_REPOSITORY",
            message=str(exc),
            component="extractors.git_commit",
        )

    except GitCommandError as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="GIT_COMMIT_COMMAND_FAILED",
            message=str(exc),
            component="extractors.git_commit",
        )

    except (ValueError, OSError) as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="GIT_COMMIT_INVALID_INPUT",
            message=str(exc),
            component="extractors.git_commit",
        )

    except Exception as exc:
        result.status = PacketStatus.FAILED
        result.add_error(
            code="GIT_COMMIT_EXTRACTION_FAILED",
            message=str(exc),
            component="extractors.git_commit",
        )

    return result