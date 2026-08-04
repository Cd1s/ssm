#!/bin/sh
set -eu

usage() {
  echo "usage: install-agent-ssm-skill.sh --platform codex|hermes --source <agent-ssm-dir> --root <platform-root> --sshctl <path> [--replace]" >&2
  exit 2
}

platform=""
source_dir=""
platform_root=""
sshctl_path=""
replace=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --platform)
      [ "$#" -ge 2 ] || usage
      platform="$2"
      shift 2
      ;;
    --source)
      [ "$#" -ge 2 ] || usage
      source_dir="$2"
      shift 2
      ;;
    --root)
      [ "$#" -ge 2 ] || usage
      platform_root="$2"
      shift 2
      ;;
    --sshctl)
      [ "$#" -ge 2 ] || usage
      sshctl_path="$2"
      shift 2
      ;;
    --replace)
      replace=true
      shift
      ;;
    *) usage ;;
  esac
done

case "$platform" in
  codex|hermes) ;;
  *) usage ;;
esac
[ -n "$source_dir" ] || usage
[ -n "$platform_root" ] || usage
[ -n "$sshctl_path" ] || usage
case "$platform_root" in
  /|.)
    echo "platform root must be one explicit private Codex or Hermes directory" >&2
    exit 1
    ;;
esac
if [ ! -d "$source_dir" ] || [ -L "$source_dir" ]; then
  echo "bundled agent-ssm source must be one real directory" >&2
  exit 1
fi
if [ ! -f "$sshctl_path" ] || [ ! -x "$sshctl_path" ]; then
  echo "sshctl version probe must resolve to one executable regular file" >&2
  exit 1
fi
if find "$source_dir" -type l -print -quit | grep -q .; then
  echo "bundled agent-ssm source must not contain symlinks" >&2
  exit 1
fi
for required in \
  SKILL.md \
  README.md \
  test-prompts.json \
  references/import-json.md \
  references/install-update.md \
  references/request-v1-bridge.schema.json \
  references/request-v1.schema.json \
  references/version-compatibility.md
do
  if [ ! -f "$source_dir/$required" ] || [ -L "$source_dir/$required" ]; then
    echo "bundled agent-ssm source is missing required regular file: $required" >&2
    exit 1
  fi
done

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to validate sshctl --json --version" >&2
  exit 1
fi
if ! version_json="$("$sshctl_path" --json --version)"; then
  echo "sshctl version probe failed; skill was not installed" >&2
  exit 1
fi
if ! version="$(printf '%s\n' "$version_json" | jq -er 'select(type == "object" and .ok == true and (.version | type == "string")) | .version')"; then
  echo "sshctl version probe returned no exact supported version; skill was not installed" >&2
  exit 1
fi
case "$version" in
  1.4.3|1.4.4) contract="v1 compatibility branch" ;;
  2.0.0) contract="v2 compatibility branch" ;;
  *)
    echo "sshctl version $version is unsupported; fail closed and install a matching official skill" >&2
    exit 1
    ;;
esac
if ! grep -Fq "v1.4.3 / v1.4.4" "$source_dir/SKILL.md" ||
   ! grep -Fq "v2.0.0" "$source_dir/SKILL.md"; then
  echo "bundled skill does not declare the reviewed version matrix" >&2
  exit 1
fi

if [ -L "$platform_root" ]; then
  echo "platform root must not be a symlink" >&2
  exit 1
fi
mkdir -p "$platform_root"
skills_root="$platform_root/skills"
if [ -L "$skills_root" ]; then
  echo "platform skills directory must not be a symlink" >&2
  exit 1
fi
mkdir -p "$skills_root"
destination="$skills_root/agent-ssm"
stage="$(mktemp -d "$skills_root/.agent-ssm.new.XXXXXX")"
cleanup_stage() {
  if [ -n "${stage:-}" ] && [ -d "$stage" ]; then
    rm -rf "$stage"
  fi
}
trap cleanup_stage EXIT HUP INT TERM
cp -R "$source_dir/." "$stage/"

backup=""
if [ -e "$destination" ] || [ -L "$destination" ]; then
  if [ "$replace" != true ]; then
    echo "agent-ssm already exists; rerun with --replace only after reviewing the exact-tag bundle" >&2
    exit 1
  fi
  if [ ! -d "$destination" ] || [ -L "$destination" ]; then
    echo "existing agent-ssm destination is not a replaceable real directory" >&2
    exit 1
  fi
  backup="$(mktemp -d "$skills_root/.agent-ssm.backup.XXXXXX")"
  mv "$destination" "$backup/agent-ssm"
fi

if ! mv "$stage" "$destination"; then
  if [ -n "$backup" ] && [ -d "$backup/agent-ssm" ]; then
    mv "$backup/agent-ssm" "$destination"
  fi
  echo "failed to publish matching agent-ssm skill; prior installation restored when present" >&2
  exit 1
fi
stage=""
printf 'installed agent-ssm for %s %s using %s at %s\n' "$platform" "$version" "$contract" "$destination"
if [ -n "$backup" ]; then
  printf 'preserved prior installation at %s\n' "$backup/agent-ssm"
fi
