#!/usr/bin/env bash
set -euo pipefail

readonly expected_repository="Cd1s/ssm"
readonly required_latest_tag="v1.4.4"
cleanup_paths=()

cleanup() {
  ((${#cleanup_paths[@]} == 0)) || rm -f -- "${cleanup_paths[@]}"
}

trap cleanup EXIT

die() {
  printf '%s\n' "$*" >&2
  exit 1
}

validate_context() {
  local tag="$1"
  [[ "${GITHUB_REPOSITORY:-}" == "$expected_repository" ]] ||
    die "release repository identity is not accepted: ${GITHUB_REPOSITORY:-unset}"
  [[ -n "${GH_TOKEN:-}" ]] || die "GH_TOKEN is required for authenticated Release-state verification"
  [[ "$tag" =~ ^v2\.[0-9]+\.[0-9]+$ ]] || die "v2 release tag must look like v2.0.0: $tag"
}

assert_release_absent() {
  local tag="$1"
  local release_tags

  validate_context "$tag"
  if ! release_tags="$(gh api --paginate \
    "repos/$GITHUB_REPOSITORY/releases?per_page=100" \
    --jq '.[].tag_name')"; then
    die "unable to prove GitHub Release $tag is absent"
  fi
  if printf '%s\n' "$release_tags" | grep -Fqx -- "$tag"; then
    die "GitHub Release $tag already exists; refusing to mutate or overwrite it"
  fi
}

assert_only_created_release() {
  local tag="$1"
  local release_id="$2"
  local stage="$3"
  local release_rows
  local matching_ids

  if ! release_rows="$(gh api --paginate \
    "repos/$GITHUB_REPOSITORY/releases?per_page=100" \
    --jq '.[] | [.id, .tag_name] | @tsv')"; then
    die "unable to prove GitHub Release $tag is unique $stage; created state is preserved"
  fi
  matching_ids="$(printf '%s\n' "$release_rows" | awk -F '\t' -v tag="$tag" '$2 == tag { print $1 }')"
  [[ "$matching_ids" == "$release_id" ]] ||
    die "GitHub Release $tag is not the sole created Release $stage; external state is preserved"
}

publish_release() {
  local tag="$1"
  local source_sha="$2"
  local body_path="$3"
  shift 3
  local -a files=("$@")
  local -a expected_names=(
    ssm-linux-amd64
    ssm-linux-arm64
    ssm-darwin-amd64
    ssm-darwin-arm64
    ssm-windows-amd64.exe
    ssm-windows-arm64.exe
    ssm-linux-amd64.sigstore.json
    ssm-linux-arm64.sigstore.json
    ssm-darwin-amd64.sigstore.json
    ssm-darwin-arm64.sigstore.json
    ssm-windows-amd64.exe.sigstore.json
    ssm-windows-arm64.exe.sigstore.json
    install.sh
    checksums.txt
  )
  local index
  local payload
  local created
  local bound
  local final
  local latest
  local created_release_id
  local expected_json

  validate_context "$tag"
  [[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || die "release source must be one exact lowercase commit SHA"
  [[ -f "$body_path" && ! -L "$body_path" ]] || die "release body is not a regular reviewed file"
  grep -q '[^[:space:]]' "$body_path" || die "release body is empty"
  ((${#files[@]} == ${#expected_names[@]})) ||
    die "release upload must contain exactly ${#expected_names[@]} files"
  for index in "${!expected_names[@]}"; do
    [[ "$(basename -- "${files[$index]}")" == "${expected_names[$index]}" ]] ||
      die "release upload file $index is not ${expected_names[$index]}"
    [[ -f "${files[$index]}" && ! -L "${files[$index]}" && -s "${files[$index]}" ]] ||
      die "release upload file ${expected_names[$index]} is missing, empty, or not regular"
  done

  assert_release_absent "$tag"
  [[ -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" ]] || die "RUNNER_TEMP is not an existing directory"
  payload="$(mktemp "$RUNNER_TEMP/ssm-release-create-payload.XXXXXX")"
  created="$(mktemp "$RUNNER_TEMP/ssm-release-created.XXXXXX")"
  bound="$(mktemp "$RUNNER_TEMP/ssm-release-bound.XXXXXX")"
  final="$(mktemp "$RUNNER_TEMP/ssm-release-final.XXXXXX")"
  latest="$(mktemp "$RUNNER_TEMP/ssm-release-latest.XXXXXX")"
  cleanup_paths=("$payload" "$created" "$bound" "$final" "$latest")

  jq -n \
    --arg tag "$tag" \
    --arg source_sha "$source_sha" \
    --rawfile body "$body_path" \
    '{
      tag_name: $tag,
      target_commitish: $source_sha,
      name: $tag,
      body: $body,
      draft: false,
      prerelease: false,
      make_latest: "false"
    }' > "$payload"

  if ! gh api --method POST \
    "repos/$GITHUB_REPOSITORY/releases" \
    --input "$payload" > "$created"; then
    die "create-only GitHub Release $tag failed; refusing to update or reuse external state"
  fi
  if ! jq -e \
    --arg tag "$tag" \
    --arg source_sha "$source_sha" \
    --rawfile body "$body_path" \
    'type == "object" and
     (.id | type == "number" and . > 0) and
     .tag_name == $tag and
     .target_commitish == $source_sha and
     .name == $tag and
     .body == $body and
     .draft == false and
     .prerelease == false' "$created" >/dev/null; then
    die "created GitHub Release response does not match the reviewed stable non-latest request"
  fi
  created_release_id="$(jq -er '.id' "$created")"
  assert_only_created_release "$tag" "$created_release_id" "before asset upload"

  if ! gh api "repos/$GITHUB_REPOSITORY/releases/tags/$tag" > "$bound"; then
    die "unable to bind created GitHub Release $tag before asset upload; partial state is preserved"
  fi
  jq -e \
    --argjson release_id "$created_release_id" \
    --arg tag "$tag" \
    --arg source_sha "$source_sha" \
    '.id == $release_id and .tag_name == $tag and .target_commitish == $source_sha and
     .draft == false and .prerelease == false and (.assets | length) == 0' \
    "$bound" >/dev/null ||
    die "created GitHub Release binding is ambiguous before asset upload; partial state is preserved"

  if ! gh release upload "$tag" "${files[@]}" --repo "$GITHUB_REPOSITORY"; then
    die "GitHub Release $tag asset upload failed; partial state is preserved and must not be retried"
  fi

  expected_json="$(printf '%s\n' "${expected_names[@]}" | jq -R . | jq -s .)"
  if ! gh api "repos/$GITHUB_REPOSITORY/releases/$created_release_id" > "$final"; then
    die "unable to read back created GitHub Release $tag; external state is preserved"
  fi
  jq -e \
    --argjson release_id "$created_release_id" \
    --argjson expected "$expected_json" \
    --arg tag "$tag" \
    --arg source_sha "$source_sha" \
    --rawfile body "$body_path" \
    '.id == $release_id and .tag_name == $tag and .target_commitish == $source_sha and
     .name == $tag and .body == $body and .draft == false and .prerelease == false and
     ([.assets[].name] | length) == ($expected | length) and
     ([.assets[].name] | sort) == ($expected | sort) and
     (.assets | all(.[]; .state == "uploaded"))' "$final" >/dev/null ||
    die "GitHub Release $tag readback is not the exact reviewed 14-asset stable release"
  assert_only_created_release "$tag" "$created_release_id" "after asset upload"

  if ! gh api "repos/$GITHUB_REPOSITORY/releases/latest" > "$latest"; then
    die "unable to prove GitHub latest remains $required_latest_tag; created state is preserved"
  fi
  jq -e \
    --arg tag "$required_latest_tag" \
    --argjson created_release_id "$created_release_id" \
    '.tag_name == $tag and .id != $created_release_id and .draft == false and .prerelease == false' \
    "$latest" >/dev/null ||
    die "GitHub latest changed from $required_latest_tag; created state is preserved"
}

case "${1:-}" in
  assert-absent)
    (($# == 2)) || die "usage: release-create-only.sh assert-absent TAG"
    assert_release_absent "$2"
    ;;
  publish)
    (($# == 18)) || die "usage: release-create-only.sh publish TAG SOURCE_SHA BODY_FILE FILE..."
    publish_release "${@:2}"
    ;;
  *)
    die "usage: release-create-only.sh assert-absent|publish ..."
    ;;
esac
