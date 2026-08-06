#!/usr/bin/env bash
set -euo pipefail

readonly expected_repository="Cd1s/ssm"
readonly release_visibility_max_attempts=10
readonly release_visibility_default_delay_seconds=2
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

read_release_inventory() {
  local stage="$1"
  local inventory

  if ! inventory="$(gh api --paginate \
    "repos/$GITHUB_REPOSITORY/releases?per_page=100")"; then
    die "unable to read exhaustive GitHub Release inventory $stage"
  fi
  if ! jq -e -s '
    length > 0 and
    all(.[];
      type == "array" and
      all(.[];
        type == "object" and
        ((.id | type) == "number") and .id > 0 and
        ((.tag_name | type) == "string") and (.tag_name | length) > 0
      )
    ) and
    ([.[][] | .id] | length) == ([.[][] | .id] | unique | length) and
    ([.[][] | .tag_name] | length) == ([.[][] | .tag_name] | unique | length)
  ' <<< "$inventory" >/dev/null; then
    die "GitHub Release inventory is malformed $stage; external state is preserved"
  fi
  printf '%s\n' "$inventory"
}

assert_release_absent() {
  local tag="$1"
  local release_inventory
  local release_tags

  validate_context "$tag"
  release_inventory="$(read_release_inventory "while proving $tag is absent")"
  release_tags="$(jq -r -s '.[][] | .tag_name' <<< "$release_inventory")"
  if printf '%s\n' "$release_tags" | grep -Fqx -- "$tag"; then
    die "GitHub Release $tag already exists; refusing to mutate or overwrite it"
  fi
}

assert_only_created_release() {
  local tag="$1"
  local release_id="$2"
  local stage="$3"
  local release_inventory
  local release_rows
  local matching_ids

  release_inventory="$(read_release_inventory "while proving $tag is unique $stage")"
  release_rows="$(jq -r -s '.[][] | [.id, .tag_name] | @tsv' <<< "$release_inventory")"
  matching_ids="$(printf '%s\n' "$release_rows" | awk -F '\t' -v tag="$tag" '$2 == tag { print $1 }')"
  [[ "$matching_ids" == "$release_id" ]] ||
    die "GitHub Release $tag is not the sole created Release $stage; external state is preserved"
}

await_only_created_release_visibility() {
  local tag="$1"
  local release_id="$2"
  local retry_delay="${SSM_RELEASE_VISIBILITY_RETRY_DELAY_SECONDS:-$release_visibility_default_delay_seconds}"
  local attempt
  local release_inventory
  local visibility

  [[ "$retry_delay" =~ ^[0-3]$ ]] ||
    die "Release visibility retry delay is invalid; partial state is preserved"
  for ((attempt = 1; attempt <= release_visibility_max_attempts; attempt++)); do
    release_inventory="$(read_release_inventory "while awaiting exact visibility of $tag before asset upload")"
    visibility="$(jq -r -s --arg tag "$tag" --argjson id "$release_id" '
      ([.[][] | select(.tag_name == $tag)] | length) as $tag_count |
      ([.[][] | select(.id == $id)] | length) as $id_count |
      if $tag_count == 1 and $id_count == 1 and
         ([.[][] | select(.tag_name == $tag and .id == $id)] | length) == 1 then
        "exact"
      elif $tag_count == 0 and $id_count == 0 then
        "absent"
      else
        "wrong"
      end
    ' <<< "$release_inventory")" ||
      die "unable to classify created GitHub Release visibility; partial state is preserved"
    case "$visibility" in
      exact)
        return 0
        ;;
      absent)
        if ((attempt < release_visibility_max_attempts)); then
          sleep "$retry_delay"
          continue
        fi
        ;;
      *)
        die "GitHub Release $tag has a conflicting ID/tag visibility binding before asset upload; partial state is preserved"
        ;;
    esac
  done
  die "GitHub Release $tag did not become uniquely visible after $release_visibility_max_attempts attempts; partial state is preserved"
}

publish_release() {
  local tag="$1"
  local source_sha="$2"
  local body_path="$3"
  local expected_latest_tag="$4"
  shift 4
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
  local -a expected_sizes=()
  local -a expected_digests=()
  local index
  local payload
  local created
  local bound
  local upload_response
  local final
  local latest_before
  local latest_after
  local expected_latest_release_id
  local created_release_id
  local expected_json
  local asset_name
  local encoded_name
  local upload_endpoint
  local asset_size
  local asset_sha256

  validate_context "$tag"
  [[ "$expected_latest_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    die "expected latest tag must be an exact stable v-tag: $expected_latest_tag"
  [[ "$expected_latest_tag" != "$tag" ]] ||
    die "expected latest tag must differ from target tag: $tag"
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
    expected_sizes[$index]="$(wc -c < "${files[$index]}" | tr -d '[:space:]')"
    [[ "${expected_sizes[$index]}" =~ ^[1-9][0-9]*$ ]] ||
      die "release upload file ${expected_names[$index]} has an invalid byte size"
    asset_sha256="$(sha256sum < "${files[$index]}" | awk '{print $1}')"
    [[ "$asset_sha256" =~ ^[0-9a-f]{64}$ ]] ||
      die "release upload file ${expected_names[$index]} has an invalid SHA-256 digest"
    expected_digests[$index]="sha256:$asset_sha256"
  done

  [[ "${SSM_RELEASE_VISIBILITY_RETRY_DELAY_SECONDS:-$release_visibility_default_delay_seconds}" =~ ^[0-3]$ ]] ||
    die "Release visibility retry delay is invalid; no external state changed"

  assert_release_absent "$tag"
  [[ -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" ]] || die "RUNNER_TEMP is not an existing directory"
  payload="$(mktemp "$RUNNER_TEMP/ssm-release-create-payload.XXXXXX")"
  created="$(mktemp "$RUNNER_TEMP/ssm-release-created.XXXXXX")"
  bound="$(mktemp "$RUNNER_TEMP/ssm-release-bound.XXXXXX")"
  upload_response="$(mktemp "$RUNNER_TEMP/ssm-release-upload.XXXXXX")"
  final="$(mktemp "$RUNNER_TEMP/ssm-release-final.XXXXXX")"
  latest_before="$(mktemp "$RUNNER_TEMP/ssm-release-latest-before.XXXXXX")"
  latest_after="$(mktemp "$RUNNER_TEMP/ssm-release-latest-after.XXXXXX")"
  cleanup_paths=("$payload" "$created" "$bound" "$upload_response" "$final" "$latest_before" "$latest_after")

  if ! gh api "repos/$GITHUB_REPOSITORY/releases/latest" > "$latest_before"; then
    die "unable to read GitHub latest before create; no external state changed"
  fi
  jq -e \
    --arg tag "$expected_latest_tag" \
    --arg target_tag "$tag" \
    'type == "object" and
     (.id | type == "number" and . > 0) and
     .tag_name == $tag and .tag_name != $target_tag and
     .draft == false and .prerelease == false' \
    "$latest_before" >/dev/null ||
    die "GitHub latest does not match reviewed baseline $expected_latest_tag before create; no external state changed"
  expected_latest_release_id="$(jq -er '.id' "$latest_before")"

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
  [[ "$created_release_id" != "$expected_latest_release_id" ]] ||
    die "created GitHub Release ID matches reviewed latest Release ID; refusing asset upload and preserving partial state"
  await_only_created_release_visibility "$tag" "$created_release_id"

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

  for index in "${!files[@]}"; do
    asset_name="${expected_names[$index]}"
    if ! encoded_name="$(jq -rn --arg name "$asset_name" '$name | @uri')"; then
      die "unable to encode GitHub Release asset name $asset_name; partial state is preserved"
    fi
    upload_endpoint="https://uploads.github.com/repos/$GITHUB_REPOSITORY/releases/$created_release_id/assets?name=$encoded_name"
    if ! gh api --method POST \
      "$upload_endpoint" \
      -H "Content-Type: application/octet-stream" \
      --input "${files[$index]}" > "$upload_response"; then
      die "GitHub Release $tag asset $asset_name upload failed; partial state is preserved and must not be retried"
    fi
    jq -e \
      --arg name "$asset_name" \
      --argjson size "${expected_sizes[$index]}" \
      --arg digest "${expected_digests[$index]}" \
      '(.id | type == "number" and . > 0) and .name == $name and
       .state == "uploaded" and .content_type == "application/octet-stream" and
       .size == $size and .digest == $digest' \
      "$upload_response" >/dev/null ||
      die "GitHub Release $tag asset $asset_name response is not the bound uploaded asset; partial state is preserved"
  done

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
  for index in "${!expected_names[@]}"; do
    jq -e \
      --arg name "${expected_names[$index]}" \
      --argjson size "${expected_sizes[$index]}" \
      --arg digest "${expected_digests[$index]}" \
      'any(.assets[];
        .name == $name and .state == "uploaded" and
        .content_type == "application/octet-stream" and
        .size == $size and .digest == $digest
      )' "$final" >/dev/null ||
      die "GitHub Release $tag asset ${expected_names[$index]} final byte metadata does not match the reviewed file"
  done
  assert_only_created_release "$tag" "$created_release_id" "after asset upload"

  if ! gh api "repos/$GITHUB_REPOSITORY/releases/latest" > "$latest_after"; then
    die "unable to prove GitHub latest remains $expected_latest_tag; created state is preserved"
  fi
  jq -e \
    --arg tag "$expected_latest_tag" \
    --argjson expected_latest_release_id "$expected_latest_release_id" \
    --argjson created_release_id "$created_release_id" \
    'type == "object" and
     (.id | type == "number" and . > 0) and
     .id == $expected_latest_release_id and .id != $created_release_id and
     .tag_name == $tag and .draft == false and .prerelease == false' \
    "$latest_after" >/dev/null ||
    die "GitHub latest changed from $expected_latest_tag; created state is preserved"
}

case "${1:-}" in
  assert-absent)
    (($# == 2)) || die "usage: release-create-only.sh assert-absent TAG"
    assert_release_absent "$2"
    ;;
  publish)
    (($# == 19)) || die "usage: release-create-only.sh publish TAG SOURCE_SHA BODY_FILE EXPECTED_LATEST_TAG FILE..."
    publish_release "${@:2}"
    ;;
  *)
    die "usage: release-create-only.sh assert-absent|publish ..."
    ;;
esac
