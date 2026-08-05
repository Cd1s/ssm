#!/usr/bin/env bash
set -euo pipefail

readonly expected_repository="Cd1s/ssm"
readonly expected_tag="v2.0.0"
readonly expected_source_sha="10417d0e235eff9b22081765b0ad17b75cf74990"
readonly expected_release_id="364882535"
readonly expected_run_id="30911029600"
readonly required_latest_id="364597135"
readonly required_latest_tag="v1.4.4"
readonly -a artifact_names=(ssm-linux-amd64 ssm-linux-arm64 ssm-darwin-amd64 ssm-darwin-arm64 ssm-windows-amd64.exe ssm-windows-arm64.exe)
readonly -a artifact_ids=(8893638050 8893654485 8893655254 8893658709 8893659626 8893655015)
readonly -a asset_names=(ssm-linux-amd64 ssm-linux-arm64 ssm-darwin-amd64 ssm-darwin-arm64 ssm-windows-amd64.exe ssm-windows-arm64.exe ssm-linux-amd64.sigstore.json ssm-linux-arm64.sigstore.json ssm-darwin-amd64.sigstore.json ssm-darwin-arm64.sigstore.json ssm-windows-amd64.exe.sigstore.json ssm-windows-arm64.exe.sigstore.json install.sh checksums.txt)

die() { printf '%s\n' "$*" >&2; exit 1; }
api() { gh api "$@"; }

[[ "${GITHUB_REPOSITORY:-}" == "$expected_repository" && "${EXPECTED_REPOSITORY:-}" == "$expected_repository" ]] || die "repository binding mismatch"
[[ "${EXPECTED_SOURCE_SHA:-}" == "$expected_source_sha" && "${EXPECTED_RELEASE_ID:-}" == "$expected_release_id" && "${EXPECTED_SOURCE_RUN_ID:-}" == "$expected_run_id" ]] || die "workflow binding mismatch"
[[ "${REQUIRED_LATEST_ID:-}" == "$required_latest_id" && "${REQUIRED_LATEST_TAG:-}" == "$required_latest_tag" ]] || die "latest binding mismatch"
[[ -n "${GH_TOKEN:-}" && -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" ]] || die "authenticated runner context required"
work="$(mktemp -d "$RUNNER_TEMP/ssm-v2-recovery.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

api --paginate "repos/$expected_repository/releases?per_page=100" > "$work/releases.pages"
jq -e -s --arg tag "$expected_tag" --argjson id "$expected_release_id" '
  all(.[]; type=="array") and ([.[][]|select(.tag_name==$tag)]|length)==1 and
  ([.[][]|select(.tag_name==$tag)][0].id)==$id and ([.[][]|.id]|length)==([.[][]|.id]|unique|length)
' "$work/releases.pages" >/dev/null || die "exhaustive Release inventory is ambiguous"

api "repos/$expected_repository/releases/$expected_release_id" > "$work/release.json"
api "repos/$expected_repository/releases/latest" > "$work/latest.json"
api "repos/$expected_repository/contents/RELEASE_NOTES.md?ref=$expected_source_sha" > "$work/release-notes-content.json"
jq -e '.type=="file" and .encoding=="base64" and (.size|type)=="number" and .size>0 and (.content|type)=="string" and (.content|length)>0' "$work/release-notes-content.json" >/dev/null || die "tagged release notes content is invalid"
jq -r .content "$work/release-notes-content.json" | tr -d '\r\n' | base64 -d > "$work/RELEASE_NOTES.md"
[[ -s "$work/RELEASE_NOTES.md" ]] || die "tagged release notes materialized empty"
awk -v h="## $expected_tag" '$0==h{f=1;next} f&&/^## /{exit} f{print} END{if(!f)exit 1}' "$work/RELEASE_NOTES.md" > "$work/body.md"
assert_release() {
  jq -e --argjson id "$expected_release_id" --arg tag "$expected_tag" --arg sha "$expected_source_sha" --rawfile body "$work/body.md" '
    .id==$id and .tag_name==$tag and .target_commitish==$sha and .name==$tag and .body==$body and .draft==false and .prerelease==false
  ' "$1" >/dev/null || die "Release metadata binding failed"
}
assert_latest() { jq -e --argjson id "$required_latest_id" --arg tag "$required_latest_tag" '.id==$id and .tag_name==$tag and .draft==false and .prerelease==false' "$work/latest.json" >/dev/null || die "GitHub latest binding failed"; }
assert_release "$work/release.json"; assert_latest

api "repos/$expected_repository/actions/runs/$expected_run_id" > "$work/run.json"
api --paginate "repos/$expected_repository/actions/runs/$expected_run_id/jobs?per_page=100" > "$work/jobs.pages"
jq -e --arg sha "$expected_source_sha" '.id==30911029600 and .event=="push" and .status=="completed" and .conclusion=="failure" and .head_branch=="v2.0.0" and .head_sha==$sha and .path==".github/workflows/release.yml" and .name=="Release" and .run_attempt==1' "$work/run.json" >/dev/null || die "source run identity mismatch"
jq -e -s '
  [ .[].jobs[] | {name,conclusion} ] as $j |
  ($j|length)==8 and
  ($j|map(select(.name=="preflight" and .conclusion=="success"))|length)==1 and
  ($j|map(select(.name=="publish" and .conclusion=="failure"))|length)==1 and
  (["build (linux, amd64, ssm-linux-amd64)","build (linux, arm64, ssm-linux-arm64)","build (darwin, amd64, ssm-darwin-amd64)","build (darwin, arm64, ssm-darwin-arm64)","build (windows, amd64, ssm-windows-amd64.exe)","build (windows, arm64, ssm-windows-arm64.exe)"] - [$j[]|select(.conclusion=="success")|.name] | length)==0
' "$work/jobs.pages" >/dev/null || die "source job conclusions are not exact"

api --paginate "repos/$expected_repository/actions/runs/$expected_run_id/artifacts?per_page=100" > "$work/artifacts.pages"
expected_artifacts="$(for i in "${!artifact_names[@]}"; do jq -n --argjson id "${artifact_ids[$i]}" --arg name "${artifact_names[$i]}" '{id:$id,name:$name}'; done | jq -s 'sort_by(.id)')"
jq -e -s '
  length>0 and
  all(.[];
    type=="object" and (keys|sort)==["artifacts","total_count"] and
    (.total_count|type)=="number" and .total_count>=0 and (.total_count|floor)==.total_count and
    (.artifacts|type)=="array"
  ) and
  .[0].total_count as $total |
  $total==([.[].artifacts[]]|length) and
  all(.[]; .total_count==$total)
' "$work/artifacts.pages" >/dev/null || die "workflow artifact inventory is malformed"
jq -e -s --argjson expected "$expected_artifacts" '
  [.[].artifacts[]] as $artifacts |
  ($artifacts|length)==6 and
  all($artifacts[];
    (.id|type)=="number" and .id>0 and (.id|floor)==.id and
    (.name|type)=="string" and .name!="" and .expired==false
  ) and
  ($artifacts|map(.id)|length)==($artifacts|map(.id)|unique|length) and
  ($artifacts|map(.name)|length)==($artifacts|map(.name)|unique|length) and
  ($artifacts|map({id,name})|sort_by(.id))==$expected
' "$work/artifacts.pages" >/dev/null || die "workflow artifacts are missing, expired, duplicate, or extra"
mkdir "$work/assets"
for i in "${!artifact_names[@]}"; do
  archive="$work/${artifact_ids[$i]}.zip"
  api "repos/$expected_repository/actions/artifacts/${artifact_ids[$i]}/zip" > "$archive"
  mkdir "$work/extract-$i"; unzip -q "$archive" -d "$work/extract-$i"
  mapfile -t files < <(find "$work/extract-$i" -type f -printf '%f\n' | sort)
  [[ "${#files[@]}" == 2 && "${files[0]}" == "${artifact_names[$i]}" && "${files[1]}" == "${artifact_names[$i]}.sigstore.json" ]] || die "artifact ${artifact_ids[$i]} has unexpected files"
  install -m 0600 "$work/extract-$i/${artifact_names[$i]}" "$work/assets/${artifact_names[$i]}"
  install -m 0600 "$work/extract-$i/${artifact_names[$i]}.sigstore.json" "$work/assets/${artifact_names[$i]}.sigstore.json"
done
api "repos/$expected_repository/contents/install.sh?ref=$expected_source_sha" > "$work/install-content.json"
jq -e '.type=="file" and .encoding=="base64" and (.size|type)=="number" and .size>0 and (.content|type)=="string" and (.content|length)>0' "$work/install-content.json" >/dev/null || die "tagged install.sh content is invalid"
jq -r .content "$work/install-content.json" | tr -d '\r\n' | base64 -d > "$work/assets/install.sh"
[[ -s "$work/assets/install.sh" && ! -L "$work/assets/install.sh" ]] || die "tagged install.sh materialized invalid"
(cd "$work/assets" && sha256sum ssm-linux-amd64 ssm-linux-arm64 ssm-darwin-amd64 ssm-darwin-arm64 ssm-windows-amd64.exe ssm-windows-arm64.exe install.sh > checksums.txt)
for binary in "${artifact_names[@]}"; do go run ./cmd/recoveryverify "$work/assets/$binary" "$work/assets/$binary.sigstore.json"; done

metadata_matches() {
  local json="$1" name="$2" file="$3" size digest count
  size="$(wc -c < "$file" | tr -d '[:space:]')"; digest="sha256:$(sha256sum < "$file" | awk '{print $1}')"
  count="$(jq --arg n "$name" '[.assets[]|select(.name==$n)]|length' "$json")"
  [[ "$count" == 1 ]] || return 1
  jq -e --arg n "$name" --argjson s "$size" --arg d "$digest" '.assets[]|select(.name==$n)|.state=="uploaded" and .content_type=="application/octet-stream" and .size==$s and .digest==$d' "$json" >/dev/null
}
assert_no_unexpected_assets() {
  local json="$1" expected
  expected="$(printf '%s\n' "${asset_names[@]}"|jq -R .|jq -s .)"
  jq -e --argjson e "$expected" '([.assets[].name]|length)==([.assets[].name]|unique|length) and ([.assets[].name]-$e|length)==0' "$json" >/dev/null || die "Release contains duplicate or unexpected assets"
}
reconcile_ambiguous_upload() { api "repos/$expected_repository/releases/$expected_release_id" > "$work/reconcile.json" && assert_release "$work/reconcile.json" && metadata_matches "$work/reconcile.json" "$1" "$2"; }

assert_no_unexpected_assets "$work/release.json"
for name in "${asset_names[@]}"; do
  api "repos/$expected_repository/releases/$expected_release_id" > "$work/current.json"; assert_release "$work/current.json"; assert_no_unexpected_assets "$work/current.json"
  if jq -e --arg n "$name" 'any(.assets[]; .name==$n)' "$work/current.json" >/dev/null; then metadata_matches "$work/current.json" "$name" "$work/assets/$name" || die "existing asset $name does not exactly match"; continue; fi
  encoded="$(jq -rn --arg n "$name" '$n|@uri')"
  endpoint="https://uploads.github.com/repos/$expected_repository/releases/$expected_release_id/assets?name=$encoded"
  if ! api --method POST "$endpoint" -H 'Content-Type: application/octet-stream' --input "$work/assets/$name" > "$work/upload.json"; then
    reconcile_ambiguous_upload "$name" "$work/assets/$name" || die "ambiguous upload for $name was not reconciled"
    continue
  fi
  size="$(wc -c < "$work/assets/$name"|tr -d '[:space:]')"; digest="sha256:$(sha256sum < "$work/assets/$name"|awk '{print $1}')"
  jq -e --arg n "$name" --argjson s "$size" --arg d "$digest" '(.id|type)=="number" and .id>0 and .name==$n and .state=="uploaded" and .content_type=="application/octet-stream" and .size==$s and .digest==$d' "$work/upload.json" >/dev/null || die "upload response for $name is not exact"
done
api "repos/$expected_repository/releases/$expected_release_id" > "$work/final.json"; api "repos/$expected_repository/releases/latest" > "$work/latest.json"
assert_release "$work/final.json"; assert_latest; assert_no_unexpected_assets "$work/final.json"
[[ "$(jq '.assets|length' "$work/final.json")" == 14 ]] || die "final asset count is not 14"
for name in "${asset_names[@]}"; do metadata_matches "$work/final.json" "$name" "$work/assets/$name" || die "final asset $name mismatch"; done
