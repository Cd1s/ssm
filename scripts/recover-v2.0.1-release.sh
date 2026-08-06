#!/usr/bin/env bash
set -euo pipefail

readonly expected_repository="Cd1s/ssm"
readonly expected_tag="v2.0.1"
readonly expected_source_sha="379ce2d91825a4d651117e13ec59d9c9baa686f5"
readonly expected_release_id="365897243"
readonly expected_run_id="31057964128"
readonly required_latest_id="364882535"
readonly required_latest_tag="v2.0.0"
readonly -a artifact_names=(ssm-linux-amd64 ssm-linux-arm64 ssm-darwin-amd64 ssm-darwin-arm64 ssm-windows-amd64.exe ssm-windows-arm64.exe)
readonly -a artifact_ids=(8951330070 8951337800 8951339181 8951335502 8951336933 8951336159)
readonly -a artifact_digests=(sha256:32da0ec46f51df83dcf534f9b2d7bbdd2a870b59d5ccc9399fcda10001428b6e sha256:7b44b39067a145d79c2cf302b1d3e6164d5e9982ef2afa41627f6d261e1a9d7d sha256:b388f87c932b2bad588fe3ca6e2f3144dbee0765e79e6ec663bdbe8ecbc893ab sha256:45dc3a18b03dbd71512dac1a3f7be4d38111a998681871e9168a9766272fcaf0 sha256:a05ef33de51e6b243aa830eb3d2ca4e8629f8cf9552dafe15a940f94010004fa sha256:048f338f6f05c49ad73c04c99c1594adca46e8897df4ba9978c94d939ce94ea0)
readonly -a asset_names=(ssm-linux-amd64 ssm-linux-arm64 ssm-darwin-amd64 ssm-darwin-arm64 ssm-windows-amd64.exe ssm-windows-arm64.exe ssm-linux-amd64.sigstore.json ssm-linux-arm64.sigstore.json ssm-darwin-amd64.sigstore.json ssm-darwin-arm64.sigstore.json ssm-windows-amd64.exe.sigstore.json ssm-windows-arm64.exe.sigstore.json install.sh checksums.txt)

die() { printf '%s\n' "$*" >&2; exit 1; }
api() { gh api "$@"; }

[[ "${GITHUB_REPOSITORY:-}" == "$expected_repository" && "${EXPECTED_REPOSITORY:-}" == "$expected_repository" ]] || die "repository binding mismatch"
[[ "${GITHUB_REF:-}" == "refs/heads/agent-headless-sync" ]] || die "recovery branch binding mismatch"
[[ "${EXPECTED_SOURCE_SHA:-}" == "$expected_source_sha" && "${EXPECTED_RELEASE_ID:-}" == "$expected_release_id" && "${EXPECTED_SOURCE_RUN_ID:-}" == "$expected_run_id" ]] || die "workflow binding mismatch"
[[ "${REQUIRED_LATEST_ID:-}" == "$required_latest_id" && "${REQUIRED_LATEST_TAG:-}" == "$required_latest_tag" ]] || die "latest binding mismatch"
[[ -n "${GH_TOKEN:-}" && -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" ]] || die "authenticated runner context required"
work="$(mktemp -d "$RUNNER_TEMP/ssm-v2-recovery.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

api --paginate "repos/$expected_repository/releases?per_page=100" > "$work/releases.pages" || die "unable to read exhaustive Release inventory"
jq -e -s '
  length>0 and
  all(.[];
    type=="array" and
    all(.[];
      type=="object" and
      (.id|type)=="number" and .id>0 and (.id|floor)==.id and
      (.tag_name|type)=="string" and .tag_name!=""
    )
  )
' "$work/releases.pages" >/dev/null || die "exhaustive Release inventory is malformed"
jq -e -s --arg tag "$expected_tag" --argjson id "$expected_release_id" '
  ([.[][]|.id]|length)==([.[][]|.id]|unique|length) and
  ([.[][]|.tag_name]|length)==([.[][]|.tag_name]|unique|length) and
  ([.[][]|select(.tag_name==$tag)]|length)==1 and
  ([.[][]|select(.id==$id)]|length)==1 and
  ([.[][]|select(.tag_name==$tag and .id==$id)]|length)==1
' "$work/releases.pages" >/dev/null || die "exhaustive Release inventory is ambiguous"

api "repos/$expected_repository/releases/$expected_release_id" > "$work/release.json" || die "unable to read fixed Release ID"
api "repos/$expected_repository/releases/latest" > "$work/latest.json" || die "unable to read GitHub latest"
api "repos/$expected_repository/contents/RELEASE_NOTES.md?ref=$expected_source_sha" > "$work/release-notes-content.json" || die "unable to read tagged release notes"
jq -e '.type=="file" and .encoding=="base64" and (.size|type)=="number" and .size>0 and (.content|type)=="string" and (.content|length)>0' "$work/release-notes-content.json" >/dev/null || die "tagged release notes content is invalid"
jq -r .content "$work/release-notes-content.json" | tr -d '\r\n' | base64 -d > "$work/RELEASE_NOTES.md"
[[ -s "$work/RELEASE_NOTES.md" && "$(wc -c < "$work/RELEASE_NOTES.md" | tr -d '[:space:]')" == "$(jq -r .size "$work/release-notes-content.json")" ]] || die "tagged release notes materialization is invalid"
awk -v h="## $expected_tag" '$0==h{f=1;next} f&&/^## /{exit} f{print} END{if(!f)exit 1}' "$work/RELEASE_NOTES.md" > "$work/body.md"
grep -q '[^[:space:]]' "$work/body.md" || die "tagged Release body is empty"
release_metadata_matches() {
  jq -e --argjson id "$expected_release_id" --arg tag "$expected_tag" --arg sha "$expected_source_sha" --rawfile body "$work/body.md" '
    type=="object" and .id==$id and .tag_name==$tag and .target_commitish==$sha and .name==$tag and .body==$body and
    .draft==false and .prerelease==false and (.assets|type)=="array"
  ' "$1" >/dev/null
}
assert_release() {
  release_metadata_matches "$1" || die "Release metadata binding failed"
}
assert_latest() { jq -e --argjson id "$required_latest_id" --arg tag "$required_latest_tag" 'type=="object" and .id==$id and .tag_name==$tag and .draft==false and .prerelease==false' "$work/latest.json" >/dev/null || die "GitHub latest binding failed"; }
release_metadata_matches "$work/release.json" && [[ "$(jq '.assets|length' "$work/release.json")" == 0 ]] || die "initial Release binding failed"
assert_latest

api "repos/$expected_repository/git/ref/tags/$expected_tag" > "$work/tag.json" || die "unable to read exact tag ref"
jq -e --arg ref "refs/tags/$expected_tag" --arg sha "$expected_source_sha" '
  type=="object" and .ref==$ref and .object.type=="commit" and .object.sha==$sha
' "$work/tag.json" >/dev/null || die "tag binding failed"

api "repos/$expected_repository/actions/runs/$expected_run_id" > "$work/run.json" || die "unable to read source run"
api --paginate "repos/$expected_repository/actions/runs/$expected_run_id/jobs?per_page=100" > "$work/jobs.pages" || die "unable to read source jobs"
jq -e --arg sha "$expected_source_sha" '.id==31057964128 and .event=="push" and .status=="completed" and .conclusion=="failure" and .head_branch=="v2.0.1" and .head_sha==$sha and .path==".github/workflows/release.yml" and .name=="Release" and .run_attempt==1' "$work/run.json" >/dev/null || die "source run identity mismatch"
jq -e -s '
  length>0 and
  all(.[];
    type=="object" and (keys|sort)==["jobs","total_count"] and
    (.total_count|type)=="number" and .total_count>=0 and (.total_count|floor)==.total_count and
    (.jobs|type)=="array" and all(.jobs[]; (.name|type)=="string" and (.conclusion|type)=="string")
  ) and
  ([.[].total_count]|unique|length)==1 and
  ([.[].total_count][0])==([.[].jobs[]]|length) and
  ([.[].jobs[]|{name,conclusion}]|sort_by(.name))==([
    {name:"preflight",conclusion:"success"},
    {name:"publish",conclusion:"failure"},
    {name:"build (linux, amd64, ssm-linux-amd64)",conclusion:"success"},
    {name:"build (linux, arm64, ssm-linux-arm64)",conclusion:"success"},
    {name:"build (darwin, amd64, ssm-darwin-amd64)",conclusion:"success"},
    {name:"build (darwin, arm64, ssm-darwin-arm64)",conclusion:"success"},
    {name:"build (windows, amd64, ssm-windows-amd64.exe)",conclusion:"success"},
    {name:"build (windows, arm64, ssm-windows-arm64.exe)",conclusion:"success"}
  ]|sort_by(.name))
' "$work/jobs.pages" >/dev/null || die "source job conclusions are not exact"

api --paginate "repos/$expected_repository/actions/runs/$expected_run_id/artifacts?per_page=100" > "$work/artifacts.pages" || die "unable to read source artifacts"
expected_artifacts="$(for i in "${!artifact_names[@]}"; do jq -n --argjson id "${artifact_ids[$i]}" --arg name "${artifact_names[$i]}" --arg digest "${artifact_digests[$i]}" '{id:$id,name:$name,digest:$digest}'; done | jq -s 'sort_by(.id)')"
jq -e -s '
  length>0 and
  all(.[];
    type=="object" and (keys|sort)==["artifacts","total_count"] and
    (.total_count|type)=="number" and .total_count>=0 and (.total_count|floor)==.total_count and
    (.artifacts|type)=="array"
  ) and
  ([.[].total_count]|unique|length)==1 and
  ([.[].total_count][0])==([.[].artifacts[]]|length)
' "$work/artifacts.pages" >/dev/null || die "workflow artifact inventory is malformed"
jq -e -s --argjson expected "$expected_artifacts" '
  [.[].artifacts[]] as $artifacts |
  ($artifacts|length)==6 and
  all($artifacts[];
    (.id|type)=="number" and .id>0 and (.id|floor)==.id and
    (.name|type)=="string" and .name!="" and
    (.digest|type)=="string" and (.digest|test("^sha256:[0-9a-f]{64}$")) and
    .expired==false
  ) and
  ($artifacts|map(.id)|length)==($artifacts|map(.id)|unique|length) and
  ($artifacts|map(.name)|length)==($artifacts|map(.name)|unique|length) and
  ($artifacts|map(.digest)|length)==($artifacts|map(.digest)|unique|length) and
  ($artifacts|map({id,name,digest})|sort_by(.id))==$expected
' "$work/artifacts.pages" >/dev/null || die "workflow artifacts are missing, expired, duplicate, or extra"
mkdir "$work/assets"
for i in "${!artifact_names[@]}"; do
  archive="$work/${artifact_ids[$i]}.zip"
  api "repos/$expected_repository/actions/artifacts/${artifact_ids[$i]}/zip" > "$archive" || die "unable to download artifact ${artifact_ids[$i]}"
  actual_archive_digest="sha256:$(sha256sum "$archive" | awk '{print $1}')"
  [[ "$actual_archive_digest" == "${artifact_digests[$i]}" ]] || die "artifact ${artifact_ids[$i]} archive digest mismatch"
  expected_entries="$(printf '%s\n' "${artifact_names[$i]}" "${artifact_names[$i]}.sigstore.json" | LC_ALL=C sort)"
  actual_entries="$(unzip -Z1 "$archive" | LC_ALL=C sort)" || die "artifact ${artifact_ids[$i]} archive inventory is unreadable"
  [[ "$actual_entries" == "$expected_entries" ]] || die "artifact ${artifact_ids[$i]} has unexpected files"
  mkdir "$work/extract-$i"
  unzip -q "$archive" -d "$work/extract-$i" || die "artifact ${artifact_ids[$i]} extraction failed"
  [[ -f "$work/extract-$i/${artifact_names[$i]}" && ! -L "$work/extract-$i/${artifact_names[$i]}" &&
     -f "$work/extract-$i/${artifact_names[$i]}.sigstore.json" && ! -L "$work/extract-$i/${artifact_names[$i]}.sigstore.json" ]] ||
    die "artifact ${artifact_ids[$i]} extracted files are invalid"
  install -m 0600 "$work/extract-$i/${artifact_names[$i]}" "$work/assets/${artifact_names[$i]}"
  install -m 0600 "$work/extract-$i/${artifact_names[$i]}.sigstore.json" "$work/assets/${artifact_names[$i]}.sigstore.json"
done
api "repos/$expected_repository/contents/install.sh?ref=$expected_source_sha" > "$work/install-content.json" || die "unable to read tagged install.sh"
jq -e '.type=="file" and .encoding=="base64" and (.size|type)=="number" and .size>0 and (.content|type)=="string" and (.content|length)>0' "$work/install-content.json" >/dev/null || die "tagged install.sh content is invalid"
jq -r .content "$work/install-content.json" | tr -d '\r\n' | base64 -d > "$work/assets/install.sh"
[[ -s "$work/assets/install.sh" && ! -L "$work/assets/install.sh" && "$(wc -c < "$work/assets/install.sh" | tr -d '[:space:]')" == "$(jq -r .size "$work/install-content.json")" ]] || die "tagged install.sh materialized invalid"
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
  jq -e --argjson e "$expected" '(.assets|type)=="array" and ([.assets[].name]|length)==([.assets[].name]|unique|length) and ([.assets[].name]-$e|length)==0' "$json" >/dev/null || die "Release contains duplicate or unexpected assets"
}
reconcile_ambiguous_upload() { api "repos/$expected_repository/releases/$expected_release_id" > "$work/reconcile.json" && assert_release "$work/reconcile.json" && assert_no_unexpected_assets "$work/reconcile.json" && metadata_matches "$work/reconcile.json" "$1" "$2"; }

assert_no_unexpected_assets "$work/release.json"
for name in "${asset_names[@]}"; do
  api "repos/$expected_repository/releases/$expected_release_id" > "$work/current.json" || die "unable to read fixed Release before $name upload"
  assert_release "$work/current.json"; assert_no_unexpected_assets "$work/current.json"
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
api "repos/$expected_repository/releases/$expected_release_id" > "$work/final.json" || die "unable to read final fixed Release"
api "repos/$expected_repository/releases/latest" > "$work/latest.json" || die "unable to read final GitHub latest"
assert_release "$work/final.json"; assert_latest; assert_no_unexpected_assets "$work/final.json"
[[ "$(jq '.assets|length' "$work/final.json")" == 14 ]] || die "final asset count is not 14"
for name in "${asset_names[@]}"; do metadata_matches "$work/final.json" "$name" "$work/assets/$name" || die "final asset $name mismatch"; done
