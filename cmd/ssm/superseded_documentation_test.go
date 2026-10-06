package main

import (
	"strings"
	"testing"
)

func TestDocumentationSupersededRollbackAndBackupRestore(t *testing.T) {
	for _, document := range []struct {
		path       string
		rowWords   []string
		restoreOps []string
	}{
		{
			path:       "docs/reference.md",
			rowWords:   []string{"already replaced", "rollback", "backup restore", "pull --adopt-remote"},
			restoreOps: []string{"restores the sync server from backup", "each affected machine", "sshctl pull --adopt-remote <sha> --yes", "one machine can adopt", "publish a new version"},
		},
		{
			path:       "docs/reference.zh-CN.md",
			rowWords:   []string{"已取代", "回滚", "备份恢复", "pull --adopt-remote"},
			restoreOps: []string{"管理员从备份恢复同步服务端后", "每台受影响的机器", "sshctl pull --adopt-remote <sha> --yes", "由一台机器采用", "重新发布一个新版本"},
		},
	} {
		t.Run(document.path, func(t *testing.T) {
			text := readContractDocument(t, document.path)
			var conflictRow string
			for _, line := range strings.Split(text, "\n") {
				if strings.HasPrefix(line, "| `sync_conflict` |") {
					conflictRow = line
					break
				}
			}
			for _, fragment := range document.rowWords {
				if !strings.Contains(conflictRow, fragment) {
					t.Errorf("sync_conflict row omits %q", fragment)
				}
			}
			for _, fragment := range document.restoreOps {
				if !strings.Contains(text, fragment) {
					t.Errorf("backup restore guidance omits %q", fragment)
				}
			}
		})
	}
}
