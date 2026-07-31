//go:build windows && compiled_cli_contract

package update

import (
	"fmt"
	"os"
	"path/filepath"
)

const windowsCompiledContractStageLinkEnv = "SSM_TEST_COMPILED_WINDOWS_STAGE_LINK"

func init() {
	alias := os.Getenv(windowsCompiledContractStageLinkEnv)
	if alias == "" {
		return
	}
	originalHook := windowsReplacementTestHook
	linked := false
	windowsReplacementTestHook = func(phase string) error {
		if originalHook != nil {
			if err := originalHook(phase); err != nil {
				return err
			}
		}
		if phase != windowsReplacementPhaseStageRenameGap || linked {
			return nil
		}
		executable, err := os.Executable()
		if err != nil {
			return fmt.Errorf("resolve compiled-contract executable: %w", err)
		}
		executable, err = filepath.EvalSymlinks(executable)
		if err != nil {
			return fmt.Errorf("resolve compiled-contract executable links: %w", err)
		}
		pattern := filepath.Join(
			filepath.Dir(executable),
			"."+filepath.Base(executable)+".*.new",
		)
		stages, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("find compiled-contract replacement stage: %w", err)
		}
		if len(stages) != 1 {
			return fmt.Errorf(
				"compiled-contract replacement stage count is %d, want 1",
				len(stages),
			)
		}
		if err := os.Link(stages[0], alias); err != nil {
			return fmt.Errorf("create compiled-contract late stage link: %w", err)
		}
		linked = true
		return nil
	}
}
