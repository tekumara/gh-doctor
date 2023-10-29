package cmd

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestUpdateSshConfig(t *testing.T) {

	tests := []struct {
		name              string
		sshConfig         string
		keyFile           string
		hostname          string
		expectedSshConfig string
	}{
		{
			name:              "CreateNewSshConfig",
			sshConfig:         "",
			keyFile:           "id_rsa",
			hostname:          "github.com",
			expectedSshConfig: "Host github.com\n  AddKeysToAgent yes\n  UseKeychain yes\n  IdentityFile id_rsa\n",
		},
		{
			name:              "AddHostToExistingSshConfig",
			sshConfig:         "Host foo.bar\n  IdentityFile top_secret\n",
			keyFile:           "id_rsa",
			hostname:          "github.com",
			expectedSshConfig: "Host foo.bar\n  IdentityFile top_secret\n\nHost github.com\n  AddKeysToAgent yes\n  UseKeychain yes\n  IdentityFile id_rsa\n",
		},
		{
			name:              "AlreadyExistsNoOp",
			sshConfig:         "Host github.com\n  IdentityFile id_rsa\n",
			keyFile:           "id_rsa",
			hostname:          "github.com",
			expectedSshConfig: "Host github.com\n  IdentityFile id_rsa\n",
		},
		{
			name: "ExistingHostUpdateIdentityFile",
			// existing ssh config is larger than the new one to test truncate
			sshConfig:         "Host github.com\n  IdentityFile yeolde.key\n",
			keyFile:           "new.key",
			hostname:          "github.com",
			expectedSshConfig: "Host github.com\n  IdentityFile new.key\n",
		},
		{
			name:      "ExistingHostUpdateAddIdentityFileBetweenHosts",
			sshConfig: "Host github.com\n  AddKeysToAgent yes\n\nHost foo.bar\n",
			keyFile:   "id_rsa",
			hostname:  "github.com",
			// NB: IdentityFile isn't indented see https://github.com/kevinburke/ssh_config/issues/12
			expectedSshConfig: "Host github.com\nIdentityFile id_rsa\n  AddKeysToAgent yes\n\nHost foo.bar\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			// Create existing config if any
			var sshConfigPath string
			if test.sshConfig != "" {
				f, err := os.CreateTemp("", "sshconfig")
				if err != nil {
					t.Fatal(err)
				}
				defer os.Remove(f.Name())

				if _, err := f.WriteString(test.sshConfig); err != nil {
					t.Fatal(err)
				}
				sshConfigPath = f.Name()
				f.Close()
			} else {
				sshConfigPath = fmt.Sprintf("%s/sshconfig.%d", os.TempDir(), time.Now().UnixMilli())
			}
			defer os.Remove(sshConfigPath)

			// Do update
			if err := updateSshConfig(sshConfigPath, test.keyFile, test.hostname); err != nil {
				t.Fatal(err)
			}

			// Check results
			content, err := os.ReadFile(sshConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(content) != test.expectedSshConfig {
				t.Errorf("\ngot  %q\nwant %q", string(content), test.expectedSshConfig)
			}

		})
	}

}
