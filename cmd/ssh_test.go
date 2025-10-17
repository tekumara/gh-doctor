package cmd

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestUpdateSshConfig(t *testing.T) {
	// Save original osName and defer restoration
	originalOsName := osName
	defer func() { osName = originalOsName }()

	tests := []struct {
		name              string
		osName            string
		sshConfig         string
		keyFile           string
		hostname          string
		expectedSSHConfig string
	}{
		{
			name:              "CreateNewSshConfigMac",
			osName:            "darwin",
			sshConfig:         "",
			keyFile:           "id_rsa",
			hostname:          "github.com",
			expectedSSHConfig: "Host github.com\n  AddKeysToAgent yes\n  UseKeychain yes\n  IdentityFile id_rsa\n",
		},
		{
			name:              "CreateNewSshConfigNonDarwin",
			osName:            "windows",
			sshConfig:         "",
			keyFile:           "id_rsa",
			hostname:          "github.com",
			expectedSSHConfig: "Host github.com\n  AddKeysToAgent yes\n  IdentityFile id_rsa\n",
		},
		{
			name:              "AddHostToExistingSshConfigMac",
			osName:            "darwin",
			sshConfig:         "Host foo.bar\n  IdentityFile top_secret\n",
			keyFile:           "id_rsa",
			hostname:          "github.com",
			expectedSSHConfig: "Host foo.bar\n  IdentityFile top_secret\n\nHost github.com\n  AddKeysToAgent yes\n  UseKeychain yes\n  IdentityFile id_rsa\n",
		},
		{
			name:              "AddHostToExistingSshConfigNonDarwin",
			osName:            "linux",
			sshConfig:         "Host foo.bar\n  IdentityFile top_secret\n",
			keyFile:           "id_rsa",
			hostname:          "github.com",
			expectedSSHConfig: "Host foo.bar\n  IdentityFile top_secret\n\nHost github.com\n  AddKeysToAgent yes\n  IdentityFile id_rsa\n",
		},
		{
			name:              "AlreadyExistsNoOp",
			osName:            "darwin",
			sshConfig:         "Host github.com\n  IdentityFile id_rsa\n",
			keyFile:           "id_rsa",
			hostname:          "github.com",
			expectedSSHConfig: "Host github.com\n  IdentityFile id_rsa\n",
		},
		{
			name: "ExistingHostUpdateIdentityFile",
			// existing ssh config is larger than the new one to test truncate
			osName:            "darwin",
			sshConfig:         "Host github.com\n  IdentityFile yeolde.key\n",
			keyFile:           "new.key",
			hostname:          "github.com",
			expectedSSHConfig: "Host github.com\n  IdentityFile new.key\n",
		},
		{
			name:      "ExistingHostUpdateAddIdentityFileBetweenHosts",
			sshConfig: "Host github.com\n  AddKeysToAgent yes\n\nHost foo.bar\n",
			keyFile:   "id_rsa",
			hostname:  "github.com",
			// NB: IdentityFile isn't indented see https://github.com/kevinburke/ssh_config/issues/12
			expectedSSHConfig: "Host github.com\nIdentityFile id_rsa\n  AddKeysToAgent yes\n\nHost foo.bar\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			osName = test.osName

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
			if err := updateSSHConfig(sshConfigPath, test.keyFile, test.hostname); err != nil {
				t.Fatal(err)
			}

			// Check results
			content, err := os.ReadFile(sshConfigPath)
			if err != nil {
				t.Fatal(err)
			}

			if string(content) != test.expectedSSHConfig {
				t.Errorf("\ngot  %q\nwant %q", string(content), test.expectedSSHConfig)
			}
		})
	}

}
