package tpm

import (
	"io/ioutil"
	"os"
	"testing"

	"gotest.tools/v3/assert"
)

func TestIsTPMKeyFile(t *testing.T) {
	tests := []struct {
		filedata string
		expected bool
	}{
		{
			filedata: `{"tpm_interface":"/dev/tpmrm0", "tpm_key_handle":"0x817fffff"}`,
			expected: true,
		}, {
			filedata: `{"tpm_interface":"/dev/tpmrm0", "tpm_key_handle":"0x817fffff", "tpm_key_password":"abcd"}`,
			expected: true,
		}, {
			filedata: `-----BEGIN EC PRIVATE KEY-----
			MHQCAQEEIHC+KAKNWMKtqu7TVHz5MW4D1jSUlv5xwxcZg9djqWr+oAcGBSuBBAAK
			oUQDQgAEycRkh5nLyq4J8f1Q8OuvcvQlOK5HmM24LPGXDj1VJsEni6WQKZOHa5oe
			usQ7lno4YUrBjiDXQeM+yDph0LzhJA==
			-----END EC PRIVATE KEY-----
			`,
			expected: false,
		}, {
			filedata: `-----BEGIN EC PRIVATE KEY-----
			Proc-Type: 4,ENCRYPTED
			DEK-Info: AES-256-CBC,9279698B0E6A113707D3AF05B9D70273
			
			o89EJkiRJtoqQNetnQSAtS5Q820Wqq12g8+J2PatrtYdly50yQ8mmT5L30cLyWrN
			vMW/O7/EgpgwqhX5yDn0IVHv0F2yc2THemNQnG9JnlU7cPdHZ2QAHCeKzDXOaiKj
			S71xux8vKtJl37Ss5NPlYW75sRFQB8x3S9xghQTEYFw=
			-----END EC PRIVATE KEY-----
			`,
			expected: false,
		}, {
			filedata: `{"tpm_interface":"/dev/tpmrm0", "tpm_key_handle":"0x817fffff"`,
			expected: false,
		}, {
			filedata: `{"test: abcd"}`,
			expected: false,
		}, {
			filedata: ``,
			expected: false,
		},
	}
	for _, test := range tests {
		data := []byte(test.filedata)
		filename := "testfile"
		err := ioutil.WriteFile(filename, data, 0644)
		assert.NilError(t, err)
		defer os.Remove(filename)
		actual := IsTPMKeyFile(filename)
		assert.Equal(t, test.expected, actual)
	}
}
