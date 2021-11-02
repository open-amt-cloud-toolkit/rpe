/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rpe

import (
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewFlags(t *testing.T) {
	setupTest()
	flags := NewFlags()
	assert.NotNil(t, flags)
}

func TestNewFlagsWithEnv(t *testing.T) {
	setupTest()
	os.Setenv("PORT", "1234")
	os.Setenv("DNS_SUFFIX", "testDemo")
	flags := NewFlags()
	assert.Equal(t, "testDemo", flags.DNSSuffix)
	assert.Equal(t, 1234, flags.Port)
	os.Setenv("PORT", "")
	os.Setenv("DNS_SUFFIX", "")
}

func TestNewFlagsWithArgs(t *testing.T) {
	setupTest()
	flags := NewFlags()
	assert.Equal(t, "", flags.DNSSuffix)
	assert.Equal(t, 3050, flags.Port)
}

func TestLookupEnvOrString(t *testing.T) {
	os.Setenv("DNS_SUFFIX", "envdomain")
	actual := LookupEnvOrString("DNS_SUFFIX", "")
	assert.Equal(t, "envdomain", actual)
	os.Setenv("DNS_SUFFIX", "")
}

func TestLookupEnvOrInt(t *testing.T) {
	os.Setenv("PORT", "1234")
	actual := LookupEnvOrInt("PORT", 0)
	assert.Equal(t, 1234, actual)
	os.Setenv("PORT", "")
}

func TestLookupEnvOrIntError(t *testing.T) {
	os.Setenv("PORT", "12H34")
	actual := LookupEnvOrInt("PORT", 0)
	assert.Equal(t, 0, actual)
	os.Setenv("PORT", "")
}

func TestParseFlags(t *testing.T) {
	setupTest()
	os.Args = []string{"./rpe", "-d", "testDemo", "-p", "1234"}
	flags := NewFlags()
	err := flags.ParseFlags()
	assert.NoError(t, err)
	assert.Equal(t, "testDemo", flags.DNSSuffix)
	assert.Equal(t, 1234, flags.Port)
}
func TestParseFlagsMissingDNS(t *testing.T) {
	setupTest()
	os.Args = []string{"./rpe", "-p", "1234"}
	flags := NewFlags()
	err := flags.ParseFlags()
	assert.Error(t, err, "missing required flags")
	assert.Equal(t, "", flags.DNSSuffix)
	assert.Equal(t, 1234, flags.Port)
}
func TestUsage(t *testing.T) {
	setupTest()
	flags := NewFlags()
	result := flags.Usage()
	expected := "\nRemote Provisioning Extension (RPE) - used to set DNS Suffix for AMT on static IP or with out FQDN.\n\n"
	expected = expected + "Usage: rpe [OPTIONS]\n\n"
	expected = expected + "OPTIONS:\n"
	expected = expected + "  -p  int     port to listen on (override PORT env var)\n"
	expected = expected + "  -d  string  dns suffix to broadcast in option 15 of DHCP (override DNS_SUFFIX env var)\n\n"
	expected = expected + "              Example: rpe.exe -p 8005 -d demo.com\n\n"

	assert.Equal(t, expected, result)
}

func TestNewFlagsWithArgsOverEnv(t *testing.T) {
	setupTest()
	os.Setenv("PORT", "1234")
	os.Setenv("DNS_SUFFIX", "testDemo")
	os.Args = []string{"./rpe", "-d", "testDemoArg", "-p", "4321"}
	flags := NewFlags()
	err := flags.ParseFlags()
	assert.NoError(t, err)
	assert.Equal(t, "testDemoArg", flags.DNSSuffix)
	assert.Equal(t, 4321, flags.Port)
}

func setupTest() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
}
