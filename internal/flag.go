/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rpe

import (
	"errors"
	"flag"
	"log"
	"os"
	"strconv"
)

type Flags struct {
	DNSSuffix string
	Port      int
}

func NewFlags() *Flags {
	flags := &Flags{}

	flag.IntVar(&flags.Port, "p", LookupEnvOrInt("PORT", 3050), "Port to run RPE service")
	flag.StringVar(&flags.DNSSuffix, "d", LookupEnvOrString("DNS_SUFFIX", ""), "DNS Suffix")

	return flags
}

func (f *Flags) ParseFlags() error {
	flag.Parse()

	if f.DNSSuffix == "" {
		log.Println("-d flag is required and cannot be empty")
		log.Println(f.Usage())
		return errors.New("missing required flags")
	}
	return nil
}
func (f *Flags) Usage() string {
	usage := "\nRemote Provisioning Extension (RPE) - used to set DNS Suffix for AMT on static IP or with out FQDN.\n\n"
	usage = usage + "Usage: rpe [OPTIONS]\n\n"
	usage = usage + "OPTIONS:\n"
	usage = usage + "  -p  int     port to listen on (override PORT env var)\n"
	usage = usage + "  -d  string  dns suffix to broadcast in option 15 of DHCP (override DNS_SUFFIX env var)\n\n"
	usage = usage + "              Example: rpe.exe -p 8005 -d demo.com\n\n"

	return usage
}

func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func LookupEnvOrInt(key string, defaultVal int) int {
	if val, ok := os.LookupEnv(key); ok {
		v, err := strconv.Atoi(val)
		if err != nil {
			log.Println(err.Error())
			return defaultVal
		}
		return v
	}
	return defaultVal
}
