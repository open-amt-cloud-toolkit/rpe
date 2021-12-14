/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package main

import (
	"log"
	rpe "rpe/internal"
)

func main() {

	//process flags
	flags := rpe.NewFlags()
	err := flags.ParseFlags()
	if err != nil {
		log.Fatalln(err.Error())
	}

	log.Println("DNS Suffix: ", flags.DNSSuffix, "RPE Port: ", flags.Port)
	log.Println("Remote Provisioning Extension (RPE) starting ...")

	error := rpe.SendAck(flags.DNSSuffix)
	if error != nil {
		log.Println("Error sending Ack packet: ", error)
	}
}
