package main

import (
	"fmt"

	. "github.com/op-se/go-ldap-client"
)

func main() {

	fmt.Println("hi")

	s := FormatGroup("CN=HQ普噗,OU=HQ豪吃,OU=OPXXX,DC=xxxxx,DC=com,DC=tw")

	fmt.Println(s)

}
