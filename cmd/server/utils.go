package main

import (
	"os"
	"strings"
)

func LoadEnv() {
	content, err := os.ReadFile(".env")
	if err != nil {
		panic("Failed to read .env file")
	}
	variables := strings.SplitSeq(string(content), "\n")
	for variable := range variables {
		keyValue := strings.Split(variable, "=")
		os.Setenv(keyValue[0], keyValue[1])
	}
}
