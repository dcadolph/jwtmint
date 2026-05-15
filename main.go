// jwtsmith is a CLI for generating, signing, decoding, verifying, and refreshing JWTs.
package main

import (
	"github.com/dcadolph/jwtsmith/cmd"
)

// main hands off to cmd.Execute, which sets the process exit code.
func main() {
	cmd.Execute()
}
