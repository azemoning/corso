package banner

import "fmt"

// Logo returns the ASCII art logo for Corso
func Logo() string {
	return `   _____  ____  ______ ____  _____  
  / ____||  _ \|  ____/ __ \|  __ \ 
 | |     | |_) | |__ | |  | | |__) |
 | |     |  _ <|  __|| |  | |  _  / 
 | |____ | |_) | |___| |__| | | \ \ 
  \_____||____/|______\____/|_|  \_\`
}

// Tagline returns the project tagline
func Tagline() string {
	return "eBPF Guard for Kubernetes"
}

// Version returns the version banner
func Version(version, commit string) string {
	return fmt.Sprintf("Corso %s (commit: %s)", version, commit)
}

// Full returns the complete banner with logo and tagline
func Full() string {
	return fmt.Sprintf("%s\n  %s", Logo(), Tagline())
}

// Short returns a compact banner for output
func Short() string {
	return "Corso - eBPF Guard for Kubernetes"
}
