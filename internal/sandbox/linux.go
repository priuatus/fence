package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Use-Tusk/fence/internal/config"
)

// LinuxBridge holds the socat bridge processes for Linux sandboxing (outbound).
type LinuxBridge struct {
	HTTPSocketPath  string
	SOCKSSocketPath string
	httpProcess     *exec.Cmd
	socksProcess    *exec.Cmd
	debug           bool
}

// ReverseBridge holds the socat bridge processes for inbound connections.
type ReverseBridge struct {
	Ports       []int
	SocketPaths []string // Unix socket paths for each port
	processes   []*exec.Cmd
	debug       bool
}

// NewLinuxBridge creates Unix socket bridges to the proxy servers.
// This allows sandboxed processes to communicate with the host's proxy (outbound).
func NewLinuxBridge(httpProxyPort, socksProxyPort int, debug bool) (*LinuxBridge, error) {
	if _, err := exec.LookPath("socat"); err != nil {
		return nil, fmt.Errorf("socat is required on Linux but not found: %w", err)
	}

	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("failed to generate socket ID: %w", err)
	}
	socketID := hex.EncodeToString(id)

	tmpDir := os.TempDir()
	httpSocketPath := filepath.Join(tmpDir, fmt.Sprintf("fence-http-%s.sock", socketID))
	socksSocketPath := filepath.Join(tmpDir, fmt.Sprintf("fence-socks-%s.sock", socketID))

	bridge := &LinuxBridge{
		HTTPSocketPath:  httpSocketPath,
		SOCKSSocketPath: socksSocketPath,
		debug:           debug,
	}

	// Start HTTP bridge: Unix socket -> TCP proxy
	httpArgs := []string{
		fmt.Sprintf("UNIX-LISTEN:%s,fork,reuseaddr", httpSocketPath),
		fmt.Sprintf("TCP:localhost:%d", httpProxyPort),
	}
	bridge.httpProcess = exec.Command("socat", httpArgs...) //nolint:gosec // args constructed from trusted input
	if debug {
		fmt.Fprintf(os.Stderr, "[fence:linux] Starting HTTP bridge: socat %s\n", strings.Join(httpArgs, " "))
	}
	if err := bridge.httpProcess.Start(); err != nil {
		return nil, fmt.Errorf("failed to start HTTP bridge: %w", err)
	}

	// Start SOCKS bridge: Unix socket -> TCP proxy
	socksArgs := []string{
		fmt.Sprintf("UNIX-LISTEN:%s,fork,reuseaddr", socksSocketPath),
		fmt.Sprintf("TCP:localhost:%d", socksProxyPort),
	}
	bridge.socksProcess = exec.Command("socat", socksArgs...) //nolint:gosec // args constructed from trusted input
	if debug {
		fmt.Fprintf(os.Stderr, "[fence:linux] Starting SOCKS bridge: socat %s\n", strings.Join(socksArgs, " "))
	}
	if err := bridge.socksProcess.Start(); err != nil {
		bridge.Cleanup()
		return nil, fmt.Errorf("failed to start SOCKS bridge: %w", err)
	}

	// Wait for sockets to be created, up to 5 seconds
	for range 50 {
		httpExists := fileExists(httpSocketPath)
		socksExists := fileExists(socksSocketPath)
		if httpExists && socksExists {
			if debug {
				fmt.Fprintf(os.Stderr, "[fence:linux] Bridges ready (HTTP: %s, SOCKS: %s)\n", httpSocketPath, socksSocketPath)
			}
			return bridge, nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	bridge.Cleanup()
	return nil, fmt.Errorf("timeout waiting for bridge sockets to be created")
}

// Cleanup stops the bridge processes and removes socket files.
func (b *LinuxBridge) Cleanup() {
	if b.httpProcess != nil && b.httpProcess.Process != nil {
		_ = b.httpProcess.Process.Kill()
		_ = b.httpProcess.Wait()
	}
	if b.socksProcess != nil && b.socksProcess.Process != nil {
		_ = b.socksProcess.Process.Kill()
		_ = b.socksProcess.Wait()
	}

	// Clean up socket files
	_ = os.Remove(b.HTTPSocketPath)
	_ = os.Remove(b.SOCKSSocketPath)

	if b.debug {
		fmt.Fprintf(os.Stderr, "[fence:linux] Bridges cleaned up\n")
	}
}

// NewReverseBridge creates Unix socket bridges for inbound connections.
// Host listens on ports, forwards to Unix sockets that go into the sandbox.
func NewReverseBridge(ports []int, debug bool) (*ReverseBridge, error) {
	if len(ports) == 0 {
		return nil, nil
	}

	if _, err := exec.LookPath("socat"); err != nil {
		return nil, fmt.Errorf("socat is required on Linux but not found: %w", err)
	}

	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("failed to generate socket ID: %w", err)
	}
	socketID := hex.EncodeToString(id)

	tmpDir := os.TempDir()
	bridge := &ReverseBridge{
		Ports: ports,
		debug: debug,
	}

	for _, port := range ports {
		socketPath := filepath.Join(tmpDir, fmt.Sprintf("fence-rev-%d-%s.sock", port, socketID))
		bridge.SocketPaths = append(bridge.SocketPaths, socketPath)

		// Start reverse bridge: TCP listen on host port -> Unix socket
		// The sandbox will create the Unix socket with UNIX-LISTEN
		// We use retry to wait for the socket to be created by the sandbox
		args := []string{
			fmt.Sprintf("TCP-LISTEN:%d,fork,reuseaddr", port),
			fmt.Sprintf("UNIX-CONNECT:%s,retry=50,interval=0.1", socketPath),
		}
		proc := exec.Command("socat", args...) //nolint:gosec // args constructed from trusted input
		if debug {
			fmt.Fprintf(os.Stderr, "[fence:linux] Starting reverse bridge for port %d: socat %s\n", port, strings.Join(args, " "))
		}
		if err := proc.Start(); err != nil {
			bridge.Cleanup()
			return nil, fmt.Errorf("failed to start reverse bridge for port %d: %w", port, err)
		}
		bridge.processes = append(bridge.processes, proc)
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[fence:linux] Reverse bridges ready for ports: %v\n", ports)
	}

	return bridge, nil
}

// Cleanup stops the reverse bridge processes and removes socket files.
func (b *ReverseBridge) Cleanup() {
	for _, proc := range b.processes {
		if proc != nil && proc.Process != nil {
			_ = proc.Process.Kill()
			_ = proc.Wait()
		}
	}

	// Clean up socket files
	for _, socketPath := range b.SocketPaths {
		_ = os.Remove(socketPath)
	}

	if b.debug {
		fmt.Fprintf(os.Stderr, "[fence:linux] Reverse bridges cleaned up\n")
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// getMandatoryDenyPaths returns concrete paths (not globs) that must be protected.
// This expands the glob patterns from GetMandatoryDenyPatterns into real paths.
func getMandatoryDenyPaths(cwd string) []string {
	var paths []string

	// Dangerous files in cwd
	for _, f := range DangerousFiles {
		p := filepath.Join(cwd, f)
		paths = append(paths, p)
	}

	// Dangerous directories in cwd
	for _, d := range DangerousDirectories {
		p := filepath.Join(cwd, d)
		paths = append(paths, p)
	}

	// Git hooks in cwd
	paths = append(paths, filepath.Join(cwd, ".git/hooks"))

	// Git config in cwd
	paths = append(paths, filepath.Join(cwd, ".git/config"))

	// Also protect home directory dangerous files
	home, err := os.UserHomeDir()
	if err == nil {
		for _, f := range DangerousFiles {
			p := filepath.Join(home, f)
			paths = append(paths, p)
		}
	}

	return paths
}

// WrapCommandLinux wraps a command with Linux bubblewrap sandbox.
func WrapCommandLinux(cfg *config.Config, command string, bridge *LinuxBridge, reverseBridge *ReverseBridge, debug bool) (string, error) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		return "", fmt.Errorf("bubblewrap (bwrap) is required on Linux but not found: %w", err)
	}

	shell := "bash"
	shellPath, err := exec.LookPath(shell)
	if err != nil {
		return "", fmt.Errorf("shell %q not found: %w", shell, err)
	}

	cwd, _ := os.Getwd()

	// Build bwrap args with filesystem restrictions
	bwrapArgs := []string{
		"bwrap",
		"--new-session",
		"--die-with-parent",
		"--unshare-net", // Network namespace isolation
		"--unshare-pid", // PID namespace isolation
	}

	// Start with read-only root filesystem (default deny writes)
	bwrapArgs = append(bwrapArgs, "--ro-bind", "/", "/")

	// Mount special filesystems
	bwrapArgs = append(bwrapArgs, "--dev", "/dev")
	bwrapArgs = append(bwrapArgs, "--proc", "/proc")

	// /tmp needs to be writable for many programs
	bwrapArgs = append(bwrapArgs, "--tmpfs", "/tmp")

	writablePaths := make(map[string]bool)

	// Add default write paths (system paths needed for operation)
	for _, p := range GetDefaultWritePaths() {
		// Skip /dev paths (handled by --dev) and /tmp paths (handled by --tmpfs)
		if strings.HasPrefix(p, "/dev/") || strings.HasPrefix(p, "/tmp/") || strings.HasPrefix(p, "/private/tmp/") {
			continue
		}
		writablePaths[p] = true
	}

	// Add user-specified allowWrite paths
	if cfg != nil && cfg.Filesystem.AllowWrite != nil {
		for _, p := range cfg.Filesystem.AllowWrite {
			normalized := NormalizePath(p)
			if !ContainsGlobChars(normalized) {
				writablePaths[normalized] = true
			}
		}
	}

	// Make writable paths actually writable (override read-only root)
	for p := range writablePaths {
		if fileExists(p) {
			bwrapArgs = append(bwrapArgs, "--bind", p, p)
		}
	}

	// Handle denyRead paths - hide them with tmpfs
	if cfg != nil && cfg.Filesystem.DenyRead != nil {
		for _, p := range cfg.Filesystem.DenyRead {
			normalized := NormalizePath(p)
			if !ContainsGlobChars(normalized) && fileExists(normalized) {
				bwrapArgs = append(bwrapArgs, "--tmpfs", normalized)
			}
		}
	}

	// Apply mandatory deny patterns (make dangerous files/dirs read-only)
	// This overrides any writable mounts for these paths
	mandatoryDeny := getMandatoryDenyPaths(cwd)
	for _, p := range mandatoryDeny {
		if fileExists(p) {
			bwrapArgs = append(bwrapArgs, "--ro-bind", p, p)
		}
	}

	// Handle explicit denyWrite paths (make them read-only)
	if cfg != nil && cfg.Filesystem.DenyWrite != nil {
		for _, p := range cfg.Filesystem.DenyWrite {
			normalized := NormalizePath(p)
			if !ContainsGlobChars(normalized) && fileExists(normalized) {
				bwrapArgs = append(bwrapArgs, "--ro-bind", normalized, normalized)
			}
		}
	}

	// Bind the outbound Unix sockets into the sandbox (need to be writable)
	if bridge != nil {
		bwrapArgs = append(bwrapArgs,
			"--bind", bridge.HTTPSocketPath, bridge.HTTPSocketPath,
			"--bind", bridge.SOCKSSocketPath, bridge.SOCKSSocketPath,
		)
	}

	// Bind reverse socket directory if needed (sockets created inside sandbox)
	if reverseBridge != nil && len(reverseBridge.SocketPaths) > 0 {
		// Get the temp directory containing the reverse sockets
		tmpDir := filepath.Dir(reverseBridge.SocketPaths[0])
		bwrapArgs = append(bwrapArgs, "--bind", tmpDir, tmpDir)
	}

	bwrapArgs = append(bwrapArgs, "--", shellPath, "-c")

	// Build the inner command that sets up socat listeners and runs the user command
	var innerScript strings.Builder

	if bridge != nil {
		// Set up outbound socat listeners inside the sandbox
		innerScript.WriteString(fmt.Sprintf(`
# Start HTTP proxy listener (port 3128 -> Unix socket -> host HTTP proxy)
socat TCP-LISTEN:3128,fork,reuseaddr UNIX-CONNECT:%s >/dev/null 2>&1 &
HTTP_PID=$!

# Start SOCKS proxy listener (port 1080 -> Unix socket -> host SOCKS proxy)
socat TCP-LISTEN:1080,fork,reuseaddr UNIX-CONNECT:%s >/dev/null 2>&1 &
SOCKS_PID=$!

# Set proxy environment variables
export HTTP_PROXY=http://127.0.0.1:3128
export HTTPS_PROXY=http://127.0.0.1:3128
export http_proxy=http://127.0.0.1:3128
export https_proxy=http://127.0.0.1:3128
export ALL_PROXY=socks5h://127.0.0.1:1080
export all_proxy=socks5h://127.0.0.1:1080
export NO_PROXY=localhost,127.0.0.1
export no_proxy=localhost,127.0.0.1
export FENCE_SANDBOX=1

`, bridge.HTTPSocketPath, bridge.SOCKSSocketPath))
	}

	// Set up reverse (inbound) socat listeners inside the sandbox
	if reverseBridge != nil && len(reverseBridge.Ports) > 0 {
		innerScript.WriteString("\n# Start reverse bridge listeners for inbound connections\n")
		for i, port := range reverseBridge.Ports {
			socketPath := reverseBridge.SocketPaths[i]
			// Listen on Unix socket, forward to localhost:port inside the sandbox
			innerScript.WriteString(fmt.Sprintf(
				"socat UNIX-LISTEN:%s,fork,reuseaddr TCP:127.0.0.1:%d >/dev/null 2>&1 &\n",
				socketPath, port,
			))
			innerScript.WriteString(fmt.Sprintf("REV_%d_PID=$!\n", port))
		}
		innerScript.WriteString("\n")
	}

	// Add cleanup function
	innerScript.WriteString(`
# Cleanup function
cleanup() {
    jobs -p | xargs -r kill 2>/dev/null
}
trap cleanup EXIT

# Small delay to ensure socat listeners are ready
sleep 0.1

# Run the user command
`)
	innerScript.WriteString(command)
	innerScript.WriteString("\n")

	bwrapArgs = append(bwrapArgs, innerScript.String())

	if debug {
		features := []string{"network filtering", "filesystem restrictions"}
		if reverseBridge != nil && len(reverseBridge.Ports) > 0 {
			features = append(features, fmt.Sprintf("inbound ports: %v", reverseBridge.Ports))
		}
		fmt.Fprintf(os.Stderr, "[fence:linux] Wrapping command with bwrap (%s)\n", strings.Join(features, ", "))
	}

	return ShellQuote(bwrapArgs), nil
}
