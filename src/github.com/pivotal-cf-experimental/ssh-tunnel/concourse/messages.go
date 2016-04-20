package main

type envRequest struct {
}

type execRequest struct {
	Command string
}

type shellRequest struct {
}

type tcpipForwardRequest struct {
	BindIP   string
	BindPort uint32
}

type tcpipForwardResponse struct {
	BoundPort uint32
}

type forwardTCPIPChannelRequest struct {
	ForwardIP   string
	ForwardPort uint32
	OriginIP    string
	OriginPort  uint32
}

// // Request types used in sessions - RFC 4254 6.X
// const (
// 	SessionRequest               = "session"       // RFC 4254 6.1
// 	PTYRequest                   = "pty-req"       // RFC 4254 6.2
// 	X11Request                   = "x11-req"       // RFC 4254 6.3.1
// 	X11ChannelRequest            = "x11"           // RFC 4254 6.3.2
// 	EnvironmentRequest           = "env"           // RFC 4254 6.4
// 	ShellRequest                 = "shell"         // RFC 4254 6.5
// 	ExecRequest                  = "exec"          // RFC 4254 6.5
// 	SubsystemRequest             = "subsystem"     // RFC 4254 6.5
// 	WindowDimensionChangeRequest = "window-change" // RFC 4254 6.7
// 	FlowControlRequest           = "xon-off"       // RFC 4254 6.8
// 	SignalRequest                = "signal"        // RFC 4254 6.9
// 	ExitStatusRequest            = "exit-status"   // RFC 4254 6.10
// 	ExitSignalRequest            = "exit-signal"   // RFC 4254 6.10
// )

// ---

// // windowDimension represents channel request for window dimension change - RFC 4254 6.7
// type windowDimensionReq struct {
// 	Width       uint32
// 	Height      uint32
// 	WidthPixel  uint32
// 	HeightPixel uint32
// }
// // ptyReq represents the channel request for a PTY. RFC 4254 6.2
// type ptyReq struct {
// 	Term        string
// 	Width       uint32
// 	Height      uint32
// 	WidthPixel  uint32
// 	HeightPixel uint32
// 	TermModes   string
// }
// // envReq represents an "env" channel request - RFC 4254 6.4
// type envReq struct {
// 	Name  string
// 	Value string
// }
// // execRequest represents an "exec" channel request - RFC 4254 6.5
// type execRequest struct {
// 	Command string
// }
// // signalRequest represents a "signal" session channel request - RFC 4254 6.9
// type signalRequest struct {
// 	Signal ssh.Signal
// }
// // exitStatusReq represents an exit status for "exec" requests - RFC 4254 6.10
// type exitStatusReq struct {
// 	ExitStatus uint32
// }
// // exitSignalReq represents an exit signal for "exec" requests - RFC 4254 6.10
// type exitSignalReq struct {
// 	SignalName   string
// 	CoreDumped   bool
// 	ErrorMessage string
// 	LanguageTag  string
// }

// ---

// var signalsMap = map[ssh.Signal]os.Signal{
// 	ssh.SIGABRT: syscall.SIGABRT,
// 	ssh.SIGALRM: syscall.SIGALRM,
// 	ssh.SIGFPE:  syscall.SIGFPE,
// 	ssh.SIGHUP:  syscall.SIGHUP,
// 	ssh.SIGILL:  syscall.SIGILL,
// 	ssh.SIGINT:  syscall.SIGINT,
// 	ssh.SIGKILL: syscall.SIGKILL,
// 	ssh.SIGPIPE: syscall.SIGPIPE,
// 	ssh.SIGQUIT: syscall.SIGQUIT,
// 	ssh.SIGSEGV: syscall.SIGSEGV,
// 	ssh.SIGTERM: syscall.SIGTERM,
// 	ssh.SIGUSR1: syscall.SIGUSR1,
// 	ssh.SIGUSR2: syscall.SIGUSR2,
// }
