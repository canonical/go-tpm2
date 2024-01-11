// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/osutil/sys"
	"github.com/snapcore/snapd/snap"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
	"github.com/canonical/go-tpm2/mssim"
)

// TPMFeatureFlags indicates the TPM features required by a test. It allows the test
// runner to restrict the features available to tests to make the tests more friendly
// with real TPM devices.
type TPMFeatureFlags uint32

const (
	// TPMFeatureOwnerHierarchy indicates that the test requires the use of the storage hierarchy. The
	// authorization value should be empty at the start of the test.
	TPMFeatureOwnerHierarchy TPMFeatureFlags = (1 << iota)

	// TPMFeatureEndorsementHierarchy indicates that the test requires the use of the endorsement hierarchy.
	// The authorization value should be empty at the start of the test.
	TPMFeatureEndorsementHierarchy

	// TPMFeatureLockoutHierarchy indicates that the test requires the use of the lockout hierarchy. The
	// authorization value should be empty at the start of the test.
	TPMFeatureLockoutHierarchy

	// TPMFeaturePlatformHierarchy indicates that the test requires the use of the platform hierarchy. The
	// authorization value should be empty at the start of the test.
	TPMFeaturePlatformHierarchy

	// TPMFeaturePCR indicates that the test requires the use of a PCR. This is only required for
	// commands that require authorization - ie, it is not required for TPM2_PCR_Read.
	TPMFeaturePCR

	// TPMFeatureStClearChange indicates that the test needs to make changes that can't be undone without a
	// TPM2_Startup(CLEAR). On a physical TPM device, these changes can only be undone with a platform
	// reset or restart. This is not required for TPM2_HierarchyControl if TPMFeaturePlatformHierarchy is
	// set because the test fixture can undo changes made by this command, as long as the test doesn't
	// disable use of the platform hierarchy.
	TPMFeatureStClearChange

	// TPMFeatureSetCommandCodeAuditStatus indicates that the test uses the TPM2_SetCommandCodeAuditStatus
	// command. This isn't required if TPMFeatureEndorsementHierarchy is set, as changes made by this
	// command can be undone. This implies TPMFeatureNV for the TPM2_SetCommandCodeAuditStatus command.
	TPMFeatureSetCommandCodeAuditStatus

	// TPMFeatureClear indicates that the test uses the TPM2_Clear command. This also requires either
	// TPMFeatureLockoutHierarchy or TPMFeaturePlatformHierarchy. This implies TPMFeatureNV for the
	// TPM2_Clear command.
	TPMFeatureClear

	// TPMFeatureClearControl indicates that the test uses the TPM2_ClearControl command. Changes made by
	// the test can only be undone with the use of the platform hierarchy, which on a proper implementation
	// requires assistance from the platform firmware. This is not needed if TPMFeaturePlatformHierarchy
	// is set, as the test harness will restore the value of disableClear automatically. This implies
	// TPMFeatureNV for the TPM2_ClearControl command.
	TPMFeatureClearControl

	// TPMFeatureShutdown indicates that the test uses the TPM2_Shutdown command. This implies
	// TPMFeatureNV for the TPM2_Shutdown command.
	TPMFeatureShutdown

	// TPMFeatureNVGlobalWriteLock indicates that the test uses the TPM2_NV_GlobalWriteLock command. This
	// may make NV indices that weren't created by the test permanently read only if they define the
	// TPMA_NV_GLOBALLOCK attribute. This implies TPMFeatureNV for the TPM2_NV_GlobalWriteLock command.
	TPMFeatureNVGlobalWriteLock

	// TPMFeatureDAProtectedCapability indicates that the test makes use of a DA protected resource. The
	// test may cause the DA counter to be incremented either intentionally or in the event of a test
	// failure, which may eventually cause the TPM to enter DA lockout mode. This is not needed if
	// TPMFeatureLockoutHierarchy is provided, as this will cause the test harness to automatically
	// reset the DA counter.
	TPMFeatureDAProtectedCapability

	// TPMFeatureNV indicates that the test makes use of a command that may write to NV. Physical
	// TPMs may employ rate limiting on these commands.
	TPMFeatureNV

	// TPMFeaturePersistent indicates that the test may make changes to persistent resources that
	// were not created by the test, such as writing to or undefining NV indices or evicting
	// persistent objects.
	TPMFeaturePersistent
)

func (f TPMFeatureFlags) String() string {
	return ""
}

func (f *TPMFeatureFlags) Set(value string) error {
	for _, value := range strings.Split(value, ",") {
		switch value {
		case "ownerhierarchy":
			*f |= TPMFeatureOwnerHierarchy
		case "endorsementhierarchy":
			*f |= TPMFeatureEndorsementHierarchy
		case "lockouthierarchy":
			*f |= TPMFeatureLockoutHierarchy
		case "platformhierarchy":
			*f |= TPMFeaturePlatformHierarchy
		case "pcr":
			*f |= TPMFeaturePCR
		case "stclearchange":
			*f |= TPMFeatureStClearChange
		case "setcommandcodeauditstatus":
			*f |= TPMFeatureSetCommandCodeAuditStatus
		case "clear":
			*f |= TPMFeatureClear
		case "clearcontrol":
			*f |= TPMFeatureClearControl
		case "shutdown":
			*f |= TPMFeatureShutdown
		case "daprotectedcap":
			*f |= TPMFeatureDAProtectedCapability
		case "nv":
			*f |= TPMFeatureNV
		default:
			return fmt.Errorf("unrecognized option %s", value)
		}
	}
	return nil
}

type TPMBackendType int

const (
	TPMBackendNone TPMBackendType = iota
	TPMBackendDevice
	TPMBackendMssim
)

var (
	// TPMBackend defines the type of TPM connection that should be used for tests.
	TPMBackend TPMBackendType = TPMBackendNone

	// PermittedTPMFeatures defines the permitted feature set for tests that use a TPMContext
	// and where TPMBackend is not TPMBackendMssim. Tests that require features that aren't
	// permitted should be skipped. This is to facilitate testing on real TPM devices where it
	// might not be desirable to perform certain actions.
	PermittedTPMFeatures TPMFeatureFlags

	// TPMDevicePath defines the path of the TPM character device where TPMBackend is TPMBackendDevice.
	TPMDevicePath string = "/dev/tpm0"

	// MssimPort defines the port number of the TPM simulator command port where TPMBackend is TPMBackendMssim.
	MssimPort uint = 2321

	wrapMssimTransport = WrapTransport
)

type tpmBackendFlag TPMBackendType

func (v tpmBackendFlag) Set(s string) error {
	b, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	if b {
		TPMBackend = TPMBackendType(v)
	} else if TPMBackend == TPMBackendType(v) {
		TPMBackend = TPMBackendNone
	}
	return nil
}

func (v tpmBackendFlag) String() string {
	return strconv.FormatBool(TPMBackend == TPMBackendType(v))
}

func (v tpmBackendFlag) IsBoolFlag() bool { return true }

// AddCommandLineFlags adds various command line flags to the current executable, which can be used for
// setting test parameters. This should be called from inside of the init function for a package.
func AddCommandLineFlags() {
	flag.Var(tpmBackendFlag(TPMBackendDevice), "use-tpm", "Whether to use a TPM character device for testing (eg, /dev/tpm0)")
	flag.Var(tpmBackendFlag(TPMBackendMssim), "use-mssim", "Whether to use the TPM simulator for testing")
	flag.Var(&PermittedTPMFeatures, "tpm-permitted-features", "Comma-separated list of features that tests can use on a TPM character device")

	flag.StringVar(&TPMDevicePath, "tpm-path", "/dev/tpm0", "The path of the TPM character device to use for testing (default: /dev/tpm0)")
	flag.UintVar(&MssimPort, "mssim-port", 2321, "The port number of the TPM simulator command channel (default: 2321)")
}

type tpmSimulatorLaunchContext struct {
	port               uint
	persistentSavePath string
	workDir            string
	keepWorkDir        bool

	cmd *exec.Cmd

	errs []error
}

func (c *tpmSimulatorLaunchContext) captureErr(task string, fn func() error) {
	if err := fn(); err != nil {
		c.errs = append(c.errs, fmt.Errorf("%s failed: %w", task, err))
	}
}

func (c *tpmSimulatorLaunchContext) kill() error {
	if err := c.cmd.Process.Kill(); err != nil {
		return fmt.Errorf("cannot kill simulator: %w", err)
	}
	return nil
}

func (c *tpmSimulatorLaunchContext) wait() error {
	if err := c.cmd.Wait(); err != nil {
		return fmt.Errorf("simulator returned an error: %w", err)
	}
	return nil
}

func (c *tpmSimulatorLaunchContext) terminateFn(stopOk bool) func() error {
	if stopOk {
		return c.wait
	}
	return c.kill
}

func (c *tpmSimulatorLaunchContext) stopAndTerminate() (err error) {
	if c.cmd == nil || c.cmd.Process == nil {
		return nil
	}

	defer func() {
		stopOk := true
		if err != nil {
			stopOk = false
		}
		c.captureErr("terminate", c.terminateFn(stopOk))
	}()

	transport, err := mssim.OpenConnection("", c.port)
	if err != nil {
		return fmt.Errorf("cannot open simulator connection for stop: %w", err)
	}

	tpm := tpm2.NewTPMContext(transport)

	c.captureErr("shutdown", func() error {
		return tpm.Shutdown(tpm2.StartupClear)
	})
	if err := transport.Stop(); err != nil {
		return fmt.Errorf("cannot stop simulator: %w", err)
	}
	if err := tpm.Close(); err != nil {
		return fmt.Errorf("cannot close simulator: %w", err)
	}

	return nil
}

func (c *tpmSimulatorLaunchContext) savePersistent() error {
	if c.workDir == "" {
		return nil
	}
	if c.persistentSavePath == "" {
		return nil
	}

	// Open the updated persistent storage
	src, err := os.Open(filepath.Join(c.workDir, "NVChip"))
	switch {
	case os.IsNotExist(err):
		// No storage - this means we failed before the simulator started
		return nil
	case err != nil:
		return fmt.Errorf("cannot open simulator's persistent data: %w", err)
	}
	defer src.Close()

	// Atomically write to the source directory
	dest, err := osutil.NewAtomicFile(c.persistentSavePath, 0644, 0, sys.UserID(osutil.NoChown), sys.GroupID(osutil.NoChown))
	if err != nil {
		return fmt.Errorf("cannot create atomic file: %w", err)
	}
	defer dest.Cancel()

	if _, err := io.Copy(dest, src); err != nil {
		return fmt.Errorf("cannot copy simulator's persistent data to destination: %w", err)
	}
	if err := dest.Commit(); err != nil {
		return fmt.Errorf("cannot commit saved persistent data: %w", err)
	}

	return nil
}

func (c *tpmSimulatorLaunchContext) cleanWorkDir() error {
	if c.workDir == "" {
		return nil
	}
	if c.keepWorkDir {
		fmt.Printf("\n*** Saved working directory: %s ***\n\n", c.workDir)
		return nil
	}
	if err := os.RemoveAll(c.workDir); err != nil {
		return err
	}

	return nil
}

func (c *tpmSimulatorLaunchContext) shutdown() error {
	c.captureErr("stop and terminate", c.stopAndTerminate)
	c.captureErr("save persistent", c.savePersistent)
	c.captureErr("cleanup workdir", c.cleanWorkDir)

	if len(c.errs) == 0 {
		return nil
	}

	msg := "cannot properly shut down the simulator because of the following errors:\n"
	for _, err := range c.errs {
		msg += "* " + err.Error() + "\n"
	}
	return errors.New(msg)
}

func (c *tpmSimulatorLaunchContext) launch(opts *TPMSimulatorOptions) error {
	noEphemeral := true // XXX: try to autodetect this

	if opts.SourcePath == "" && opts.SavePersistent {
		return errors.New("SavePersistent requires SourcePath")
	}
	if opts.WorkDir == "" && opts.KeepWorkDir {
		return errors.New("KeepWorkDir requires WorkDir")
	}

	c.port = opts.Port
	if c.port == 0 {
		c.port = MssimPort
	}
	c.keepWorkDir = opts.KeepWorkDir
	if opts.SavePersistent {
		c.persistentSavePath = opts.SourcePath
	}

	// Search for a TPM simulator binary
	mssimPath := ""
	for _, p := range []string{"tpm2-simulator", "tpm2-simulator-chrisccoulson.tpm2-simulator"} {
		var err error
		mssimPath, err = exec.LookPath(p)
		if err == nil {
			break
		}
	}
	if mssimPath == "" {
		return errors.New("cannot find a simulator binary")
	}

	// The TPM simulator creates its persistent storage in its current directory. We create a
	// directory in XDG_RUNTIME_DIR because snaps have their own private tpmdir. For this,
	// we need to know the name of the snap if the simulator belongs to one.
	mssimSnapName := ""
	for currentPath, lastPath := mssimPath, ""; currentPath != ""; {
		dest, err := os.Readlink(currentPath)
		switch {
		case err != nil:
			if filepath.Base(currentPath) == "snap" {
				mssimSnapName, _ = snap.SplitSnapApp(filepath.Base(lastPath))
			}
			currentPath = ""
		default:
			if !filepath.IsAbs(dest) {
				dest = filepath.Join(filepath.Dir(currentPath), dest)
			}
			lastPath = currentPath
			currentPath = dest
		}
	}

	runDir := os.Getenv("XDG_RUNTIME_DIR")
	if runDir == "" {
		return errors.New("cannot determine XDG_RUNTIME_DIR")
	}

	// Determine working directory location
	var workDirRoot string
	var workDirPrefix string
	switch {
	case opts.WorkDir != "":
		workDirRoot = opts.WorkDir
		workDirPrefix = "tpm2test.mssim"
	case mssimSnapName != "":
		// The simulator is a snap. Use the snap-specific rundir.
		workDirRoot = filepath.Join(runDir, "snap."+mssimSnapName)
		workDirPrefix = ""
	default:
		workDirRoot = runDir
		workDirPrefix = "tpm2test.mssim"
	}

	// Create working directory
	if noEphemeral || opts.SourcePath != "" || opts.WorkDir != "" {
		if err := os.MkdirAll(workDirRoot, 0755); err != nil {
			return fmt.Errorf("cannot create workdir root: %w", err)
		}
		workDir, err := ioutil.TempDir(workDirRoot, workDirPrefix)
		if err != nil {
			return fmt.Errorf("cannot create workdir for simulator: %w", err)
		}
		c.workDir = workDir
	}

	// Copy any pre-existing persistent data in to the working directory
	if opts.SourcePath != "" {
		source, err := os.Open(opts.SourcePath)
		switch {
		case err != nil && opts.SavePersistent && os.IsNotExist(err):
			// The source file doesn't exist and SavePersistent is set. Permit this
			// so that it can be used to create a new file. Nothing to do in this case.
		case err != nil:
			return fmt.Errorf("cannot open source persistent storage: %w", err)
		default:
			// We have a source file. Copy it to the working directory
			defer source.Close()
			dest, err := os.Create(filepath.Join(c.workDir, "NVChip"))
			if err != nil {
				return fmt.Errorf("cannot create working copy of persistent storage for simulator: %w", err)
			}
			defer dest.Close()
			if _, err := io.Copy(dest, source); err != nil {
				return fmt.Errorf("cannot copy persistent storage for simulator to working directory: %w", err)
			}
		}
	}

	var args []string
	if opts.Manufacture {
		args = append(args, "-m")
	}
	if c.workDir == "" {
		args = append(args, "-e")
	}
	args = append(args, strconv.FormatUint(uint64(c.port), 10))

	cmd := exec.Command(mssimPath, args...)
	cmd.Dir = c.workDir // Run from the working directory
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr

	c.cmd = cmd

	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("cannot start simulator: %w", err)
	}

	var transport *mssim.Transport
	// Give the simulator 5 seconds to start up
Loop:
	for i := 0; ; i++ {
		var err error
		transport, err = mssim.OpenConnection("", c.port)
		switch {
		case err != nil && i == 4:
			return fmt.Errorf("cannot open simulator connection: %w", err)
		case err != nil:
			time.Sleep(time.Second)
		default:
			break Loop
		}
	}

	tpm := tpm2.NewTPMContext(transport)
	defer tpm.Close()

	if err := tpm.Startup(tpm2.StartupClear); err != nil {
		return fmt.Errorf("simulator startup failed: %w", err)
	}

	return nil
}

// TPMSimulatorOptions provide the options to LaunchTPMSimulator
type TPMSimulatorOptions struct {
	// Port is the TCP port to use for the command channel. This port + 1 will also be used for the
	// platform channel. If this is zero, then the value of [MssimPort] will be used.
	Port uint

	SourcePath     string    // Path for the source persistent data file
	Manufacture    bool      // Indicates that the simulator should be executed in re-manufacture mode
	SavePersistent bool      // Saves the persistent data file back to SourcePath on exit
	Stdout         io.Writer // Specify stdout for simulator
	Stderr         io.Writer // Specify stderr for simulator
	WorkDir        string    // Specify a temporary working directory for the simulator. One will be created if not specified
	KeepWorkDir    bool      // Keep the working directory on exit. Requires WorkDir.
}

// LaunchTPMSimulator launches a TPM simulator with the TCP command channel listening on
// opts.Port. The platform channel will listen on opts.Port + 1. If opts.Port is zero, then
// the value of [MssimPort] is used.
//
// If opts.SourcePath and opts.WorkDir are empty, the simulator will run with ephemeral storage
// if this is supported. When not using ephemeral storage, a temporary working directory is
// created in XDG_RUNTIME_DIR. The location of the temporary working directory can be overridden
// with opts.WorkDir.
//
// If opts.SourcePath is not empty, the file at the specified path will be copied to the
// working directory and used as the persistent NV storage. If opts.SavePersistent is also true,
// the updated persistent storage will be copied back to opts.SourcePath on exit. This is useful
// for generating test data that needs to be checked into a repository. If opts.SavePersistent
// is true then the file at opts.SourcePath doesn't need to exist.
//
// The temporary working directory is cleaned up on exit, unless opts.KeepWorkDir is set.
//
// On success, it returns a function that can be used to stop the simulator and clean up its
// temporary directory.
func LaunchTPMSimulator(opts *TPMSimulatorOptions) (stop func(), err error) {
	// Pick sensible defaults
	if opts == nil {
		opts = &TPMSimulatorOptions{Port: MssimPort, Manufacture: true}
	}

	ctx := new(tpmSimulatorLaunchContext)

	// Defer cleanup on failure
	defer func() {
		if err == nil {
			return
		}
		ctx.shutdown()
	}()

	if err := ctx.launch(opts); err != nil {
		return nil, err
	}

	return func() {
		ctx.shutdown()
	}, nil
}

func newTransport(features TPMFeatureFlags) (*Transport, error) {
	switch TPMBackend {
	case TPMBackendNone:
		return nil, nil
	case TPMBackendDevice:
		if features&PermittedTPMFeatures != features {
			return nil, nil
		}
		transport, err := linux.OpenDevice(TPMDevicePath)
		if err != nil {
			return nil, err
		}
		return WrapTransport(transport, features)
	case TPMBackendMssim:
		transport, err := mssim.OpenConnection("", MssimPort)
		if err != nil {
			return nil, err
		}
		return WrapTransport(transport, features)
	}
	panic("not reached")
}

// NewTransport returns a new Transport for testing, for integration with test suites that might have a custom way to create a
// TPMContext. If TPMBackend is TPMBackendNone then the current test will be skipped. If TPMBackend is TPMBackendMssim,
// the returned Transport will wrap a *mssim.Transport and will correspond to a connection to the TPM simulator on the port
// specified by the MssimPort variable. If TPMBackend is TPMBackendDevice, the returned Transport will wrap a
// *linux.Transport if the requested features are permitted, as defined by the PermittedTPMFeatures variable. In
// this case, the Transport will correspond to a connection to the Linux character device at the path specified by the
// TPMDevicePath variable. If the test requires features that are not permitted, the test will be skipped.
//
// The returned Transport must be closed when it is no longer required.
func NewTransport(c *C, features TPMFeatureFlags) *Transport {
	transport, err := newTransport(features)
	c.Assert(err, IsNil)
	if transport == nil {
		c.Skip("no TPM available for the test")
	}
	return transport
}

// NewTransportT returns a new Transport for testing, for integration with test suites that might have a custom way to create a
// TPMContext. If TPMBackend is TPMBackendNone then the current test will be skipped. If TPMBackend is TPMBackendMssim,
// the returned Transport will wrap a *mssim.Transport and will correspond to a connection to the TPM simulator on the port
// specified by the MssimPort variable. If TPMBackend is TPMBackendDevice, the returned Transport will wrap a
// *linux.Transport if the requested features are permitted, as defined by the PermittedTPMFeatures variable. In
// this case, the Transport will correspond to a connection to the Linux character device at the path specified by the
// TPMDevicePath variable. If the test requires features that are not permitted, the test will be skipped.
//
// The returned Transport must be closed when it is no longer required.
func NewTransportT(t *testing.T, features TPMFeatureFlags) *Transport {
	transport, err := newTransport(features)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if transport == nil {
		t.SkipNow()
	}
	return transport
}

// NewTPMContext returns a new TPMContext for testing. If TPMBackend is TPMBackendNone then the current test will be
// skipped. If TPMBackend is TPMBackendMssim, the returned context will correspond to a connection to the TPM
// simulator on the port specified by the MssimPort variable. If TPMBackend is TPMBackendDevice, a TPMContext will
// be returned if the requested features are permitted, as defined by the PermittedTPMFeatures variable. In this
// case, the TPMContext will correspond to a connection to the Linux character device at the path specified by the
// TPMDevicePath variable. If the test requires features that are not permitted, the test will be skipped.
//
// The returned TPMContext must be closed when it is no longer required.
func NewTPMContext(c *C, features TPMFeatureFlags) (*tpm2.TPMContext, *Transport) {
	transport := NewTransport(c, features)
	tpm := tpm2.NewTPMContext(transport)
	return tpm, transport
}

// NewTPMContextT returns a new TPMContext for testing. If TPMBackend is TPMBackendNone then the current test will be
// skipped. If TPMBackend is TPMBackendMssim, the returned context will correspond to a connection to the TPM
// simulator on the port specified by the MssimPort variable. If TPMBackend is TPMBackendDevice, a TPMContext will
// be returned if the requested features are permitted, as defined by the PermittedTPMFeatures variable. In this
// case, the TPMContext will correspond to a connection to the Linux character device at the path specified by the
// TPMDevicePath variable. If the test requires features that are not permitted, the test will be skipped.
//
// The returned TPMContext must be closed when it is no longer required. This can be done with the returned
// close callback, which will cause the test to fail if closing doesn't succeed.
func NewTPMContextT(t *testing.T, features TPMFeatureFlags) (tpm *tpm2.TPMContext, transport *Transport, close func()) {
	transport = NewTransportT(t, features)
	tpm = tpm2.NewTPMContext(transport)
	return tpm, transport, func() {
		if err := tpm.Close(); err != nil {
			t.Errorf("close failed: %v", err)
		}
	}
}

func newSimulatorTransport() (*Transport, error) {
	if TPMBackend != TPMBackendMssim {
		return nil, nil
	}

	mssim, err := mssim.OpenConnection("", MssimPort)
	if err != nil {
		return nil, err
	}

	return wrapMssimTransport(mssim, TPMFeatureFlags(math.MaxUint32))
}

// NewSimulatorTransport returns a new Transport for testing that corresponds to a connection to the TPM simulator
// on the port specified by the MssimPort variable. If TPMBackend is not TPMBackendMssim then the test
// will be skipped.
//
// The returned Transport must be closed when it is no longer required.
func NewSimulatorTransport(c *C) *Transport {
	transport, err := newSimulatorTransport()
	c.Assert(err, IsNil)
	if transport == nil {
		c.Skip("no TPM available for the test")
	}
	return transport
}

// NewSimulatorTransportT returns a new Transport for testing that corresponds to a connection to the TPM simulator
// on the port specified by the MssimPort variable. If TPMBackend is not TPMBackendMssim then the test
// will be skipped.
//
// The returned Transport must be closed when it is no longer required.
func NewSimulatorTransportT(t *testing.T) *Transport {
	transport, err := newSimulatorTransport()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if transport == nil {
		t.SkipNow()
	}
	return transport
}

// NewTPMSimulatorContext returns a new TPMContext for testing that corresponds to a connection to the TPM simulator
// on the port specified by the MssimPort variable. If TPMBackend is not TPMBackendMssim then the test will be
// skipped.
//
// The returned TPMContext must be closed when it is no longer required.
func NewTPMSimulatorContext(c *C) (*tpm2.TPMContext, *Transport) {
	transport := NewSimulatorTransport(c)
	tpm := tpm2.NewTPMContext(transport)
	return tpm, transport
}

// NewTPMSimulatorContextT returns a new TPMContext for testing that corresponds to a connection to the TPM simulator
// on the port specified by the MssimPort variable. If TPMBackend is not TPMBackendMssim then the test will be
// skipped.
//
// The returned TPMContext must be closed when it is no longer required. This can be done with the returned
// close callback, which will cause the test to fail if closing doesn't succeed.
func NewTPMSimulatorContextT(t *testing.T) (tpm *tpm2.TPMContext, transport *Transport, close func()) {
	transport = NewSimulatorTransportT(t)
	tpm = tpm2.NewTPMContext(transport)
	return tpm, transport, func() {
		if err := tpm.Close(); err != nil {
			t.Errorf("close failed: %v", err)
		}
	}
}

func clearTPMUsingPlatform(tpm *tpm2.TPMContext) error {
	if err := tpm.ClearControl(tpm.PlatformHandleContext(), false, nil); err != nil {
		return err
	}
	return tpm.Clear(tpm.PlatformHandleContext(), nil)
}

// ClearTPMUsingPlatformHierarchyT enables the TPM2_Clear command and then
// clears the TPM using the platform hierarchy.
func ClearTPMUsingPlatformHierarchyT(t *testing.T, tpm *tpm2.TPMContext) {
	if err := clearTPMUsingPlatform(tpm); err != nil {
		t.Fatal(err)
	}
}

func resetTPMSimulator(tpm *tpm2.TPMContext, transport *mssim.Transport) error {
	if err := tpm.Shutdown(tpm2.StartupClear); err != nil {
		return err
	}
	if err := transport.Reset(); err != nil {
		return fmt.Errorf("resetting the simulator failed: %v", err)
	}
	return tpm.Startup(tpm2.StartupClear)
}

// ResetTPMSimulatorT issues a Shutdown -> Reset -> Startup cycle of the TPM simulator.
func ResetTPMSimulatorT(t *testing.T, tpm *tpm2.TPMContext, transport *Transport) {
	mssim, ok := transport.Unwrap().(*mssim.Transport)
	if !ok {
		t.Fatal("not a simulator")
	}
	if err := resetTPMSimulator(tpm, mssim); err != nil {
		t.Fatal(err)
	}
}
