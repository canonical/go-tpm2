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

	wrapMssimTCTI = WrapTCTI
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

// TPMSimulatorOptions provide the options to LaunchTPMSimulator
type TPMSimulatorOptions struct {
	SourcePath     string // Path for the source persistent data file
	Manufacture    bool   // Indicates that the simulator should be executed in re-manufacture mode
	SavePersistent bool   // Saves the persistent data file back to SourcePath on exit
}

// LaunchTPMSimulator launches a TPM simulator. If opts.SourcePath is empty, or it points to a
// non-existant file and opts.SavePersistent is false, the simulator will run with ephemeral
// storage if this is supported, else a temporary directory will be created to store the
// persistent NV storage for the simulator. If opts.SourcePath is not empty, the target file
// is copied to the temporary directory and used as the persistent NV storage. The temporary
// directory will be cleanup up on exit. If opts.SavePersistent is true, the persistant NV
// storage is copied back to opts.SourcePath on exit. This is useful for generating test data
// that needs to be checked into a repository.
//
// On success, it returns a function that can be used to stop the simulator and clean up its
// temporary directory.
func LaunchTPMSimulator(opts *TPMSimulatorOptions) (stop func(), err error) {
	noEphemeral := true // XXX: try to autodetect this

	// Pick sensible defaults
	if opts == nil {
		opts = &TPMSimulatorOptions{Manufacture: true}
	}

	if opts.SourcePath == "" && opts.SavePersistent {
		return nil, errors.New("SavePersistent requires SourcePath")
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
		return nil, errors.New("cannot find a simulator binary")
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
		return nil, errors.New("cannot determine XDG_RUNTIME_DIR")
	}

	// Create the root temporary directory.
	tmpRoot := runDir
	tmpPrefix := "tpm2test.mssim"
	if mssimSnapName != "" {
		// The simulator is shipped as a snap
		tmpRoot = filepath.Join(runDir, mssimSnapName)
		tmpPrefix = ""
		if err := os.MkdirAll(tmpRoot, 0755); err != nil {
			return nil, fmt.Errorf("cannot create snap tmpdir: %w", err)
		}
	}

	var mssimTmpDir string
	var cmd *exec.Cmd

	// At this point, we have stuff to clean up on early failure.
	cleanup := func() {
		// Defer saving the persistent data and removing the temporary directory
		defer func() {
			// Defer removal of the temporary directory
			defer func() {
				if mssimTmpDir == "" {
					return
				}
				os.RemoveAll(mssimTmpDir)
			}()

			if !opts.SavePersistent {
				// Nothing else to do
				return
			}

			// Open the updated persistent storage
			src, err := os.Open(filepath.Join(mssimTmpDir, "NVChip"))
			switch {
			case os.IsNotExist(err):
				// No storage - this means we failed before the simulator started
				return
			case err != nil:
				fmt.Fprintf(os.Stderr, "Cannot open TPM simulator persistent data: %v\n", err)
				return
			}
			defer src.Close()

			// Atomically write to the source directory
			dest, err := osutil.NewAtomicFile(opts.SourcePath, 0644, 0, sys.UserID(osutil.NoChown), sys.GroupID(osutil.NoChown))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot create new atomic file for saving TPM simulator persistent data: %v\n", err)
				return
			}
			defer dest.Cancel()

			if _, err := io.Copy(dest, src); err != nil {
				fmt.Fprintf(os.Stderr, "Cannot copy TPM simulator persistent data: %v\n", err)
				return
			}

			if err := dest.Commit(); err != nil {
				fmt.Fprintf(os.Stderr, "Cannot commit TPM simulator persistent data: %v\n", err)
			}
		}()

		if cmd != nil && cmd.Process != nil {
			// If we've called exec.Cmd.Start, attempt to stop the simulator.
			cleanShutdown := false
			// Defer the call to exec.Cmd.Wait or os.Process.Kill until after we've initiated the shutdown.
			defer func() {
				if cleanShutdown {
					if err := cmd.Wait(); err != nil {
						fmt.Fprintf(os.Stderr, "TPM simulator finished with an error: %v", err)
					}
				} else {
					fmt.Fprintf(os.Stderr, "Killing TPM simulator\n")
					if err := cmd.Process.Kill(); err != nil {
						fmt.Fprintf(os.Stderr, "Cannot send signal to TPM simulator: %v\n", err)
					}
				}
			}()

			tcti, err := mssim.OpenConnection("", MssimPort)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot open TPM simulator connection for shutdown: %v\n", err)
				return
			}

			tpm := tpm2.NewTPMContext(tcti)
			if err := tpm.Shutdown(tpm2.StartupClear); err != nil {
				fmt.Fprintf(os.Stderr, "TPM simulator shutdown failed: %v\n", err)
			}
			if err := tcti.Stop(); err != nil {
				fmt.Fprintf(os.Stderr, "TPM simulator stop failed: %v\n", err)
				return
			}
			if err := tpm.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "TPM simulator connection close failed: %v\n", err)
				return
			}
			cleanShutdown = true
		}
	}

	// Defer cleanup on failure
	defer func() {
		if err == nil {
			return
		}
		cleanup()
	}()

	makeTmpDir := func() (err error) {
		mssimTmpDir, err = ioutil.TempDir(tmpRoot, tmpPrefix)
		if err != nil {
			return fmt.Errorf("cannot create temporary directory for simulator: %w", err)
		}
		return nil
	}

	// Copy any pre-existing persistent data in to the temporary directory
	if opts.SourcePath != "" {
		source, err := os.Open(opts.SourcePath)
		switch {
		case err != nil && !os.IsNotExist(err):
			return nil, fmt.Errorf("cannot open source persistent storage: %w", err)
		case err != nil && (opts.SavePersistent || noEphemeral):
			// No source file, but we want to either save the persistent data or we
			// don't support ephemeral mode, so create the instance tmpdir.
			if err := makeTmpDir(); err != nil {
				return nil, err
			}
		case err != nil:
			// No source file, we don't want to save the persistent data and we support
			// ephemeral mode - nothing to do.
		default:
			// We have a source file. Create the instance tmpdir and copy the file there.
			defer source.Close()
			if err := makeTmpDir(); err != nil {
				return nil, err
			}
			dest, err := os.Create(filepath.Join(mssimTmpDir, "NVChip"))
			if err != nil {
				return nil, fmt.Errorf("cannot create temporary storage for simulator: %w", err)
			}
			defer dest.Close()
			if _, err := io.Copy(dest, source); err != nil {
				return nil, fmt.Errorf("cannot copy persistent storage to temporary location for simulator: %w", err)
			}
		}
	} else if !noEphemeral {
		// No source file and we aren't saving the persistent data, but ephemeral
		// mode is not supported - create the instance tmpdir.
		if err := makeTmpDir(); err != nil {
			return nil, err
		}
	}

	var args []string
	if opts.Manufacture {
		args = append(args, "-m")
	}
	if mssimTmpDir == "" {
		args = append(args, "-e")
	}
	args = append(args, strconv.FormatUint(uint64(MssimPort), 10))

	cmd = exec.Command(mssimPath, args...)
	cmd.Dir = mssimTmpDir // Run from the temporary directory we created

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("cannot start simulator: %w", err)
	}

	var tcti *mssim.Tcti
	// Give the simulator 5 seconds to start up
Loop:
	for i := 0; ; i++ {
		var err error
		tcti, err = mssim.OpenConnection("", MssimPort)
		switch {
		case err != nil && i == 4:
			return nil, fmt.Errorf("cannot open simulator connection: %w", err)
		case err != nil:
			time.Sleep(time.Second)
		default:
			break Loop
		}
	}

	tpm := tpm2.NewTPMContext(tcti)
	defer tpm.Close()

	if err := tpm.Startup(tpm2.StartupClear); err != nil {
		return nil, fmt.Errorf("simulator startup failed: %w", err)
	}

	return cleanup, nil
}

func newTCTI(features TPMFeatureFlags) (*TCTI, error) {
	switch TPMBackend {
	case TPMBackendNone:
		return nil, nil
	case TPMBackendDevice:
		if features&PermittedTPMFeatures != features {
			return nil, nil
		}
		tcti, err := linux.OpenDevice(TPMDevicePath)
		if err != nil {
			return nil, err
		}
		return WrapTCTI(tcti, features)
	case TPMBackendMssim:
		tcti, err := mssim.OpenConnection("", MssimPort)
		if err != nil {
			return nil, err
		}
		return WrapTCTI(tcti, features)
	}
	panic("not reached")
}

// NewTCTI returns a new TCTI for testing, for integration with test suites that might have a custom way to create a
// TPMContext. If TPMBackend is TPMBackendNone then the current test will be skipped. If TPMBackend is TPMBackendMssim,
// the returned TCTI will wrap a *mssim.Tcti and will correspond to a connection to the TPM simulator on the port
// specified by the MssimPort variable. If TPMBackend is TPMBackendDevice, the returned TCTI will wrap a
// *tpm2.TctiDeviceLinux if the requested features are permitted, as defined by the PermittedTPMFeatures variable. In
// this case, the TCTI will correspond to a connection to the Linux character device at the path specified by the
// TPMDevicePath variable. If the test requires features that are not permitted, the test will be skipped.
//
// The returned TCTI must be closed when it is no longer required.
func NewTCTI(c *C, features TPMFeatureFlags) *TCTI {
	tcti, err := newTCTI(features)
	c.Assert(err, IsNil)
	if tcti == nil {
		c.Skip("no TPM available for the test")
	}
	return tcti
}

// NewTCTIT returns a new TCTI for testing, for integration with test suites that might have a custom way to create a
// TPMContext. If TPMBackend is TPMBackendNone then the current test will be skipped. If TPMBackend is TPMBackendMssim,
// the returned TCTI will wrap a *mssim.Tcti and will correspond to a connection to the TPM simulator on the port
// specified by the MssimPort variable. If TPMBackend is TPMBackendDevice, the returned TCTI will wrap a
// *tpm2.TctiDeviceLinux if the requested features are permitted, as defined by the PermittedTPMFeatures variable. In
// this case, the TCTI will correspond to a connection to the Linux character device at the path specified by the
// TPMDevicePath variable. If the test requires features that are not permitted, the test will be skipped.
//
// The returned TCTI must be closed when it is no longer required.
func NewTCTIT(t *testing.T, features TPMFeatureFlags) *TCTI {
	tcti, err := newTCTI(features)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if tcti == nil {
		t.SkipNow()
	}
	return tcti
}

// NewTPMContext returns a new TPMContext for testing. If TPMBackend is TPMBackendNone then the current test will be
// skipped. If TPMBackend is TPMBackendMssim, the returned context will correspond to a connection to the TPM
// simulator on the port specified by the MssimPort variable. If TPMBackend is TPMBackendDevice, a TPMContext will
// be returned if the requested features are permitted, as defined by the PermittedTPMFeatures variable. In this
// case, the TPMContext will correspond to a connection to the Linux character device at the path specified by the
// TPMDevicePath variable. If the test requires features that are not permitted, the test will be skipped.
//
// The returned TPMContext must be closed when it is no longer required.
func NewTPMContext(c *C, features TPMFeatureFlags) (*tpm2.TPMContext, *TCTI) {
	tcti := NewTCTI(c, features)
	tpm := tpm2.NewTPMContext(tcti)
	return tpm, tcti
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
func NewTPMContextT(t *testing.T, features TPMFeatureFlags) (tpm *tpm2.TPMContext, tcti *TCTI, close func()) {
	tcti = NewTCTIT(t, features)
	tpm = tpm2.NewTPMContext(tcti)
	return tpm, tcti, func() {
		if err := tpm.Close(); err != nil {
			t.Errorf("close failed: %v", err)
		}
	}
}

func newSimulatorTCTI() (*TCTI, error) {
	if TPMBackend != TPMBackendMssim {
		return nil, nil
	}

	mssim, err := mssim.OpenConnection("", MssimPort)
	if err != nil {
		return nil, err
	}

	return wrapMssimTCTI(mssim, TPMFeatureFlags(math.MaxUint32))
}

// NewSimulatorTCTI returns a new TCTI for testing that corresponds to a connection to the TPM simulator
// on the port specified by the MssimPort variable. If TPMBackend is not TPMBackendMssim then the test
// will be skipped.
//
// The returned TCTI must be closed when it is no longer required.
func NewSimulatorTCTI(c *C) *TCTI {
	tcti, err := newSimulatorTCTI()
	c.Assert(err, IsNil)
	if tcti == nil {
		c.Skip("no TPM available for the test")
	}
	return tcti
}

// NewSimulatorTCTIT returns a new TCTI for testing that corresponds to a connection to the TPM simulator
// on the port specified by the MssimPort variable. If TPMBackend is not TPMBackendMssim then the test
// will be skipped.
//
// The returned TCTI must be closed when it is no longer required.
func NewSimulatorTCTIT(t *testing.T) *TCTI {
	tcti, err := newSimulatorTCTI()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if tcti == nil {
		t.SkipNow()
	}
	return tcti
}

// NewTPMSimulatorContext returns a new TPMContext for testing that corresponds to a connection to the TPM simulator
// on the port specified by the MssimPort variable. If TPMBackend is not TPMBackendMssim then the test will be
// skipped.
//
// The returned TPMContext must be closed when it is no longer required.
func NewTPMSimulatorContext(c *C) (*tpm2.TPMContext, *TCTI) {
	tcti := NewSimulatorTCTI(c)
	tpm := tpm2.NewTPMContext(tcti)
	return tpm, tcti
}

// NewTPMSimulatorContextT returns a new TPMContext for testing that corresponds to a connection to the TPM simulator
// on the port specified by the MssimPort variable. If TPMBackend is not TPMBackendMssim then the test will be
// skipped.
//
// The returned TPMContext must be closed when it is no longer required. This can be done with the returned
// close callback, which will cause the test to fail if closing doesn't succeed.
func NewTPMSimulatorContextT(t *testing.T) (tpm *tpm2.TPMContext, tcti *TCTI, close func()) {
	tcti = NewSimulatorTCTIT(t)
	tpm = tpm2.NewTPMContext(tcti)
	return tpm, tcti, func() {
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

func resetTPMSimulator(tpm *tpm2.TPMContext, tcti *mssim.Tcti) error {
	if err := tpm.Shutdown(tpm2.StartupClear); err != nil {
		return err
	}
	if err := tcti.Reset(); err != nil {
		return fmt.Errorf("resetting the simulator failed: %v", err)
	}
	return tpm.Startup(tpm2.StartupClear)
}

// ResetTPMSimulatorT issues a Shutdown -> Reset -> Startup cycle of the TPM simulator.
func ResetTPMSimulatorT(t *testing.T, tpm *tpm2.TPMContext, tcti *TCTI) {
	mssim, ok := tcti.Unwrap().(*mssim.Tcti)
	if !ok {
		t.Fatal("not a simulator")
	}
	if err := resetTPMSimulator(tpm, mssim); err != nil {
		t.Fatal(err)
	}
}
