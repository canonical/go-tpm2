// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"testing"
)

func TestStartup(t *testing.T) {
	tpm, tcti := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc         string
		shutdownType StartupType
		startupType  StartupType
	}{
		{
			desc:         "Reset",
			shutdownType: StartupClear,
			startupType:  StartupClear,
		},
		{
			desc:         "Restart",
			shutdownType: StartupState,
			startupType:  StartupClear,
		},
		{
			desc:         "Resume",
			shutdownType: StartupState,
			startupType:  StartupState,
		},
	} {
		run := func(t *testing.T) {
			if err := tpm.Shutdown(data.shutdownType); err != nil {
				t.Fatalf("Shutdown failed: %v", err)
			}
			if err := tcti.Reset(); err != nil {
				t.Fatalf("Reset failed: %v", err)
			}
			if err := tpm.Startup(data.startupType); err != nil {
				t.Fatalf("Startup failed: %v", err)
			}
		}

		t.Run(data.desc+"/WithTransientObject", func(t *testing.T) {
			context := createRSASrkForTesting(t, tpm, nil)
			defer verifyContextFlushed(t, tpm, context)

			handle := context.Handle()

			run(t)

			c, err := tpm.WrapHandle(handle)
			if err == nil {
				defer flushContext(t, tpm, c)
				t.Fatalf("Unexpected behaviour: transient handle should have been flushed")
			}
			if err.Error() != "TPM returned a warning whilst executing command TPM_CC_ReadPublic: "+
				"TPM_RC_REFERENCE_H0 (the 1st handle in the handle area references a transient "+
				"object or session that is not loaded)" {
				t.Errorf("Unexpected error: %v", err)
			}
		})

		t.Run(data.desc+"/WithPersistentObject", func(t *testing.T) {
			context := createRSASrkForTesting(t, tpm, nil)
			defer verifyContextFlushed(t, tpm, context)

			persistentContext := persistObjectForTesting(t, tpm, HandleOwner, context,
				Handle(0x8100ffff))
			defer evictPersistentObject(t, tpm, HandleOwner, persistentContext)

			handle := persistentContext.Handle()

			run(t)

			if persistentContext.Handle() != handle {
				t.Errorf("Persistent handle was invalidated")
			}
			if _, _, _, err := tpm.ReadPublic(persistentContext); err != nil {
				t.Errorf("Unexpected behaviour: ReadPublic failed: %v", err)
			}
		})

		t.Run(data.desc+"/WithSession", func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil,
				AlgorithmSHA256, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer verifyContextFlushed(t, tpm, sessionContext)

			handle := sessionContext.Handle()

			run(t)

			handles, err := tpm.GetCapabilityHandles(
				handle&Handle(0xffffff)|HandleTypeLoadedSession.BaseHandle(), 1)
			if err != nil {
				t.Fatalf("GetCapability failed: %v", err)
			}
			if len(handles) > 0 && handles[0] == handle {
				t.Errorf("Unexpected behaviour: session handle should have been flushed")
			}
		})

		for _, data2 := range []struct {
			desc  string
			in    NVPublic
			write bool
			clear bool
		}{
			{
				desc: "WriteDefine",
				in: NVPublic{
					Index:   0x0181ffff,
					NameAlg: AlgorithmSHA256,
					Attrs: MakeNVAttributes(AttrNVAuthRead|AttrNVAuthWrite|
						AttrNVWriteDefine, NVTypeOrdinary),
					Size: 8},
				write: true,
				clear: false,
			},
			{
				desc: "WriteStClear",
				in: NVPublic{
					Index:   0x0181ffff,
					NameAlg: AlgorithmSHA256,
					Attrs: MakeNVAttributes(AttrNVAuthRead|AttrNVAuthWrite|
						AttrNVWriteStClear, NVTypeOrdinary),
					Size: 8},
				write: true,
				clear: true,
			},
			{
				desc: "WriteDefineNotWritten",
				in: NVPublic{
					Index:   0x0181ffff,
					NameAlg: AlgorithmSHA256,
					Attrs: MakeNVAttributes(AttrNVAuthRead|AttrNVAuthWrite|
						AttrNVWriteDefine, NVTypeOrdinary),
					Size: 8},
				write: false,
				clear: true,
			},
		} {
			t.Run(data.desc+"/NVWriteLocked/"+data2.desc, func(t *testing.T) {
				if err := tpm.NVDefineSpace(HandleOwner, nil, &data2.in, nil); err != nil {
					t.Fatalf("NVDefine failed: %v", err)
				}
				nv, err := tpm.WrapHandle(data2.in.Index)
				if err != nil {
					t.Fatalf("WrapHandle failed: %v", err)
				}
				defer undefineNVSpace(t, tpm, nv, HandleOwner, nil)

				if data2.write {
					if err := tpm.NVWrite(nv, nv, []byte("foo"), 0, nil); err != nil {
						t.Errorf("NVWrite failed: %v", err)
					}
				}

				if err := tpm.NVWriteLock(nv, nv, nil); err != nil {
					t.Errorf("NVWriteLock failed: %v", err)
				}

				run(t)

				if nv.Handle() != data2.in.Index {
					t.Errorf("NV handle was invalidated")
				}
				_, name, err := tpm.NVReadPublic(nv)
				if err != nil {
					t.Errorf("NVReadPublic failed: %v", err)
				}
				if !bytes.Equal(nv.Name(), name) {
					t.Errorf("NV index ResourceContext was not updated correctly")
				}
			})
		}

		for _, data2 := range []struct {
			desc string
			in   NVPublic
		}{
			{
				desc: "Ordinary",
				in: NVPublic{
					Index:   0x0181ffff,
					NameAlg: AlgorithmSHA256,
					Attrs:   MakeNVAttributes(AttrNVAuthRead|AttrNVAuthWrite, NVTypeOrdinary),
					Size:    8},
			},
			{
				desc: "OrdinaryNVClearStClear",
				in: NVPublic{
					Index:   0x0181ffff,
					NameAlg: AlgorithmSHA256,
					Attrs: MakeNVAttributes(AttrNVAuthRead|AttrNVAuthWrite|
						AttrNVClearStClear, NVTypeOrdinary),
					Size: 8},
			},
			{
				desc: "OrdinaryNVOrderly",
				in: NVPublic{
					Index:   0x0181ffff,
					NameAlg: AlgorithmSHA256,
					Attrs: MakeNVAttributes(AttrNVAuthRead|AttrNVAuthWrite|
						AttrNVOrderly, NVTypeOrdinary),
					Size: 8},
			},
			{
				desc: "Counter",
				in: NVPublic{
					Index:   0x0181ffff,
					NameAlg: AlgorithmSHA256,
					Attrs:   MakeNVAttributes(AttrNVAuthRead|AttrNVAuthWrite, NVTypeCounter),
					Size:    8},
			},
			{
				desc: "CounterNVOrderly",
				in: NVPublic{
					Index:   0x0181ffff,
					NameAlg: AlgorithmSHA256,
					Attrs: MakeNVAttributes(AttrNVAuthRead|AttrNVAuthWrite|
						AttrNVOrderly, NVTypeCounter),
					Size: 8},
			},
		} {
			t.Run(data.desc+"/NVWritten/"+data2.desc, func(t *testing.T) {
				if err := tpm.NVDefineSpace(HandleOwner, nil, &data2.in, nil); err != nil {
					t.Fatalf("NVDefine failed: %v", err)
				}
				nv, err := tpm.WrapHandle(data2.in.Index)
				if err != nil {
					t.Fatalf("WrapHandle failed: %v", err)
				}
				defer undefineNVSpace(t, tpm, nv, HandleOwner, nil)

				if data2.in.Attrs.Type() == NVTypeOrdinary {
					if err := tpm.NVWrite(nv, nv, []byte("foo"), 0, nil); err != nil {
						t.Errorf("NVWrite failed: %v", err)
					}
				} else {
					if err := tpm.NVIncrement(nv, nv, nil); err != nil {
						t.Errorf("NVIncrement failed: %v", err)
					}
				}

				run(t)

				if nv.Handle() != data2.in.Index {
					t.Errorf("NV handle was invalidated")
				}
				_, name, err := tpm.NVReadPublic(nv)
				if err != nil {
					t.Errorf("NVReadPublic failed: %v", err)
				}
				if !bytes.Equal(nv.Name(), name) {
					t.Errorf("NV index ResourceContext was not updated correctly")
				}
			})
		}

		t.Run(data.desc+"/NVReadLocked", func(t *testing.T) {
			template := NVPublic{
				Index:   0x0181ffff,
				NameAlg: AlgorithmSHA256,
				Attrs: MakeNVAttributes(AttrNVAuthRead|AttrNVAuthWrite|AttrNVReadStClear,
					NVTypeOrdinary),
				Size: 8}
			if err := tpm.NVDefineSpace(HandleOwner, nil, &template, nil); err != nil {
				t.Fatalf("NVDefine failed: %v", err)
			}
			nv, err := tpm.WrapHandle(template.Index)
			if err != nil {
				t.Fatalf("WrapHandle failed: %v", err)
			}
			defer undefineNVSpace(t, tpm, nv, HandleOwner, nil)

			if err := tpm.NVReadLock(nv, nv, nil); err != nil {
				t.Errorf("NVReadLock failed: %v", err)
			}

			run(t)

			if nv.Handle() != template.Index {
				t.Errorf("NV handle was invalidated")
			}
			_, name, err := tpm.NVReadPublic(nv)
			if err != nil {
				t.Errorf("NVReadPublic failed: %v", err)
			}
			if !bytes.Equal(nv.Name(), name) {
				t.Errorf("NV index ResourceContext was not updated correctly")
			}
		})
	}
}
