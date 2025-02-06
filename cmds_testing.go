// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 9 - Start-up

// SelfTest executes the TPM2_SelfTest command and causes the TPM to perform a self test
// of its capabilities. If fullTest is true, it will test all functions. If fullTest is
// false, it will only perform a test of functions that haven't already been tested.
//
// Some implementatons will return immediately and then begin testing. In this case, if
// fullTest is true or fullTest is false and there are tests to perform, a *[TPMWarning]
// with the warning code [WarningTesting] will be returned. If fullTest is false and
// there are no tests to perform, this function will return with success.
//
// Some implementations will block and only return if all required tests have been completed.
// In this case, if a failure occurs, a *[TPMError] with the error code [ErrorFailure] will
// be returned. If all tests that execute complete successfully, the function will return
// no error.
func (t *TPMContext) SelfTest(fullTest bool, sessions ...SessionContext) error {
	return t.StartCommand(CommandSelfTest).
		AddParams(fullTest).
		AddExtraSessions(sessions...).
		Run(nil)
}

// IncrementalSelfTest executes the TPM2_IncrementalSelfTest command and causes the TPM to
// perform a test of the selected algorithms.
//
// If toTest contains an algorithm that has already been tested, it won't be tested again.
//
// The TPM will return a todo list of algorithms that haven't been fully tested. Supplying
// an empty toTest list is a way to determine which algorithms have not been fully tested
// yet.
//
// If toTest is not an empty list, this command should respond with no error. Subsequent
// calls to this command or any others will return a *[TPMWarning] with warning code
// [WarningTesting] until the requested testing is complete.
func (t *TPMContext) IncrementalSelfTest(toTest AlgorithmList, sessions ...SessionContext) (AlgorithmList, error) {
	var toDoList AlgorithmList
	if err := t.StartCommand(CommandIncrementalSelfTest).
		AddParams(toTest).
		AddExtraSessions(sessions...).
		Run(nil, &toDoList); err != nil {
		return nil, err
	}
	return toDoList, nil
}

// GetTestResult executes the TPM2_GetTestResult command and returns manufacturer-specific information
// regarding the results of a self-test as well as the test status.
//
// If TPM2_SelfTest hasn't been executed and a testable function hasn't been tested, then testResult
// will equal [ResponseNeedsTest]. If TPM2_SelfTest has been executed and testing is ongoing, then
// testResult will equal [ResponseTesting].
//
// If testing of all functions is complete without failure, testResult will be [ResponseSuccess]. If
// any test failed, testResult will be [ResponseFailure].
func (t *TPMContext) GetTestResult(sessions ...SessionContext) (outData MaxBuffer, testResult ResponseCode, err error) {
	if err := t.StartCommand(CommandGetTestResult).
		AddExtraSessions(sessions...).
		Run(nil, &outData, &testResult); err != nil {
		return nil, 0, err
	}
	return outData, testResult, nil
}
