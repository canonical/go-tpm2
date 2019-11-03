// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 9 - Start-up

func (t *TPMContext) SelfTest(fullTest bool, sessions ...*Session) error {
	return t.RunCommand(CommandSelfTest, sessions, Separator, fullTest)
}

func (t *TPMContext) IncrementalSelfTest(toTest AlgorithmList, sessions ...*Session) (AlgorithmList, error) {
	var toDoList AlgorithmList
	if err := t.RunCommand(CommandIncrementalSelfTest, sessions,
		Separator,
		toTest, Separator,
		Separator,
		&toDoList); err != nil {
		return nil, err
	}
	return toDoList, nil
}

func (t *TPMContext) GetTestResult(sessions ...*Session) (MaxBuffer, ResponseCode, error) {
	var outData MaxBuffer
	var testResult ResponseCode
	if err := t.RunCommand(CommandGetTestResult, sessions, Separator, Separator, Separator, &outData, &testResult); err != nil {
		return nil, 0, err
	}
	return outData, testResult, nil
}
