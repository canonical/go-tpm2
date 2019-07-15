package tpm2

func (t *tpmImpl) SelfTest(fullTest bool) error {
	return t.RunCommand(CommandSelfTest, Format{0, 1}, Format{0, 0}, fullTest)
}

func (t *tpmImpl) IncrementalSelfTest(toTest AlgorithmList) (AlgorithmList, error) {
	var toDoList AlgorithmList
	if err := t.RunCommand(CommandIncrementalSelfTest, Format{0, 1}, Format{0, 1}, toTest,
		&toDoList); err != nil {
		return nil, err
	}
	return toDoList, nil
}

func (t *tpmImpl) GetTestResult() (MaxBuffer, ResponseCode, error) {
	var outData MaxBuffer
	var testResult ResponseCode
	if err := t.RunCommand(CommandGetTestResult, Format{0, 0}, Format{0, 2}, &outData,
		&testResult); err != nil {
		return nil, 0, err
	}
	return outData, testResult, nil
}
