package scan

import "fmt"

type InventoryDriftError struct{ Err error }

func (e *InventoryDriftError) Error() string { return e.Err.Error() }
func (e *InventoryDriftError) Unwrap() error { return e.Err }

type InvalidSubmissionError struct{ Problems []string }

func (e *InvalidSubmissionError) Error() string {
	return fmt.Sprintf("invalid submission: %s", joinProblems(e.Problems))
}

func joinProblems(problems []string) string {
	result := ""
	for index, problem := range problems {
		if index > 0 {
			result += "; "
		}
		result += problem
	}
	return result
}
