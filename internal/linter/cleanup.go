package linter

// cleanupStack owns acquired resources and releases them in reverse order.
// Cleanup functions must be registered immediately, including when the
// acquisition call also returned an error.
type cleanupStack []func()

func (s *cleanupStack) Add(cleanup func()) {
	if cleanup != nil {
		*s = append(*s, cleanup)
	}
}

func (s *cleanupStack) Close() {
	if s == nil {
		return
	}
	for i := len(*s) - 1; i >= 0; i-- {
		(*s)[i]()
	}
	*s = nil
}
