package operator

import (
	"fmt"
	"regexp"
	"sync"

	"github.com/cavoq/PCL/internal/node"
)

var (
	regexCache   = make(map[string]*regexp.Regexp)
	regexCacheMu sync.RWMutex
)

func getCompiledRegex(pattern string) (*regexp.Regexp, error) {
	regexCacheMu.RLock()
	re, exists := regexCache[pattern]
	regexCacheMu.RUnlock()

	if exists {
		return re, nil
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}

	regexCacheMu.Lock()
	regexCache[pattern] = re
	regexCacheMu.Unlock()

	return re, nil
}

type Regex struct{}

func (Regex) Name() string { return "regex" }

func (Regex) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	return matchRegex(n, operands)
}

type NotRegex struct{}

func (NotRegex) Name() string { return "notRegex" }

func (NotRegex) Evaluate(n *node.Node, _ *EvaluationContext, operands []any) (bool, error) {
	match, err := matchRegex(n, operands)
	if err != nil {
		return false, err
	}
	return !match, nil
}

func matchRegex(n *node.Node, operands []any) (bool, error) {
	if n == nil || len(operands) != 1 {
		return false, nil
	}

	pattern, ok := operands[0].(string)
	if !ok {
		return false, fmt.Errorf("regex operator requires a string pattern operand")
	}

	re, err := getCompiledRegex(pattern)
	if err != nil {
		return false, err
	}

	str, ok := n.Value.(string)
	if !ok {
		return false, nil
	}

	return re.MatchString(str), nil
}
