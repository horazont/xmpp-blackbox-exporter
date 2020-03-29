package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPingResultMatches(t *testing.T) {
	t.Run("success matches success", func(t *testing.T) {
		pr1 := PingResult{Success: true}
		pr2 := PingResult{Success: true}

		assert.True(t, pr1.Matches(pr2))
		assert.True(t, pr2.Matches(pr1))
	})

	t.Run("success does not match non-success", func(t *testing.T) {
		pr1 := PingResult{Success: true}
		pr2 := PingResult{}
		pr3 := PingResult{ErrorType: "foo", ErrorCondition: "bar"}

		assert.False(t, pr1.Matches(pr2))
		assert.False(t, pr1.Matches(pr3))
	})

	t.Run("error does not match success", func(t *testing.T) {
		pr1 := PingResult{ErrorType: "foo", ErrorCondition: "bar"}
		pr2 := PingResult{Success: true}

		assert.False(t, pr1.Matches(pr2))
	})

	t.Run("error requires equal type if given", func(t *testing.T) {
		pr1 := PingResult{ErrorType: "foo"}
		pr2 := PingResult{ErrorType: "foo"}
		pr3 := PingResult{ErrorType: "bar"}

		assert.True(t, pr1.Matches(pr2))
		assert.True(t, pr2.Matches(pr1))
		assert.False(t, pr1.Matches(pr3))
		assert.False(t, pr2.Matches(pr3))
		assert.False(t, pr3.Matches(pr1))
		assert.False(t, pr3.Matches(pr2))
	})

	t.Run("error requires equal condition if given", func(t *testing.T) {
		pr1 := PingResult{ErrorCondition: "foo"}
		pr2 := PingResult{ErrorCondition: "foo"}
		pr3 := PingResult{ErrorCondition: "bar"}

		assert.True(t, pr1.Matches(pr2))
		assert.True(t, pr2.Matches(pr1))
		assert.False(t, pr1.Matches(pr3))
		assert.False(t, pr2.Matches(pr3))
		assert.False(t, pr3.Matches(pr1))
		assert.False(t, pr3.Matches(pr2))
	})

	t.Run("error ignores condition if not given", func(t *testing.T) {
		pr1 := PingResult{ErrorType: "foo"}
		pr2 := PingResult{ErrorType: "foo", ErrorCondition: "fnord"}

		assert.True(t, pr1.Matches(pr2))
	})

	t.Run("error ignores type if not given", func(t *testing.T) {
		pr1 := PingResult{ErrorCondition: "foo"}
		pr2 := PingResult{ErrorType: "fnord", ErrorCondition: "foo"}

		assert.True(t, pr1.Matches(pr2))
	})

	t.Run("error requires both to match if given", func(t *testing.T) {
		pr1 := PingResult{ErrorType: "t1", ErrorCondition: "c1"}
		pr2 := PingResult{ErrorType: "t1", ErrorCondition: "c2"}
		pr3 := PingResult{ErrorType: "t2", ErrorCondition: "c2"}
		pr4 := PingResult{ErrorType: "t2", ErrorCondition: "c1"}

		pr5 := PingResult{ErrorType: "t1"}
		pr6 := PingResult{ErrorType: "t2"}

		pr7 := PingResult{ErrorCondition: "c1"}
		pr8 := PingResult{ErrorCondition: "c2"}

		assert.True(t, pr1.Matches(pr1))
		assert.False(t, pr1.Matches(pr2))
		assert.False(t, pr1.Matches(pr3))
		assert.False(t, pr1.Matches(pr4))

		assert.False(t, pr2.Matches(pr1))
		assert.True(t, pr2.Matches(pr2))
		assert.False(t, pr2.Matches(pr3))
		assert.False(t, pr2.Matches(pr4))

		assert.False(t, pr3.Matches(pr1))
		assert.False(t, pr3.Matches(pr2))
		assert.True(t, pr3.Matches(pr3))
		assert.False(t, pr3.Matches(pr4))

		assert.False(t, pr4.Matches(pr1))
		assert.False(t, pr4.Matches(pr2))
		assert.False(t, pr4.Matches(pr3))
		assert.True(t, pr4.Matches(pr4))

		assert.True(t, pr5.Matches(pr1))
		assert.True(t, pr5.Matches(pr2))
		assert.False(t, pr1.Matches(pr5))
		assert.False(t, pr2.Matches(pr5))

		assert.True(t, pr6.Matches(pr3))
		assert.True(t, pr6.Matches(pr4))
		assert.False(t, pr3.Matches(pr6))
		assert.False(t, pr4.Matches(pr6))

		assert.True(t, pr7.Matches(pr1))
		assert.True(t, pr7.Matches(pr4))
		assert.False(t, pr1.Matches(pr7))
		assert.False(t, pr4.Matches(pr7))

		assert.True(t, pr8.Matches(pr2))
		assert.True(t, pr8.Matches(pr3))
		assert.False(t, pr2.Matches(pr8))
		assert.False(t, pr3.Matches(pr8))
	})
}
