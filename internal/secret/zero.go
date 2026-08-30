package secret

import "runtime"

// Zero затирает содержимое переданного байтового среза нулевыми значениями.
func Zero(value []byte) {
	for i := range value {
		value[i] = 0
	}

	runtime.KeepAlive(value)
}
