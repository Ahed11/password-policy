package secret

import "runtime"

func Zero(value []byte) {
	for i := range value {
		value[i] = 0
	}

	runtime.KeepAlive(value)
}
