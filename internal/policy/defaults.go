package policy

func defaultPolicy() Config {
	config := Config{
		Policy: Policy{
			Length: Length{
				Min: 12,
			},
			Exclude:  "",
			Attempts: 100,
			Forbid: Forbid{
				RepeatRun:   0,
				RepeatTotal: false,
				Sequences: Sequences{
					Alphabet: 0,
					Keyboard: 0,
					Layouts:  []string{"qwerty"},
				},
				Dictionary: Dictionary{
					Path:            "",
					MinLength:       4,
					CaseInsensitive: true,
					Leet:            false,
				},
				Context: Context{
					MinLength: 3,
				},
			},
		},
		Issue: Issue{
			PoolSize: 16,
			//Store:       "", пока не понятно какое значение по умолчанию, поэтому оставим пустым
			History:     History{Window: 0, Ttl: ""},
			RotateAfter: "",
		},
	}

	return config
}
