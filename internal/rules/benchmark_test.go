package rules

import "testing"

func BenchmarkCheckPasswordLength20(b *testing.B) {
	options := Options{
		RepeatRun:        2,
		RepeatTotal:      true,
		AlphabetSequence: 3,
		KeyboardSequence: 3,
		KeyboardLayouts: []string{
			"qwerty",
			"jcuken",
		},

		ContextValues: []string{
			"service",
			"svc-01",
			"example.com",
		},

		ContextMinLength:       3,
		ContextCaseInsensitive: true,
		ContextLeet:            true,
	}

	cases := []struct {
		name           string
		password       []byte
		wantViolations bool
	}{
		{
			name:           "clean",
			password:       []byte("A7!m2#Q9$v4&Z6*e8?xK"),
			wantViolations: false,
		},
		{
			name:           "violating",
			password:       []byte("aaabcdeqwertyservice"),
			wantViolations: true,
		},
	}

	for _, testCase := range cases {
		b.Run(testCase.name, func(b *testing.B) {
			violations, err := Check(testCase.password, options)
			if err != nil {
				b.Fatalf("check benchmark password: %v", err)
			}

			if testCase.wantViolations && len(violations) == 0 {
				b.Fatal("benchmark password must produce violations")
			}

			if !testCase.wantViolations && len(violations) != 0 {
				b.Fatalf("benchmark password unexpectedly produced %d violations", len(violations))
			}

			b.ReportAllocs()
			b.SetBytes(int64(len(testCase.password)))

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := Check(testCase.password, options)
				if err != nil {
					b.Fatal(err)
				}
			}
		},
		)
	}
}
