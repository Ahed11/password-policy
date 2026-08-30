package random

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestProjectDoesNotImportMathRand(t *testing.T) {
	root := filepath.Join("..", "..")

	err := filepath.WalkDir(
		root,
		func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if entry.IsDir() {
				switch entry.Name() {
				case ".git", "build":
					return filepath.SkipDir
				}

				return nil
			}

			if filepath.Ext(path) != ".go" {
				return nil
			}

			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}

			for _, importSpec := range file.Imports {
				importPath, err := strconv.Unquote(importSpec.Path.Value)
				if err != nil {
					return err
				}

				forbidden := strings.Join([]string{"math", "rand"}, "/")

				if importPath == forbidden {
					t.Errorf("%s imports forbidden package %s", path, forbidden)
				}
			}

			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
}
