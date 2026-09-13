package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Every flag this command defines is read somewhere.
//
// A flag that is parsed, documented in -help and handed to nothing is the most
// convincing kind of defect: the operator types it, the command accepts it, and
// the report is exactly what it would have been without it. This repository has
// shipped a field set and handed to nothing twice. On 2026-09-13 a sabotage
// that left -helo parsed and never passed to runMail escaped every test in this
// package, because run() reads the global flag set and nothing drives it.
//
// So the source is read rather than the program run. Every variable assigned
// from a flag.* call in run() has to be dereferenced at least once — which is
// what reading a flag's value is. It says nothing about whether the value goes
// to the right place, and does not pretend to; it catches the flag that goes
// nowhere, for every flag, including the ones not written yet.
func TestEveryFlagIsReadSomewhere(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing main.go: %v", err)
	}

	var run *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "run" {
			run = fn
		}
	}
	if run == nil {
		t.Fatal("main.go has no run function, so this test asserts nothing")
	}

	isFlagCall := func(expr ast.Expr) bool {
		call, ok := expr.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		pkg, ok := sel.X.(*ast.Ident)
		return ok && pkg.Name == "flag" && sel.Sel.Name != "Parse" && sel.Sel.Name != "Args" &&
			sel.Sel.Name != "PrintDefaults" && sel.Sel.Name != "Usage"
	}

	// Names assigned from a flag call, in either spelling: var ( x = flag.X() )
	// and x := flag.X().
	defined := map[string]token.Pos{}
	ast.Inspect(run.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ValueSpec:
			for i, value := range node.Values {
				if isFlagCall(value) && i < len(node.Names) {
					defined[node.Names[i].Name] = node.Names[i].Pos()
				}
			}
		case *ast.AssignStmt:
			for i, value := range node.Rhs {
				if isFlagCall(value) && i < len(node.Lhs) {
					if ident, ok := node.Lhs[i].(*ast.Ident); ok {
						defined[ident.Name] = ident.Pos()
					}
				}
			}
		}
		return true
	})
	if len(defined) == 0 {
		t.Fatal("no flags were found in run(), so this test asserts nothing")
	}

	// Every *name read.
	read := map[string]int{}
	ast.Inspect(run.Body, func(n ast.Node) bool {
		if star, ok := n.(*ast.StarExpr); ok {
			if ident, ok := star.X.(*ast.Ident); ok {
				read[ident.Name]++
			}
		}
		return true
	})

	for name, pos := range defined {
		if read[name] == 0 {
			t.Errorf("the flag held in %q (%s) is parsed and its value is never read: an operator "+
				"can type it and nothing changes", name, fset.Position(pos))
		}
	}
}
