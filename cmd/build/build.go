//go:build tools
// +build tools

/*
 * Copyright (C) 2024-2026 Holger de Carne
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
)

// Used via go:generate to perform build tasks.
func main() {
	switch os.Args[1] {
	case "fetch":
		fetch()
	case "generate":
		generate()
	}
}

// fetch external file
func fetch() {
	rsp, err := http.Get(os.Args[2])
	if err != nil {
		log.Fatal("download failure: ", err)
	}
	defer rsp.Body.Close()
	file, err := os.Create(os.Args[3])
	if err != nil {
		log.Fatal("create file failure: ", err)
	}
	defer file.Close()
	_, err = io.Copy(file, rsp.Body)
	if err != nil {
		log.Fatal("write file failure: ", err)
	}
}

// generate bridge client
func generate() {
	err := generateClient(os.Args[2], os.Args[3])
	if err != nil {
		log.Fatal("generate client failure: ", err)
	}
}

const generateClientInterfaceName string = "ClientWithResponsesInterface"
const generateWithResponseSuffix string = "WithResponse"
const generateWithBodyWithResponseSuffix string = "WithBodyWithResponse"
const generateReqEditorsParam string = "reqEditors"
const generateAuthenticateAPI string = "Authenticate"

func generateClient(apiSrc string, clientSrc string) error {
	fset := token.NewFileSet()
	apiSrcBytes, err := os.ReadFile(apiSrc)
	if err != nil {
		return err
	}
	f, err := parser.ParseFile(fset, apiSrc, apiSrcBytes, 0)
	if err != nil {
		return err
	}
	ast.Inspect(f, func(node ast.Node) bool {
		typeSpec, ok := node.(*ast.TypeSpec)
		if !ok || typeSpec.Name.Name != generateClientInterfaceName {
			return true
		}
		interfaceType, ok := typeSpec.Type.(*ast.InterfaceType)
		if !ok {
			return true
		}
		generator := &bridgeClientGenerator{
			buffer: &bytes.Buffer{},
		}
		generator.GeneratePreamble(apiSrc)
		generator.GenerateBridgeClientInterface(interfaceType)
		generator.GenerateBridgeClientImpl(interfaceType)
		err := generator.Source(clientSrc)
		if err != nil {
			panic(err)
		}
		return false
	})
	return nil
}

type bridgeClientGenerator struct {
	buffer *bytes.Buffer
}

func (generator *bridgeClientGenerator) GeneratePreamble(src string) {
	generator.buffer.WriteString("//generated from " + src + "\n")
	generator.buffer.WriteString("package hue\n\n")
	generator.buffer.WriteString("import (\n")
	generator.buffer.WriteString("\"context\"\n")
	generator.buffer.WriteString("\"github.com/tdrn-org/go-hue/api\"\n")
	generator.buffer.WriteString(")\n")
}

func (generator *bridgeClientGenerator) GenerateBridgeClientInterface(interfaceType *ast.InterfaceType) {
	generator.buffer.WriteString("// BridgeClient provides the Hue API functions provided by a bridge.\n")
	generator.buffer.WriteString("type BridgeClient interface {\n")
	generator.buffer.WriteString("MiddlewareClient\n")
	for _, method := range interfaceType.Methods.List {
		methodName := method.Names[0].Name
		if !strings.HasSuffix(methodName, generateWithResponseSuffix) || strings.HasSuffix(methodName, generateWithBodyWithResponseSuffix) {
			continue
		}
		apiName := strings.TrimSuffix(methodName, generateWithResponseSuffix)
		generator.buffer.WriteString("// " + apiName + " API call\n")
		generator.buffer.WriteString(apiName)
		funcType := method.Type.(*ast.FuncType)
		generator.buffer.WriteString(generator.fieldsString(funcType.Params.List, generateReqEditorsParam))
		generator.buffer.WriteString(generator.fieldsString(funcType.Results.List))
		generator.buffer.WriteString("\n")
	}
	generator.buffer.WriteString("}\n\n")
}

func (generator *bridgeClientGenerator) GenerateBridgeClientImpl(interfaceType *ast.InterfaceType) {
	generator.buffer.WriteString("type bridgeClient struct {\n")
	generator.buffer.WriteString("middlewareClient\n")
	generator.buffer.WriteString("apiClient api." + generateClientInterfaceName + "\n")
	generator.buffer.WriteString("}\n\n")
	for _, method := range interfaceType.Methods.List {
		methodName := method.Names[0].Name
		if !strings.HasSuffix(methodName, generateWithResponseSuffix) || strings.HasSuffix(methodName, generateWithBodyWithResponseSuffix) {
			continue
		}
		apiName := strings.TrimSuffix(methodName, generateWithResponseSuffix)
		generator.buffer.WriteString("func (client *bridgeClient) " + apiName)
		funcType := method.Type.(*ast.FuncType)
		generator.buffer.WriteString(generator.fieldsString(funcType.Params.List, generateReqEditorsParam))
		generator.buffer.WriteString(generator.fieldsString(funcType.Results.List))
		generator.buffer.WriteString("{\n")
		generator.buffer.WriteString("response, err := client.apiClient." + apiName + "WithResponse(")
		generator.buffer.WriteString(generator.paramsString(funcType.Params.List, generateReqEditorsParam))
		if apiName != generateAuthenticateAPI {
			generator.buffer.WriteString(", client.authenticator.AuthenticateRequest")
		}
		generator.buffer.WriteString(")\n")
		generator.buffer.WriteString("if err != nil {\n")
		generator.buffer.WriteString("return nil, bridgeClientWrapSystemError(err)\n")
		generator.buffer.WriteString("}\n")
		if apiName == generateAuthenticateAPI {
			generator.buffer.WriteString("client.authenticator.Authenticated(response)\n")
		}
		generator.buffer.WriteString("return response, bridgeClientApiError(response.HTTPResponse)\n")
		generator.buffer.WriteString("}\n\n")
	}
}

func (generator *bridgeClientGenerator) paramsString(params []*ast.Field, ignore ...string) string {
	buffer := &strings.Builder{}
	first := true
	for _, param := range params {
		paramName := param.Names[0].Name
		if slices.Contains(ignore, paramName) {
			continue
		}
		if first {
			first = false
		} else {
			buffer.WriteString(", ")
		}
		buffer.WriteString(paramName)
	}
	return buffer.String()
}

func (generator *bridgeClientGenerator) fieldsString(fields []*ast.Field, ignore ...string) string {
	buffer := &strings.Builder{}
	buffer.WriteString("(")
	first := true
	for _, field := range fields {
		fieldName := ""
		if len(field.Names) > 0 {
			fieldName = field.Names[0].Name
		}
		if slices.Contains(ignore, fieldName) {
			continue
		}
		if first {
			first = false
		} else {
			buffer.WriteString(", ")
		}
		buffer.WriteString(fieldName + " " + generator.exprString(field.Type))
	}
	buffer.WriteString(")")
	return buffer.String()
}

func (generator *bridgeClientGenerator) exprString(expr ast.Expr) string {
	switch expr := expr.(type) {
	case *ast.Ident:
		if expr.IsExported() {
			return "api." + expr.Name
		} else {
			return expr.Name
		}
	case *ast.SelectorExpr:
		return generator.exprString(expr.X) + "." + expr.Sel.Name
	case *ast.StarExpr:
		return "*" + generator.exprString(expr.X)
	default:
		return "any"
	}
}

func (generator *bridgeClientGenerator) Source(src string) error {
	source, err := format.Source(generator.buffer.Bytes())
	if err != nil {
		fmt.Println(generator.buffer.String())
		return err
	}
	file, err := os.Create(src)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(source)
	return err
}
