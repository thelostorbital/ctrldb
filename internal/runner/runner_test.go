// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package runner_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/runner"
)

func TestValidateRequestAcceptsArgvWithoutInterpretingShellSyntax(t *testing.T) {
	t.Parallel()

	request := validRequest()
	request.Arguments = []string{"compute", "instances", "describe", "name; still-one-argument"}

	if err := runner.ValidateRequest(request); err != nil {
		t.Fatalf("ValidateRequest() error = %v", err)
	}
}

func TestValidateRequestRejectsUnsafeOrIncompleteRequests(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*runner.Request)
	}{
		{name: "empty executable", mutate: func(request *runner.Request) { request.Executable = "" }},
		{name: "combined command", mutate: func(request *runner.Request) { request.Executable = "gcloud compute" }},
		{name: "executable control", mutate: func(request *runner.Request) { request.Executable = "gcloud\n" }},
		{name: "relative executable path", mutate: func(request *runner.Request) { request.Executable = "bin/gcloud" }},
		{name: "unclean executable path", mutate: func(request *runner.Request) { request.Executable = "/usr/bin/../bin/gcloud" }},
		{name: "shell executable", mutate: func(request *runner.Request) { request.Executable = "/bin/sh" }},
		{name: "generic launcher", mutate: func(request *runner.Request) { request.Executable = "env" }},
		{name: "argument control", mutate: func(request *runner.Request) { request.Arguments = []string{"compute\ninstances"} }},
		{name: "invalid environment name", mutate: func(request *runner.Request) { request.Environment[0].Name = "Path" }},
		{name: "unknown environment name", mutate: func(request *runner.Request) { request.Environment[0].Name = "SECRET" }},
		{name: "duplicate environment name", mutate: func(request *runner.Request) {
			request.Environment = append(request.Environment, request.Environment[0])
		}},
		{name: "empty environment value", mutate: func(request *runner.Request) { request.Environment[0].Value = "" }},
		{name: "environment value control", mutate: func(request *runner.Request) { request.Environment[0].Value = "bad\nvalue" }},
		{name: "missing path", mutate: removeEnvironment("PATH")},
		{name: "missing home", mutate: removeEnvironment("HOME")},
		{name: "missing config", mutate: removeEnvironment("CLOUDSDK_CONFIG")},
		{name: "missing locale", mutate: removeEnvironment("LANG")},
		{name: "prompts enabled", mutate: setEnvironment("CLOUDSDK_CORE_DISABLE_PROMPTS", "0")},
		{name: "usage reporting enabled", mutate: setEnvironment("CLOUDSDK_CORE_DISABLE_USAGE_REPORTING", "0")},
		{name: "color enabled", mutate: setEnvironment("NO_COLOR", "0")},
		{name: "relative home", mutate: setEnvironment("HOME", "home/operator")},
		{name: "relative config", mutate: setEnvironment("CLOUDSDK_CONFIG", "config/gcloud")},
		{name: "relative path entry", mutate: setEnvironment("PATH", "/usr/bin:local/bin")},
		{name: "empty path entry", mutate: setEnvironment("PATH", "/usr/bin::/bin")},
		{name: "zero timeout", mutate: func(request *runner.Request) { request.Timeout = 0 }},
		{name: "excess timeout", mutate: func(request *runner.Request) { request.Timeout = runner.MaxTimeout + time.Nanosecond }},
		{name: "zero stdout limit", mutate: func(request *runner.Request) { request.StdoutLimitBytes = 0 }},
		{name: "excess stdout limit", mutate: func(request *runner.Request) { request.StdoutLimitBytes = runner.MaxStdoutBytes + 1 }},
		{name: "zero stderr limit", mutate: func(request *runner.Request) { request.StderrLimitBytes = 0 }},
		{name: "excess stderr limit", mutate: func(request *runner.Request) { request.StderrLimitBytes = runner.MaxStderrBytes + 1 }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			request := validRequest()
			test.mutate(&request)

			err := runner.ValidateRequest(request)
			if !errors.Is(err, runner.ErrInvalidRequest) {
				t.Fatalf("ValidateRequest() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestEnvironmentStringsReturnsStableDetachedVector(t *testing.T) {
	t.Parallel()

	request := validRequest()
	got, err := runner.EnvironmentStrings(request)
	if err != nil {
		t.Fatalf("EnvironmentStrings() error = %v", err)
	}
	want := []string{
		"CLOUDSDK_CONFIG=/tmp/ctrldb-gcloud",
		"CLOUDSDK_CORE_DISABLE_PROMPTS=1",
		"CLOUDSDK_CORE_DISABLE_USAGE_REPORTING=1",
		"HOME=/tmp/ctrldb-home",
		"LANG=C.UTF-8",
		"NO_COLOR=1",
		"PATH=/usr/bin:/bin",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EnvironmentStrings() = %#v, want %#v", got, want)
	}

	request.Environment[0].Value = "/changed"
	if !reflect.DeepEqual(got, want) {
		t.Fatal("EnvironmentStrings() result aliases request storage")
	}
}

func TestEnvironmentStringsRejectsInvalidRequest(t *testing.T) {
	t.Parallel()

	request := validRequest()
	request.Timeout = 0
	got, err := runner.EnvironmentStrings(request)
	if got != nil || !errors.Is(err, runner.ErrInvalidRequest) {
		t.Fatalf("EnvironmentStrings() = (%#v, %v), want (nil, ErrInvalidRequest)", got, err)
	}
}

type fakeRunner struct{}

func (fakeRunner) Run(context.Context, runner.Request) (runner.Result, error) {
	return runner.Result{}, nil
}

var _ runner.Runner = fakeRunner{}

func validRequest() runner.Request {
	return runner.Request{
		Executable: "/usr/bin/gcloud",
		Arguments:  []string{"version", "--format=json"},
		Environment: []runner.EnvironmentVariable{
			{Name: "PATH", Value: "/usr/bin:/bin"},
			{Name: "HOME", Value: "/tmp/ctrldb-home"},
			{Name: "CLOUDSDK_CONFIG", Value: "/tmp/ctrldb-gcloud"},
			{Name: "CLOUDSDK_CORE_DISABLE_PROMPTS", Value: "1"},
			{Name: "CLOUDSDK_CORE_DISABLE_USAGE_REPORTING", Value: "1"},
			{Name: "NO_COLOR", Value: "1"},
			{Name: "LANG", Value: "C.UTF-8"},
		},
		Timeout:          time.Minute,
		StdoutLimitBytes: runner.MaxStdoutBytes,
		StderrLimitBytes: runner.MaxStderrBytes,
	}
}

func removeEnvironment(name string) func(*runner.Request) {
	return func(request *runner.Request) {
		filtered := request.Environment[:0]
		for _, variable := range request.Environment {
			if variable.Name != name {
				filtered = append(filtered, variable)
			}
		}
		request.Environment = filtered
	}
}

func setEnvironment(name, value string) func(*runner.Request) {
	return func(request *runner.Request) {
		for index := range request.Environment {
			if request.Environment[index].Name == name {
				request.Environment[index].Value = value
				return
			}
		}
	}
}
