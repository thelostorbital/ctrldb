// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

// Package app owns the WF-TEST-01 orchestration core: the single mutation
// gateway, the execution engine over compiled plans, and the typed adapter
// interfaces every provider mutation must satisfy.
//
// The package performs no I/O of its own. Durable records reach it through the
// ControlStore interface, provider reads through StepObserver, and provider
// mutations only through adapter interfaces whose entry points require a
// gateway-issued MutationAuthorization. No exported constructor accepts a bare
// resource name or argument vector.
package app
