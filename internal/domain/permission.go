// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package domain

// PlanPermission is one exact operation permission checked for the identity
// that will execute it. A denied permission remains part of the reviewable
// plan; the execution gate is responsible for blocking it.
type PlanPermission struct {
	Identity   ExecutionIdentity `json:"identity"`
	Permission string            `json:"permission"`
	Granted    bool              `json:"granted"`
}
