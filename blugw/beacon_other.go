//go:build !linux

package blugw

import "context"

func beacon(context.Context) {} // unreachable: Scan rejects TimeBeacon first
