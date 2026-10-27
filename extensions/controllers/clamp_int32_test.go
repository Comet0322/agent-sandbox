/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"math"
	"testing"
)

func TestClampInt32Saturates(t *testing.T) {
	for _, tc := range []struct {
		in   int
		want int32
	}{
		{0, 0},
		{300, 300},
		{-5, -5},
		{math.MaxInt32, math.MaxInt32},
		{math.MaxInt32 + 1, math.MaxInt32}, // a plain int32() would wrap to MinInt32
		{math.MinInt32 - 1, math.MinInt32},
	} {
		if got := clampInt32(tc.in); got != tc.want {
			t.Errorf("clampInt32(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
