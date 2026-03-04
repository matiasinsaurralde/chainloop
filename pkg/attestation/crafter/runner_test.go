//
// Copyright 2026 The Chainloop Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crafter

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRunnerGlobalTimeoutCtxEventuallyExpires(t *testing.T) {
	t.Helper()

	deadline, ok := timeoutCtx.Deadline()
	require.True(t, ok, "global timeoutCtx should always have a deadline")

	wait := time.Until(deadline) + 250*time.Millisecond
	if wait > 0 {
		time.Sleep(wait)
	}

	require.Error(t, timeoutCtx.Err(), "global timeoutCtx should be canceled after its deadline")

	freshCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	require.NoError(t, freshCtx.Err(), "fresh timeout context should be active")
}
