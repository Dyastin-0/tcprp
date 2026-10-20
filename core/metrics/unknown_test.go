package metrics

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnknownSNITracker(t *testing.T) {
	tracker := NewUnknownSNITracker(2)

	require.True(t, tracker.Observe("A.example.com"))
	require.False(t, tracker.Observe("a.example.com")) // normalized duplicate
	require.True(t, tracker.Observe("b.example.com"))
	require.False(t, tracker.Observe("c.example.com")) // cap reached

	tracker.Block()
	tracker.Block()

	total, blocked, entries := tracker.Snapshot()
	require.Equal(t, uint64(4), total)
	require.Equal(t, uint64(2), blocked)
	require.Len(t, entries, 2)
	require.Equal(t, "a.example.com", entries[0].SNI)
	require.Equal(t, uint64(2), entries[0].Count)
	require.Equal(t, "b.example.com", entries[1].SNI)
}

func TestUnknownSNITrackerNoSNI(t *testing.T) {
	tracker := NewUnknownSNITracker(4)
	require.True(t, tracker.Observe(""))

	_, _, entries := tracker.Snapshot()
	require.Len(t, entries, 1)
	require.Equal(t, noSNILabel, entries[0].SNI)
}

func TestUnknownSNITrackerSanitizes(t *testing.T) {
	tracker := NewUnknownSNITracker(4)
	require.True(t, tracker.Observe("bad\nname\x00.com"))

	_, _, entries := tracker.Snapshot()
	require.Len(t, entries, 1)
	require.Equal(t, "badname.com", entries[0].SNI)
}
