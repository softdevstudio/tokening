//go:build windows

package stdio

func fakeChild() int { return 0 }
func alive(int) bool { return false }
