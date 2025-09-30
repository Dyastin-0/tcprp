package limiter

import (
	"time"

	"golang.org/x/time/rate"
)

type OptFunc func(*Limiter)

func WithRPS(rps int) OptFunc {
	return func(l *Limiter) {
		l.rate = rate.Limit(rps)
	}
}

func WithBurst(burst int) OptFunc {
	return func(l *Limiter) {
		l.burst = burst
	}
}

func WithCooldown(cd time.Duration) OptFunc {
	return func(l *Limiter) {
		l.cooldown = cd
	}
}

func WithDefaultRPS(l *Limiter) {
	l.rate = rate.Limit(10)
}

func WithDefaultBurst(l *Limiter) {
	l.burst = 10
}

func WithDefaultCooldown(l *Limiter) {
	l.cooldown = 5 * time.Minute
}
