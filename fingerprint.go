package main

import "github.com/yelinaung/go-haikunator"

type Fingerprint struct {
    delta uint64
}

func (fg Fingerprint) String() string {
    return haikunator.New(int64(fg.delta)).Haikunate()
}

func (fg Fingerprint) matches_haiku(haiku string) (bool) {
    return fg.String() == haiku;
}

func (fg Fingerprint) matches_delta(delta uint64) (bool) {
    return fg.delta == delta;
}
