package store

import (
	"fmt"
	"strings"
	"sync"

	stnrv1a1 "github.com/l7mp/stunner/pkg/apis/v1alpha1"
)

type Object = *stnrv1a1.StunnerConfig

var ConfigMaps = NewStore()

type Store interface {
	Reset([]Object)
	Get() []Object
	Len() int
	String() string
}

type storeImpl struct {
	lock    sync.RWMutex
	objects []Object
}

// NewStore creates a new local object storage
func NewStore() Store {
	return &storeImpl{
		objects: []Object{},
	}
}

func (s *storeImpl) Get() []Object {
	s.lock.RLock()
	defer s.lock.RUnlock()

	ret := make([]Object, len(s.objects))
	copy(ret, s.objects)

	return ret
}

func (s *storeImpl) Reset(objects []Object) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.objects = make([]Object, len(objects))
	copy(s.objects, objects)
}

func (s *storeImpl) Len() int {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return len(s.objects)
}

func (s *storeImpl) String() string {
	os := s.Get()
	ret := []string{}
	for _, o := range os {
		o := o
		ret = append(ret, o.String())
	}
	return fmt.Sprintf("store (%d objects): %s", len(os),
		strings.Join(ret, ", "))
}
