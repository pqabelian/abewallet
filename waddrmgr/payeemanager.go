package waddrmgr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abewallet/walletdb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	mathrand "math/rand"
	"time"
)

type state struct {
	time   time.Time //when give coin to this payee
	amount int64     //how much
}

func (s *state) Serialize() []byte {
	var res [16]byte
	binary.BigEndian.PutUint64(res[0:8], uint64(s.time.Unix()))
	binary.BigEndian.PutUint64(res[8:], uint64(s.amount))
	return res[:]

}
func (s *state) Deserialize(b []byte) error {
	if len(b) != 16 {
		return fmt.Errorf("timestamp's length is wrong")
	}
	s.time = time.Unix(int64(binary.BigEndian.Uint64(b[0:8])), 0)
	s.amount = int64(binary.BigEndian.Uint64(b[8:16]))
	return nil
}

type PayeeManager struct {
	name        string
	rootManager *ManagerAbe
	mpks        [][]byte //one payee may have more than one master address
	totalAmount int64
	states      []state
}

func (p PayeeManager) Name() string {
	return p.name
}
func (p PayeeManager) ChooseMAddr() ([]byte, error) {
	if len(p.mpks) == 0 {
		return nil, errors.New("this payee has no master address, please add it.")
	}
	i := mathrand.Intn(len(p.mpks))
	return p.mpks[i], nil
}
func (p *PayeeManager) ChangeName(ns walletdb.ReadWriteBucket, newName string) error {
	p.name = newName
	return putPayeeManager(ns, p.name, p)

}
func (p *PayeeManager) Payee(ns walletdb.ReadWriteBucket, amount int64) error {
	if len(p.mpks) == 0 {
		return fmt.Errorf("this payee has 0 master public key")
	}
	p.totalAmount += amount
	p.states = append(p.states, state{
		time:   time.Now(),
		amount: amount,
	})
	return putPayeeManager(ns, p.name, p)
}
func (p *PayeeManager) AddMPK(ns walletdb.ReadWriteBucket, addr []byte) error {
	for i := 0; i < len(p.mpks); i++ {
		if bytes.Equal(p.mpks[i], addr) {
			return fmt.Errorf("the payee had the same master address.")
		}
	}
	p.mpks = append(p.mpks, addr)
	return putPayeeManager(ns, p.name, p) // update the payee manager in database
}
func (p *PayeeManager) RemoveMPK(ns walletdb.ReadWriteBucket, addr []byte) error {
	index := -1
	for i := 0; i < len(p.mpks); i++ {
		if bytes.Equal(p.mpks[i], addr) {
			index = i
			break
		}
	}
	if index != -1 {
		p.mpks = append(p.mpks[:index], p.mpks[index+1:]...)
		return putPayeeManager(ns, p.name, p)
	} else {
		return fmt.Errorf("the payee %s has no addr %v", p.name, addr)
	}
}

// length of paymanager||name||num of mpk||[length of mpk||mpk...]||num of state||[state...]
func (p PayeeManager) SerializeSize() int {
	totalSize := 8 + 2 + len([]byte(p.name)) + 2 + len(p.mpks)*4 + 8 + 2 + 16*len(p.states)
	for _, mpk := range p.mpks {
		totalSize += len(mpk)
	}
	return totalSize
}
func (p PayeeManager) Serialize() []byte {
	res := make([]byte, p.SerializeSize())
	offset := 0
	// total length of the payee manager
	binary.BigEndian.PutUint64(res[offset:offset+8], uint64(p.SerializeSize()))
	offset += 8
	// length of name
	binary.BigEndian.PutUint16(res[offset:offset+2], uint16(len([]byte(p.name))))
	offset += 2
	// name
	copy(res[offset:offset+len([]byte(p.name))], []byte(p.name))
	offset += len([]byte(p.name))
	// number of master public key1
	binary.BigEndian.PutUint16(res[offset:offset+2], uint16(len(p.mpks)))
	offset += 2
	for _, mpk := range p.mpks {
		// length of master public key
		binary.BigEndian.PutUint32(res[offset:offset+4], uint32(len(mpk)))
		offset += 4
		// master public key
		copy(res[offset:offset+len(mpk)], mpk)
		offset += len(mpk)
	}
	// total amount
	binary.BigEndian.PutUint64(res[offset:offset+8], uint64(p.totalAmount))
	offset += 8
	// length of state
	binary.BigEndian.PutUint16(res[offset:offset+2], uint16(len(p.states)))
	offset += 2
	for _, s := range p.states {
		// time(4 bytes) + amount(4 bytes)
		copy(res[offset:offset+16], s.Serialize())
		offset += 16
	}
	return res
}
func (p *PayeeManager) Deserialize(b []byte) error {
	offset := 0
	totalSize := int(binary.BigEndian.Uint64(b[offset : offset+8]))
	offset += 8
	if len(b) < totalSize {
		return fmt.Errorf("wrong size of serialized payee manager")
	}
	nameSize := int(binary.BigEndian.Uint16(b[offset : offset+2]))
	offset += 2
	p.name = string(b[offset : offset+nameSize])
	offset += nameSize
	numOfMPK := int(binary.BigEndian.Uint16(b[offset : offset+2]))
	offset += 2
	if p.mpks == nil {
		p.mpks = make([][]byte, 0, numOfMPK)
	}
	for i := 0; i < numOfMPK; i++ {
		lengthOfMPK := int(binary.BigEndian.Uint32(b[offset : offset+4]))
		offset += 4
		scheme := abecryptoparam.CryptoScheme(binary.BigEndian.Uint32(b[offset : offset+4]))
		if scheme == abecryptoparam.CryptoSchemePQRingCT {
		} else {
			return errors.New("unsupported address scheme")
		}

		//var mpk abeutil.MasterAddress
		//switch scheme {
		//case abecrypto.CryptoSchemeSALRS:
		//	mpk = new(abeutil.MasterAddressSalrs)
		//case abecrypto.CryptoSchemePQRINGCT:
		//
		//}
		mpk := make([]byte, lengthOfMPK)
		copy(mpk, b[offset:offset+lengthOfMPK])
		offset += lengthOfMPK
		p.mpks = append(p.mpks, mpk)
	}
	p.totalAmount = int64(binary.BigEndian.Uint64(b[offset : offset+8]))
	offset += 8
	numOfStates := int(binary.BigEndian.Uint16(b[offset : offset+2]))
	offset += 2
	if p.states == nil {
		p.states = make([]state, 0, numOfStates)
	}
	for i := 0; i < numOfStates; i++ {
		s := new(state)
		s.Deserialize(b[offset : offset+16])
		offset += 16
		p.states = append(p.states, *s)
	}
	return nil
}
