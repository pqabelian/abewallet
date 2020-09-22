package waddrmgr

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abewallet/walletdb"
	"math/big"
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
	mpks        []ManagedAddressAbe //one payee may have more than one master address
	totalAmount int64
	states      []state
}

func (p PayeeManager) Name() string {
	return p.name
}
func (p PayeeManager) ChooseMAddr() (abeutil.MasterAddress,error) {
	index, err := cryptorand.Int(cryptorand.Reader, new(big.Int).SetInt64(int64(len(p.mpks))))
	if err!=nil{
		return nil,err
	}
	return p.mpks[index.Int64()],nil
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
func (p *PayeeManager) AddMPK(ns walletdb.ReadWriteBucket, addr ManagedAddressAbe) error {
	p.mpks = append(p.mpks, addr)
	return putPayeeManager(ns, p.name, p)
}
func (p *PayeeManager) RemoveMPK(ns walletdb.ReadWriteBucket, addr ManagedAddressAbe) error {
	index := -1
	for i := 0; i < len(p.mpks); i++ {
		if p.mpks[i] == addr {
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
	totalSize := 2 + 2 + len([]byte(p.name)) + 2 + 2*len(p.mpks) + 8 + 2 + 16*len(p.states)
	for _, mpk := range p.mpks {
		totalSize += mpk.SerializeSize()
	}
	return totalSize
}
func (p PayeeManager) Serialize() []byte {
	res := make([]byte, p.SerializeSize())
	offset := 0
	binary.BigEndian.PutUint16(res[offset:offset+2], uint16(p.SerializeSize()))
	offset += 2
	binary.BigEndian.PutUint16(res[offset:offset+2], uint16(len([]byte(p.name))))
	offset += 2
	copy(res[offset:offset+len([]byte(p.name))], p.name)
	offset += len([]byte(p.name))
	binary.BigEndian.PutUint16(res[offset:offset+2], uint16(len(p.mpks)))
	offset += 2
	for _, mpk := range p.mpks {
		binary.BigEndian.PutUint16(res[offset:offset+2], uint16(mpk.SerializeSize()))
		offset += 2
		copy(res[offset:offset+mpk.SerializeSize()], mpk.Serialize())
		offset += mpk.SerializeSize()
	}
	binary.BigEndian.PutUint64(res[offset:offset+8], uint64(p.totalAmount))
	offset += 8
	binary.BigEndian.PutUint16(res[offset:offset+2], uint16(len(p.states)))
	offset += 2
	for _, s := range p.states {
		copy(res[offset:offset+16], s.Serialize())
		offset += 16
	}
	return res
}
func (p PayeeManager) Deserialize(b []byte) error {
	totalSize := int(binary.BigEndian.Uint16(b[0:2]))
	if len(b) < totalSize {
		return fmt.Errorf("wrong size of serialized payee manager")
	}
	nameSize := int(binary.BigEndian.Uint16(b[2:4]))
	offset := 4
	p.name = string(b[offset : offset+nameSize])
	offset += nameSize
	numOfMPK := int(binary.BigEndian.Uint16(b[offset : offset+2]))
	offset += 2
	for i := 0; i < numOfMPK; i++ {
		lengthOfMPK := int(binary.BigEndian.Uint16(b[offset : offset+2]))
		offset += 2
		scheme := abecrypto.CryptoScheme(binary.BigEndian.Uint16(b[offset : offset+2]))
		var mpk abeutil.MasterAddress
		switch scheme {
		case abecrypto.CryptoSchemeSALRS:
			mpk = new(abeutil.MasterAddressSalrs)
		}
		mpk.Deserialize(b[offset : offset+lengthOfMPK])
		if p.mpks == nil {
			p.mpks = *new([]ManagedAddressAbe)
		}
		p.mpks = append(p.mpks, ManagedAddressAbe(mpk))
		offset += lengthOfMPK
	}
	p.totalAmount = int64(binary.BigEndian.Uint64(b[offset : offset+8]))
	offset += 8
	numOfStates := int(binary.BigEndian.Uint16(b[offset : offset+2]))
	offset += 2
	for i := 0; i < numOfStates; i++ {
		s := new(state)
		s.Deserialize(b[offset : offset+16])
		if p.states == nil {
			p.states = *new([]state)
		}
		p.states = append(p.states, *s)
		offset += 16
	}
	return nil
}
