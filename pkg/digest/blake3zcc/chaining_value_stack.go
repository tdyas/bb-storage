package blake3zcc

// ChainingValueStack implements BLAKE3's Chaining Value Stack, as
// specified in section 5.1.2 on pages 15 to 17.
//
// The Chaining Value Stack is a simple data structure that is used to
// compute the root node of a Merkle tree. Upon creation, it corresponds
// with an empty Merkle tree. Nodes may be appended to the right hand
// side of the tree. As only the final root node is computed, appending
// nodes may lead to immediate compaction into parent nodes.
type ChainingValueStack struct {
	stack      [][8]uint32
	totalNodes uint64
}

// NewChainingValueStack creates an empty ChainValueStack that
// corresponds to an empty Merkle tree.
func NewChainingValueStack() *ChainingValueStack {
	return &ChainingValueStack{}
}

// AppendNode appends a node to the right hand side of the Merkle tree.
func (s *ChainingValueStack) AppendNode(n *Node) {
	chainingValue := truncate(compress(&n.chainingValue, &n.m, 0, n.blockSize, n.flags))
	for totalNodes := s.totalNodes; totalNodes&1 != 0; totalNodes >>= 1 {
		// One or more subtrees are now completed. Create parent
		// nodes as specified in section 2.5 on page 7 and 8.
		m := concatenate(&s.stack[len(s.stack)-1], &chainingValue)
		s.stack = s.stack[:len(s.stack)-1]
		chainingValue = truncate(compress(&iv, &m, 0, maximumBlockSize, flagParent))
	}
	s.stack = append(s.stack, chainingValue)
	s.totalNodes++
}

// GetRootNode terminates the Merkle tree by inserting a final node on
// the right hand side. It then computes and returns the root node of
// the Merkle tree. This node is used to compute BLAKE3's output hash.
func (s *ChainingValueStack) GetRootNode(lastNode *Node) Node {
	n := *lastNode
	for i := len(s.stack) - 1; i >= 0; i-- {
		v := truncate(compress(&n.chainingValue, &n.m, 0, n.blockSize, n.flags))
		chainingValue := concatenate(&s.stack[i], &v)
		n = NewParentNode(&chainingValue)
	}
	return n
}
