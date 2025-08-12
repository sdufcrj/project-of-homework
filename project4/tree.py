import hashlib
import struct
from collections import namedtuple

# RFC6962定义的节点类型
LEAF_PREFIX = b'\x00'
INTERNAL_PREFIX = b'\x01'


# 证明结构
class MerkleProof:
    def __init__(self, leaf_index, path):
        self.leaf_index = leaf_index
        self.path = path


class Node:
    def __init__(self):
        self.hash = None
        self.left_index = 0
        self.right_index = 0
        self.left_child = None
        self.right_child = None
        self.parent = None


class SortedMerkleTree:
    def __init__(self):
        self.root = None
        self.leaf_count = 0
        self.leaf_data = []

    def _hash_leaf(self, data):
        return hashlib.sha256(LEAF_PREFIX + data).digest()

    def _hash_internal(self, left_hash, right_hash):
        return hashlib.sha256(INTERNAL_PREFIX + left_hash + right_hash).digest()

    def _build_tree(self, start, end):
        """递归构建Merkle树"""
        if start == end:
            # 叶子节点
            node = Node()
            node.left_index = start
            node.right_index = end
            node.hash = self._hash_leaf(self.leaf_data[start])
            return node

        # 内部节点
        mid = (start + end) // 2
        left_child = self._build_tree(start, mid)
        right_child = self._build_tree(mid + 1, end)

        node = Node()
        node.left_index = start
        node.right_index = end
        node.left_child = left_child
        node.right_child = right_child
        left_child.parent = node
        right_child.parent = node
        node.hash = self._hash_internal(left_child.hash, right_child.hash)

        return node

    def build_tree(self, sorted_data):
        """构建排序的Merkle树"""
        if not sorted_data:
            self.root = None
            self.leaf_count = 0
            return

        self.leaf_data = sorted_data
        self.leaf_count = len(sorted_data)
        self.root = self._build_tree(0, self.leaf_count - 1)

    def get_root_hash(self):
        """获取根哈希"""
        return self.root.hash if self.root else None

    def generate_inclusion_proof(self, leaf_index):
        """生成存在性证明"""
        if leaf_index < 0 or leaf_index >= self.leaf_count:
            return None

        path = []
        node = self._find_leaf_node(leaf_index)
        while node.parent:
            parent = node.parent
            if node == parent.left_child:
                # 当前节点是左子节点，添加右兄弟哈希
                path.append(parent.right_child.hash)
            else:
                # 当前节点是右子节点，添加左兄弟哈希
                path.append(parent.left_child.hash)
            node = parent

        return MerkleProof(leaf_index, path)

    def verify_inclusion_proof(self, data, proof):
        """验证存在性证明"""
        if not proof or not self.root:
            return False

        # 计算叶子哈希
        current_hash = self._hash_leaf(data)
        current_index = proof.leaf_index  # 使用局部变量避免修改原始证明

        # 沿着路径向上计算
        for sibling_hash in proof.path:
            # 根据位置决定计算顺序
            if current_index % 2 == 0:
                current_hash = self._hash_internal(current_hash, sibling_hash)
            else:
                current_hash = self._hash_internal(sibling_hash, current_hash)
            current_index //= 2  # 移动到父节点位置

        # 验证最终哈希是否匹配根哈希
        return current_hash == self.root.hash

    def generate_exclusion_proof(self, data):
        """生成不存在性证明（RFC6962标准）"""
        if not self.leaf_data:
            return None

        # 在排序列表中找到插入位置
        index = self._find_insert_position(data)

        # 如果数据已存在，返回None
        if index < self.leaf_count and self.leaf_data[index] == data:
            return None

        # 获取相邻叶子的存在性证明
        left_proof = None
        right_proof = None

        if index > 0:
            left_proof = self.generate_inclusion_proof(index - 1)

        if index < self.leaf_count:
            right_proof = self.generate_inclusion_proof(index)

        return (left_proof, right_proof)

    def verify_exclusion_proof(self, data, proof):
        """验证不存在性证明"""
        if not proof or not self.root:
            return False

        left_proof, right_proof = proof

        # 验证左叶子小于目标数据
        if left_proof:
            left_data = self.leaf_data[left_proof.leaf_index]
            if left_data >= data:
                return False
            if not self.verify_inclusion_proof(left_data, left_proof):
                return False

        # 验证右叶子大于目标数据
        if right_proof:
            right_data = self.leaf_data[right_proof.leaf_index]
            if right_data <= data:
                return False
            if not self.verify_inclusion_proof(right_data, right_proof):
                return False

        # 如果相邻叶子存在且满足顺序关系，则数据不存在
        return True

    def _find_leaf_node(self, index):
        """查找叶子节点"""
        node = self.root
        start = 0
        end = self.leaf_count - 1

        while start != end:
            mid = (start + end) // 2
            if index <= mid:
                node = node.left_child
                end = mid
            else:
                node = node.right_child
                start = mid + 1

        return node

    def _find_insert_position(self, data):
        """在排序列表中找到数据应插入的位置"""
        low, high = 0, self.leaf_count
        while low < high:
            mid = (low + high) // 2
            if self.leaf_data[mid] < data:
                low = mid + 1
            else:
                high = mid
        return low


# 测试代码
if __name__ == '__main__':
    # 创建测试数据（排序）
    leaf_data = [struct.pack('<Q', i) for i in range(1, 100001)]

    # 构建Merkle树
    tree = SortedMerkleTree()
    tree.build_tree(leaf_data)
    print(f"Merkle Root: {tree.get_root_hash().hex()}")

    # 测试存在性证明
    index = 4  # 第5个叶子节点（值=5）
    data = struct.pack('<Q', 5)
    proof = tree.generate_inclusion_proof(index)
    valid = tree.verify_inclusion_proof(data, proof)
    print(f"Inclusion proof for {5}: {'Valid' if valid else 'Invalid'}")

    # 测试不存在性证明
    missing_data = struct.pack('<Q', 100001)  # 不存在的值
    exclusion_proof = tree.generate_exclusion_proof(missing_data)
    if exclusion_proof:
        valid = tree.verify_exclusion_proof(missing_data, exclusion_proof)
        print(f"Exclusion proof for {100001}: {'Valid' if valid else 'Invalid'}")

    # 测试边界情况
    missing_data = struct.pack('<Q', 0)  # 小于所有值
    exclusion_proof = tree.generate_exclusion_proof(missing_data)
    if exclusion_proof:
        valid = tree.verify_exclusion_proof(missing_data, exclusion_proof)
        print(f"Exclusion proof for {0}: {'Valid' if valid else 'Invalid'}")

