"use strict";
exports.__esModule = true;
var assert = require("assert");
var _1 = require("./");
var deepCopyBigIntArray = function (arr) {
    return arr.map(function (x) { return BigInt(x.toString()); });
};
/*
 * An incremental Merkle tree which conforms to the implementation in
 * IncrementalQuinTree.sol. It supports 2 or 5 elements per leaf.
 */
var IncrementalQuinTree = /** @class */ (function () {
    function IncrementalQuinTree(_depth, _zeroValue, _leavesPerNode) {
        // This class supports either 2 leaves per node, or 5 leaves per node.
        // 5 is largest number of inputs which circomlib's Poseidon EVM hash
        // function implementation provides for.
        // TODO: modify this to support 3 or 4 leaves per node
        if (_leavesPerNode === void 0) { _leavesPerNode = 5; }
        // All leaves in the tree
        this.leaves = [];
        // Contains the zero value per level. i.e. zeros[0] is zeroValue,
        // zeros[1] is the hash of leavesPerNode zeros, and so on.
        this.zeros = [];
        // Caches values needed for efficient appends.
        this.filledSubtrees = [];
        // Caches values needed to compute Merkle paths.
        this.filledPaths = {};
        this.leavesPerNode = Number(_leavesPerNode);
        assert(this.leavesPerNode === 2 || this.leavesPerNode === 5);
        this.depth = Number(_depth);
        this.nextIndex = 0;
        this.zeroValue = BigInt(_zeroValue);
        // Set this.hashFunc depending on the number of leaves per node
        if (this.leavesPerNode === 2) {
            // Uses PoseidonT3 under the hood, which accepts 2 inputs
            this.hashFunc = function (inputs) {
                return _1.hashLeftRight(inputs[0], inputs[1]);
            };
        }
        else {
            // Uses PoseidonT6 under the hood, which accepts up to 5 inputs
            this.hashFunc = _1.hash5;
        }
        this.zeros = [];
        this.filledSubtrees = [];
        var currentLevelHash = this.zeroValue;
        // Calculate intermediate values
        for (var i = 0; i < this.depth; i++) {
            if (i < this.depth - 1) {
                this.filledPaths[i] = [];
            }
            this.zeros.push(currentLevelHash);
            var z = [];
            for (var j = 0; j < this.leavesPerNode; j++) {
                z.push(this.zeros[i]);
            }
            this.filledSubtrees.push(z);
            currentLevelHash = this.hash(z);
        }
        // Calculate the root
        this.root = this.hash(this.filledSubtrees[this.depth - 1]);
    }
    /*
     * Insert a leaf into the Merkle tree
     * @param _value The value to insert. This may or may not already be
     *               hashed.
     */
    IncrementalQuinTree.prototype.insert = function (_value) {
        // Ensure that _value is a BigInt
        _value = BigInt(_value);
        // A node is one level above the leaf
        // m is the leaf's relative position within its node
        var m = this.nextIndex % this.leavesPerNode;
        // Zero out the level in filledSubtrees
        if (m === 0) {
            for (var j = 1; j < this.filledSubtrees[0].length; j++) {
                this.filledSubtrees[0][j] = this.zeros[0];
            }
        }
        this.filledSubtrees[0][m] = _value;
        var currentIndex = this.nextIndex;
        for (var i = 1; i < this.depth; i++) {
            // currentIndex is the leaf or node's absolute index
            currentIndex = Math.floor(currentIndex / this.leavesPerNode);
            // m is the leaf's relative position within its node
            m = currentIndex % this.leavesPerNode;
            // Zero out the level
            if (m === 0) {
                for (var j = 1; j < this.filledSubtrees[i].length; j++) {
                    this.filledSubtrees[i][j] = this.zeros[i];
                }
            }
            var hashed = this.hash(this.filledSubtrees[i - 1]);
            this.filledSubtrees[i][m] = hashed;
            if (this.filledPaths[i - 1].length <= currentIndex) {
                this.filledPaths[i - 1].push(hashed);
            }
            else {
                this.filledPaths[i - 1][currentIndex] = hashed;
            }
        }
        this.leaves.push(_value);
        this.nextIndex++;
        this.root = this.hash(this.filledSubtrees[this.filledSubtrees.length - 1]);
    };
    /*
     * Update the leaf at the specified index with the given value.
     */
    IncrementalQuinTree.prototype.update = function (_index, _value) {
        if (_index >= this.nextIndex || _index >= this.leaves.length) {
            throw new Error('The leaf index specified is too large');
        }
        _value = BigInt(_value);
        var temp = this.leaves;
        temp[_index] = _value;
        this.leaves[_index] = _value;
        var newTree = new IncrementalQuinTree(this.depth, this.zeroValue, this.leavesPerNode);
        for (var i = 0; i < temp.length; i++) {
            newTree.insert(temp[i]);
        }
        this.leaves = newTree.leaves;
        this.zeros = newTree.zeros;
        this.filledSubtrees = newTree.filledSubtrees;
        this.filledPaths = newTree.filledPaths;
        this.root = newTree.root;
        this.nextIndex = newTree.nextIndex;
    };
    /*
     * Returns the leaf value at the given index
     */
    IncrementalQuinTree.prototype.getLeaf = function (_index) {
        return this.leaves[_index];
    };
    /*  Generates a Merkle proof from a leaf to the root.
     */
    IncrementalQuinTree.prototype.genMerklePath = function (_index) {
        if (_index < 0) {
            throw new Error('The leaf index must be greater than 0');
        }
        if (_index >= this.nextIndex || _index >= this.leaves.length) {
            throw new Error('The leaf index is too large');
        }
        var pathElements = [];
        var indices = [_index % this.leavesPerNode];
        var r = Math.floor(_index / this.leavesPerNode);
        for (var i = 0; i < this.depth; i++) {
            var s = [];
            if (i === 0) {
                // Get a slice of leaves, padded with zeros
                var leafStartIndex = _index - (_index % this.leavesPerNode);
                var leafEndIndex = leafStartIndex + this.leavesPerNode;
                for (var j = leafStartIndex; j < leafEndIndex; j++) {
                    if (j < this.leaves.length) {
                        s.push(this.leaves[j]);
                    }
                    else {
                        s.push(this.zeros[i]);
                    }
                }
            }
            else {
                for (var j = 0; j < this.leavesPerNode; j++) {
                    var x = r * this.leavesPerNode + j;
                    if (this.filledPaths[i - 1].length <= x) {
                        s.push(this.zeros[i]);
                    }
                    else {
                        var e = this.filledPaths[i - 1][x];
                        s.push(e);
                    }
                }
            }
            var p = r % this.leavesPerNode;
            pathElements.push(s);
            if (i < this.depth - 1) {
                indices.push(p);
            }
            r = Math.floor(r / this.leavesPerNode);
        }
        // Remove the commitments to elements which are the leaves per level
        var newPe = [[]];
        var firstIndex = _index % this.leavesPerNode;
        for (var i = 0; i < pathElements[0].length; i++) {
            if (i !== firstIndex) {
                newPe[0].push(pathElements[0][i]);
            }
        }
        for (var i = 1; i < pathElements.length; i++) {
            var level = [];
            for (var j = 0; j < pathElements[i].length; j++) {
                if (j !== indices[i]) {
                    level.push(pathElements[i][j]);
                }
            }
            newPe.push(level);
        }
        return {
            pathElements: newPe,
            indices: indices,
            depth: this.depth,
            root: this.root,
            leaf: this.leaves[_index]
        };
    };
    IncrementalQuinTree.verifyMerklePath = function (_proof, _hashFunc) {
        assert(_proof.pathElements);
        var pathElements = _proof.pathElements;
        // Validate the proof format
        assert(_proof.indices);
        for (var i = 0; i < _proof.depth; i++) {
            assert(pathElements[i]);
            assert(_proof.indices[i] != undefined);
        }
        // Hash the first level
        var firstLevel = pathElements[0].map(BigInt);
        firstLevel.splice(Number(_proof.indices[0]), 0, _proof.leaf);
        var currentLevelHash = _hashFunc(firstLevel);
        // Verify the proof
        for (var i = 1; i < pathElements.length; i++) {
            var level = pathElements[i].map(BigInt);
            level.splice(Number(_proof.indices[i]), 0, currentLevelHash);
            currentLevelHash = _hashFunc(level);
        }
        return currentLevelHash === _proof.root;
    };
    /*  Deep-copies this object
     */
    IncrementalQuinTree.prototype.copy = function () {
        var newTree = new IncrementalQuinTree(this.depth, this.zeroValue, this.leavesPerNode);
        newTree.leaves = deepCopyBigIntArray(this.leaves);
        newTree.zeros = deepCopyBigIntArray(this.zeros);
        newTree.root = this.root;
        newTree.nextIndex = this.nextIndex;
        newTree.filledSubtrees = this.filledSubtrees.map(deepCopyBigIntArray);
        newTree.filledPaths = _1.unstringifyBigInts(JSON.parse(JSON.stringify(_1.stringifyBigInts(this.filledPaths))));
        return newTree;
    };
    IncrementalQuinTree.prototype.hash = function (_leaves) {
        if (this.leavesPerNode > 2) {
            while (_leaves.length < 5) {
                _leaves.push(this.zeroValue);
            }
        }
        return this.hashFunc(_leaves);
    };
    return IncrementalQuinTree;
}());
exports.IncrementalQuinTree = IncrementalQuinTree;
//# sourceMappingURL=IncrementalQuinTree.js.map