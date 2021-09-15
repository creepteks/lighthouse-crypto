declare type Leaf = BigInt;
declare type PathElements = BigInt[][];
declare type Indices = number[];
interface MerkleProof {
    pathElements: PathElements;
    indices: Indices;
    depth: number;
    root: BigInt;
    leaf: Leaf;
}
declare class IncrementalQuinTree {
    leavesPerNode: number;
    depth: number;
    zeroValue: BigInt;
    root: BigInt;
    nextIndex: number;
    leaves: Leaf[];
    zeros: BigInt[];
    filledSubtrees: BigInt[][];
    filledPaths: any;
    hashFunc: (leaves: BigInt[]) => BigInt;
    constructor(_depth: number, _zeroValue: BigInt | number, _leavesPerNode?: number | BigInt);
    insert(_value: Leaf): void;
    update(_index: number, _value: Leaf): void;
    getLeaf(_index: number): Leaf;
    genMerklePath(_index: number): MerkleProof;
    static verifyMerklePath(_proof: MerkleProof, _hashFunc: (leaves: BigInt[]) => BigInt): boolean;
    copy(): IncrementalQuinTree;
    hash(_leaves: BigInt[]): BigInt;
}
export { IncrementalQuinTree, };
