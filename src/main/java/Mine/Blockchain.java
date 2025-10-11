package Mine;

import java.util.ArrayList;

public class Blockchain {
    private ArrayList<Block> chain;
    private int difficulty;

    // 构造函数
    public Blockchain(int difficulty) {
        this.chain = new ArrayList<>();
        this.difficulty = difficulty;
        // 创建创世区块
        chain.add(new Block("Genesis Block", "0"));
    }

    // 添加新区块
    public void addBlock(String data) {
        Block previousBlock = chain.get(chain.size() - 1);
        Block newBlock = new Block(data, previousBlock.getHash());
        newBlock.mineBlock(difficulty);
        chain.add(newBlock);
    }

    // 验证区块链的完整性
    public boolean isChainValid() {
        for (int i = 1; i < chain.size(); i++) {
            Block currentBlock = chain.get(i);
            Block previousBlock = chain.get(i - 1);

            // 检查当前区块的哈希值是否正确
            if (!currentBlock.getHash().equals(currentBlock.calculateHash())) {
                System.out.println("Current block hash is invalid!");
                return false;
            }

            // 检查当前区块的前一个哈希值是否等于前一个区块的哈希值
            if (!currentBlock.getPreviousHash().equals(previousBlock.getHash())) {
                System.out.println("Previous block hash is invalid!");
                return false;
            }
        }
        return true;
    }

    // 打印区块链
    public void printChain() {
        for (Block block : chain) {
            System.out.println("Block Data: " + block.getData());
            System.out.println("Block Hash: " + block.getHash());
            System.out.println("Previous Hash: " + block.getPreviousHash());
            System.out.println();
        }
    }
}