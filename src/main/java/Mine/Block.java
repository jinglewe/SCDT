package Mine;

import Mine.util.StringUtil;

import java.util.Date;

public class Block {
    private String hash;
    private String previousHash;
    private String data; // 区块数据
    private long timeStamp; // 时间戳
    private int nonce; // 用于挖矿的随机数

    // 构造函数
    public Block(String data, String previousHash) {
        this.data = data;
        this.previousHash = previousHash;
        this.timeStamp = new Date().getTime();
        this.hash = calculateHash(); // 计算当前区块的哈希值
    }

    // 计算区块的哈希值
    public String calculateHash() {
        return StringUtil.applySha256(
                previousHash +
                        Long.toString(timeStamp) +
                        Integer.toString(nonce) +
                        data
        );
    }

    // 挖矿（工作量证明）
    public void mineBlock(int difficulty) {
        String target = new String(new char[difficulty]).replace('\0', '0'); // 创建难度字符串
        while (!hash.substring(0, difficulty).equals(target)) {
            nonce++;
            hash = calculateHash();
        }
        System.out.println("Block Mined!!! : " + hash);
    }

    // Getter 和 Setter 方法
    public String getHash() {
        return hash;
    }

    public String getPreviousHash() {
        return previousHash;
    }

    public String getData() {
        return data;
    }
}
