// 文件名：tx_performance_test.js
import { ethers } from "ethers";
import fs from "fs";
import dotenv from "dotenv";
dotenv.config();

// ======== 测试参数配置 ========
const RPC_URL = process.env.RPC_URL;          // Sepolia RPC 节点
const PRIVATE_KEY = process.env.PRIVATE_KEY;  // 测试账户私钥
const RECEIVER = process.env.RECEIVER;        // 接收方地址
const TX_COUNT = 60;                           // 要处理的交易数量，根据实际情况调整

const provider = new ethers.JsonRpcProvider(RPC_URL);
const wallet = new ethers.Wallet(PRIVATE_KEY, provider);
async function processMultipleTransactionsAsync() {
    console.log(`🔄 开始异步处理 ${TX_COUNT} 笔交易...`);
    const overallStartTime = Date.now();

    const results = [];
    let nonce = await wallet.getNonce(); // 获取当前nonce

    const promises = [];

    for (let i = 0; i < TX_COUNT; i++) {
        try {
            console.log(`\n📋 构建第 ${i + 1} 笔交易...`);

            const filePath = `../output/dataAS_${i}.txt`;
            if (!fs.existsSync(filePath)) {
                console.log(`❌ 文件不存在: ${filePath}，跳过该交易`);
                continue;
            }

            const dataFromFile = fs.readFileSync(filePath, "utf8").trim();
            console.log(`📥 从 Java 获取的数据 (交易 ${i + 1}):`, dataFromFile);

            const tx = {
                to: RECEIVER,
                value: 0,
                data: ethers.hexlify(ethers.toUtf8Bytes(dataFromFile)),
                gasLimit: 100000,
                nonce: nonce + i // 设置nonce，确保按顺序
            };

            // 不等待发送结果，直接放入promises数组
            promises.push(wallet.sendTransaction(tx).then(sentTx => {
                console.log(`🔗 交易 ${i + 1} 哈希:`, sentTx.hash);
                return { sentTx, index: i + 1, filePath };
            }));

        } catch (error) {
            console.error(`❌ 构建第 ${i + 1} 笔交易时出错:`, error.message);
            results.push({
                index: i + 1,
                status: 'failed',
                error: error.message
            });
        }
    }

    // 等待所有交易发送完成，然后等待它们确认
    const sentResults = await Promise.allSettled(promises);

    // 处理发送结果
    for (const result of sentResults) {
        if (result.status === 'fulfilled') {
            const { sentTx, index, filePath } = result.value;
            try {
                const startTime = Date.now();
                const receipt = await sentTx.wait();
                const endTime = Date.now();
                const delay = ((endTime - startTime) / 1000).toFixed(2);

                results.push({
                    index: index,
                    txHash: sentTx.hash,
                    blockNumber: receipt.blockNumber,
                    gasUsed: receipt.gasUsed.toString(),
                    delay: delay,
                    filePath: filePath,
                    status: 'success'
                });

                console.log(`✅ 交易 ${index} 上链成功！`);
            } catch (error) {
                console.error(`❌ 交易 ${index} 确认失败:`, error.message);
                results.push({
                    index: index,
                    status: 'failed',
                    error: error.message
                });
            }
        } else {
            // 发送失败
            console.error(`❌ 交易发送失败:`, result.reason);
            // 注意：这里我们不知道索引，因为它在result.value中，但我们可以从promises的索引推断？实际上我们无法直接获取，所以需要在构建时捕获并记录
        }
    }
    const overallEndTime = Date.now();
    const overallDuration = ((overallEndTime - overallStartTime) / 1000).toFixed(2);


    // ======== 5. 输出汇总报告 ========
    console.log('\n' + '='.repeat(50));
    console.log('📊 交易处理汇总报告');
    console.log('='.repeat(50));

    const successfulTxs = results.filter(r => r.status === 'success');
    const failedTxs = results.filter(r => r.status === 'failed');

    console.log(`✅ 成功交易: ${successfulTxs.length} 笔`);
    console.log(`❌ 失败交易: ${failedTxs.length} 笔`);
    console.log(`📈 成功率: ${((successfulTxs.length / TX_COUNT) * 100).toFixed(2)}%`);

    if (successfulTxs.length > 0) {
        const totalGas = successfulTxs.reduce((sum, tx) => sum + parseInt(tx.gasUsed), 0);
        const avgGas = totalGas / successfulTxs.length;
        const totalDelay = successfulTxs.reduce((sum, tx) => sum + parseFloat(tx.delay), 0);
        const avgDelay = totalDelay / successfulTxs.length;

        console.log(`⛽ 平均Gas消耗: ${avgGas.toFixed(0)}`);
        console.log(`⏱️  平均确认时延: ${avgDelay.toFixed(2)} 秒`);

        console.log('\n📋 成功交易详情:');
        successfulTxs.forEach(tx => {
            console.log(`  交易 ${tx.index}: 区块 ${tx.blockNumber}, Gas ${tx.gasUsed}, 时延 ${tx.delay}秒`);
        });
        console.log(`   总执行时长: ${overallDuration} 秒`);
    }

    if (failedTxs.length > 0) {
        console.log('\n📋 失败交易详情:');
        failedTxs.forEach(tx => {
            console.log(`  交易 ${tx.index}: ${tx.error}`);
        });
    }

    // ======== 6. 可选：将结果保存到文件 ========
    const resultFilePath = `../output/tx_results_${Date.now()}.json`;
    fs.writeFileSync(resultFilePath, JSON.stringify(results, null, 2));
    console.log(`\n💾 详细结果已保存至: ${resultFilePath}`);
}

// 执行主函数
processMultipleTransactionsAsync().catch(console.error);